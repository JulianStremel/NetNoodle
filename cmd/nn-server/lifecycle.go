package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/server"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/store/sqlite"
	"github.com/JulianStremel/netnoodle/internal/version"
)

// acquireDataLock serializes startup and maintenance before opening the store.
// The lock file persists; its existence is not the lock. The OS releases the
// advisory lock when its handle closes or the process exits, even after a crash.
func acquireDataLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "nn-server.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("server or maintenance command is running (data directory lock): %w", err)
	}
	return f, nil
}

func lifecycle(ctx context.Context, command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	config := flags.String("config", "netnoodle.json", "config file (optional)")
	latest := flags.Bool("latest", false, "restore the newest migration backup")
	file := flags.String("file", "", "backup file to restore")
	out := flags.String("out", "", "destination .tar.gz archive (0600)")
	dryRun := flags.Bool("dry-run", false, "verify restore without replacing the database")
	jsonOutput := flags.Bool("json", false, "output backup path as JSON")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "nn-server %s [flags]\nRestore requires nn-server to be stopped and holds data_dir/nn-server.lock (released automatically after a crash). Export supports online SQLite snapshots.\n", command)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if command == "restore" && (*latest == (*file != "") || *out != "") {
		return fmt.Errorf("restore requires exactly one of --latest or --file")
	}
	if command == "export" && (*out == "" || *latest || *file != "" || *dryRun) {
		return fmt.Errorf("export requires --out <file.tar.gz>")
	}
	if command == "backup" && (*out != "" || *latest || *file != "" || *dryRun) {
		return fmt.Errorf("backup accepts only --config and --json")
	}
	cfg, err := server.LoadConfig(*config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if command == "restore" {
		lock, err := acquireDataLock(cfg.DataDir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if cfg.Store.Type != "" && cfg.Store.Type != "sqlite" {
			return fmt.Errorf("restore is supported only by SQLite")
		}
		path, err := sqlite.DatabasePath(cfg.DataDir, cfg.Store.Settings)
		if err != nil {
			return err
		}
		backupDir := filepath.Join(cfg.DataDir, "backups")
		if *latest {
			*file, err = sqlite.LatestBackup(backupDir)
			if err != nil {
				return err
			}
		}
		preserved, err := sqlite.Restore(ctx, path, *file, backupDir, *dryRun)
		if err != nil {
			return err
		}
		if *dryRun {
			fmt.Printf("Verified %s; would restore database\n", *file)
		} else {
			fmt.Printf("Restored %s; previous database: %s\n", *file, preserved)
		}
		return nil
	}
	var st store.Store
	if cfg.Store.Type == "" || cfg.Store.Type == "sqlite" {
		path, e := sqlite.DatabasePath(cfg.DataDir, cfg.Store.Settings)
		if e != nil {
			return e
		}
		st, err = sqlite.OpenReadOnly(ctx, path)
	} else {
		st, err = store.Open(ctx, cfg.Store, cfg.DataDir)
	}
	if err != nil {
		return err
	}
	defer st.Close()
	b, ok := st.(store.Backuper)
	if !ok {
		return fmt.Errorf("store does not support database export")
	}
	if command == "backup" {
		dir, err := filepath.Abs(filepath.Join(cfg.DataDir, "backups"))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if cfg.Store.Type == "" || cfg.Store.Type == "sqlite" {
			database, e := sqlite.DatabasePath(cfg.DataDir, cfg.Store.Settings)
			if e != nil {
				return e
			}
			var size uint64
			for _, p := range []string{database, database + "-wal"} {
				i, e := os.Stat(p)
				if os.IsNotExist(e) && p != database {
					continue
				}
				if e != nil {
					return e
				}
				size += uint64(i.Size())
			}
			available, e := backupFreeSpace(dir)
			if e != nil {
				return fmt.Errorf("cannot check backup space: %w", e)
			}
			if available < size*2 {
				return fmt.Errorf("insufficient free space for update backup: need %d bytes, have %d", size*2, available)
			}
		}
		// Updater backups use a separate prefix: migration rotation must not
		// delete a retained rollback snapshot during subsequent updates.
		path := filepath.Join(dir, "update-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".db")
		if err := b.Backup(ctx, path); err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"path": path})
		}
		fmt.Println(path)
		return nil
	}
	return exportArchive(ctx, b, cfg.DataDir, *out)
}

func exportArchive(ctx context.Context, b store.Backuper, dataDir, destination string) (err error) {
	temp, err := os.MkdirTemp(dataDir, ".export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	database := filepath.Join(temp, "netnoodle.db")
	if err := b.Backup(ctx, database); err != nil {
		return err
	}
	files := map[string]string{"netnoodle.db": database}
	for _, dir := range []string{"tls", "keys"} {
		base := filepath.Join(dataDir, dir)
		if _, err := os.Lstat(base); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlink in export: %s", path)
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("refusing non-regular export file: %s", path)
			}
			// Only certificate/key artifacts belong in the recovery archive.
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext != ".pem" && ext != ".key" && ext != ".crt" && ext != ".cer" && ext != ".der" && ext != ".pub" {
				return nil
			}
			rel, err := filepath.Rel(dataDir, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = path
			return nil
		}); err != nil {
			return err
		}
	}
	// Exclusive creation avoids truncating an existing archive, config or DB.
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			_ = os.Remove(destination)
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files)+1)
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := archiveFile(tw, name, files[name]); err != nil {
			return err
		}
	}
	names = append(names, "manifest.json")
	manifest, err := json.MarshalIndent(struct {
		Version  string    `json:"version"`
		Protocol string    `json:"protocol"`
		Created  time.Time `json:"created"`
		Files    []string  `json:"files"`
	}{version.Version, version.Protocol, time.Now().UTC(), names}, "", "  ")
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		return err
	}
	if _, err := tw.Write(manifest); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func archiveFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: i.Size(), ModTime: i.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
