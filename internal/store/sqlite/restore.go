package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LatestBackup selects only migration backups, excluding pre-restore copies.
func LatestBackup(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	type candidate struct {
		path string
		at   time.Time
	}
	var candidates []candidate
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), "netnoodle-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		i, err := e.Info()
		if err != nil {
			return "", err
		}
		candidates = append(candidates, candidate{filepath.Join(dir, e.Name()), i.ModTime()})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no migration backups in %s", dir)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].path > candidates[j].path
		}
		return candidates[i].at.After(candidates[j].at)
	})
	return candidates[0].path, nil
}

func openExisting(ctx context.Context, path, mode string) (*sql.DB, error) {
	// Escaping and slash conversion preserve Windows drive letters, spaces,
	// question marks and # characters without treating them as URI options.
	dsn := "file:" + (&url.URL{Path: filepath.ToSlash(path)}).EscapedPath() + "?mode=" + mode + "&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Restore requires the caller to hold the server data directory lock. It checks
// integrity before touching the current database and stages a self-contained
// SQLite snapshot on the destination filesystem. dryRun verifies without writes.
func Restore(ctx context.Context, current, backup, backupDir string, dryRun bool) (string, error) {
	info, err := os.Lstat(backup)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("backup must be a nonempty regular SQLite file")
	}
	source, err := openExisting(ctx, backup, "ro")
	if err != nil {
		return "", fmt.Errorf("verify backup: %w", err)
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return "", fmt.Errorf("backup integrity_check: %w", err)
	}
	ok := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			rows.Close()
			return "", err
		}
		if result != "ok" {
			rows.Close()
			return "", fmt.Errorf("backup integrity_check: %s", result)
		}
		ok = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !ok {
		return "", fmt.Errorf("backup integrity_check failed: %v", err)
	}
	if dryRun {
		return "", nil
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", err
	}
	stageDir, err := os.MkdirTemp(filepath.Dir(current), ".restore-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stageDir)
	stage := filepath.Join(stageDir, "database.db")
	if err := (&DB{db: source}).Backup(ctx, stage); err != nil {
		return "", err
	}
	// Close the source before a rename (Windows also forbids renaming an open
	// file when --file names the current database).
	if err := source.Close(); err != nil {
		return "", err
	}

	preserved := filepath.Join(backupDir, "pre-restore-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".db")
	type move struct{ from, to string }
	var moves []move
	// Preserve the exact current database, including crash-left WAL/SHM files.
	// Opening it would prevent recovery from corruption or a schema which this
	// SQLite library cannot read. The caller's OS lock excludes nn-server.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := current + suffix
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("current database file is not regular: %s", path)
		}
		moves = append(moves, move{path, preserved + suffix})
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	moved := 0
	rollback := func(cause error) (string, error) {
		failed := false
		for i := moved - 1; i >= 0; i-- {
			if err := os.Rename(moves[i].to, moves[i].from); err != nil {
				failed = true
				cause = errors.Join(cause, fmt.Errorf("rollback %s: %w", moves[i].to, err))
			}
		}
		if !failed {
			return "", fmt.Errorf("restore failed; previous database left in place: %w", cause)
		}
		return preserved, fmt.Errorf("restore failed (previous database recovery path: %s): %w", preserved, cause)
	}
	for _, m := range moves {
		if err := os.Rename(m.from, m.to); err != nil {
			return rollback(err)
		}
		moved++
	}
	if err := os.Rename(stage, current); err != nil {
		return rollback(err)
	}
	if len(moves) == 0 {
		preserved = ""
	}

	return preserved, nil
}

// OpenReadOnly opens an existing database for online export without applying
// migrations. Backup uses VACUUM INTO and sees a consistent committed snapshot.
func OpenReadOnly(ctx context.Context, path string) (*DB, error) {
	db, err := openExisting(ctx, path, "ro")
	if err != nil {
		return nil, err
	}
	return &DB{db: db, path: path}, nil
}
