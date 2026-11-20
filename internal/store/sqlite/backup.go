package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

var _ store.Backuper = (*DB)(nil)

// ExportBackup sanitizes only the snapshot. VACUUM removes old secret bytes
// from freed pages as well as live records; the original database is untouched.
func (s *DB) ExportBackup(ctx context.Context, destination string) error {
	if err := s.Backup(ctx, destination); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: filepath.ToSlash(destination)}).EscapedPath())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='integrations'`).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		if _, err := db.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `UPDATE integrations SET secrets_json='{}',settings_json=json_remove(settings_json,'$.url','$.base_url','$.broker'),enabled=0,last_error=''`); err != nil {
			return err
		}
		rows, err := db.QueryContext(ctx, `SELECT id,settings_json FROM integrations`)
		if err != nil {
			return err
		}
		type cleanRow struct {
			id  int64
			raw []byte
		}
		var clean []cleanRow
		for rows.Next() {
			var id int64
			var raw []byte
			if err := rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			var settings map[string]json.RawMessage
			if err := json.Unmarshal(raw, &settings); err != nil {
				rows.Close()
				return err
			}
			for key, value := range settings {
				var v string
				if json.Unmarshal(value, &v) == nil && tlspin.CredentialURL(v) {
					delete(settings, key)
				}
			}
			b, _ := json.Marshal(settings)
			clean = append(clean, cleanRow{id, b})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, row := range clean {
			if _, err := db.ExecContext(ctx, `UPDATE integrations SET settings_json=? WHERE id=?`, string(row.raw), row.id); err != nil {
				return err
			}
		}
		if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
			return err
		}
	}
	// Fold any WAL into the exported main file before the archive reads it.
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type migrationOptions struct {
	fs        fs.FS
	free      func(string) (uint64, error)
	backupDir string
}

// Backup writes a durable, consistent online snapshot to a new private file.
func (s *DB) Backup(ctx context.Context, destination string) error {
	// Reserve the destination exclusively. VACUUM INTO accepts an existing
	// empty file, so snapshots are private from creation and cleanup can never
	// remove somebody else's file after a destination race.
	reserved, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("backup destination: %w", err)
	}
	if err := reserved.Close(); err != nil {
		_ = os.Remove(destination)
		return err
	}
	// SQLite's online snapshot includes committed WAL content.
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		_ = os.Remove(destination)
		return err
	}
	f, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		_ = os.Remove(destination)
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func (s *DB) migrate(ctx context.Context) error {
	return s.migrateWithOptions(ctx, migrationOptions{fs: migrations, free: freeSpace})
}

func (s *DB) migrateWithOptions(ctx context.Context, opts migrationOptions) (err error) {
	names, err := fs.Glob(opts.fs, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	known := map[string]bool{}
	for _, name := range names {
		known[name] = true
	}
	var tableExists int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='schema_migrations'`).Scan(&tableExists); err != nil {
		return err
	}
	applied := map[string]bool{}
	from := "empty"
	if tableExists != 0 {
		rows, err := s.db.QueryContext(ctx, `SELECT name FROM schema_migrations ORDER BY name`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			if !known[name] {
				rows.Close()
				return fmt.Errorf("database schema is newer than this nn-server; use a newer version or restore a backup (unknown migration %s)", name)
			}
			applied[name] = true
			from = strings.TrimSuffix(filepath.Base(name), ".sql")
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	pending := []string{}
	for _, name := range names {
		if !applied[name] {
			pending = append(pending, name)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	backup := ""
	var tables int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT IN ('schema_migrations','sqlite_sequence')`).Scan(&tables); err != nil {
		return err
	}
	if s.path != "" && s.path != ":memory:" && (len(applied) > 0 || tables > 0) {
		if err := os.MkdirAll(s.backupDir, 0o700); err != nil {
			return err
		}
		info, err := os.Stat(s.path)
		if err != nil {
			return err
		}
		size := uint64(info.Size())
		// WAL mode may have most committed pages outside the main file.
		var pages, pageSize uint64
		if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
			return err
		}
		if err := s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
			return err
		}
		size = max(size, pages*pageSize)
		available, err := opts.free(s.backupDir)
		if err != nil {
			return fmt.Errorf("cannot check free disk space; refusing migration without backup: %w", err)
		}
		if available < size*2 {
			return fmt.Errorf("insufficient free disk space for migration backup: need %d bytes (2x database), have %d; refusing migration", size*2, available)
		}
		backup = filepath.Join(s.backupDir, "netnoodle-"+from+"-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".db")
		if err := s.Backup(ctx, backup); err != nil {
			return fmt.Errorf("refusing migration without backup: %w", err)
		}
		if err := rotateBackups(s.backupDir); err != nil {
			return fmt.Errorf("backup saved at %s; rotate: %w", backup, err)
		}
	}
	defer func() {
		if err != nil && backup != "" {
			err = fmt.Errorf("%w (pre-migration backup: %s)", err, backup)
		}
	}()
	if _, err = s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for _, name := range pending {
		body, e := fs.ReadFile(opts.fs, name)
		if e != nil {
			return e
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, string(body)); e == nil {
			_, e = tx.ExecContext(ctx, `INSERT INTO schema_migrations(name,applied_at) VALUES (?,?)`, name, time.Now().UTC().Format(time.RFC3339))
		}
		if e != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, e)
		}
		if e = tx.Commit(); e != nil {
			return fmt.Errorf("migration %s: %w", name, e)
		}
	}
	return nil
}

func rotateBackups(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type entry struct {
		name string
		at   time.Time
	}
	var backups []entry
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "netnoodle-") && strings.HasSuffix(e.Name(), ".db") {
			i, err := e.Info()
			if err != nil {
				return err
			}
			backups = append(backups, entry{e.Name(), i.ModTime()})
		}
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].at.Equal(backups[j].at) {
			return backups[i].name > backups[j].name
		}
		return backups[i].at.After(backups[j].at)
	})
	for i := 3; i < len(backups); i++ {
		if err := os.Remove(filepath.Join(dir, backups[i].name)); err != nil {
			return err
		}
	}
	return nil
}
