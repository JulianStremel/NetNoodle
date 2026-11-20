// Package sqlite implements store.Store on SQLite (pure Go driver, no cgo).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver "sqlite"

	"github.com/JulianStremel/netnoodle/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB is the SQLite store.
type DB struct {
	db        *sql.DB
	path      string
	backupDir string
}

var _ store.Store = (*DB)(nil)

// Open opens (and creates) the database file at path and applies all
// pending migrations. Use ":memory:" for tests.
func Open(ctx context.Context, path string) (*DB, error) {
	return openWithOptions(ctx, path, migrationOptions{fs: migrations, free: freeSpace})
}

func openWithOptions(ctx context.Context, path string, opts migrationOptions) (*DB, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	if path != ":memory:" {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	dsn := "file:" + (&url.URL{Path: filepath.ToSlash(path)}).EscapedPath() + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite allows one writer; this avoids SQLITE_BUSY on
	// lock upgrades and keeps ":memory:" databases shared. Revisit if reads
	// become a bottleneck.
	db.SetMaxOpenConns(1)
	if path != ":memory:" {
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &DB{db: db, path: path, backupDir: opts.backupDir}
	if s.backupDir == "" {
		s.backupDir = filepath.Join(filepath.Dir(path), "backups")
	}
	if err := s.migrateWithOptions(ctx, opts); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// SQL gives other store packages in this module access to the handle.
func (s *DB) SQL() *sql.DB { return s.db }

func (s *DB) Close() error { return s.db.Close() }

// tsLayout has a fixed width, so text comparison in SQL equals time order.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, s)
	}
	return t
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// --- users ---

func (s *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *DB) CreateUser(ctx context.Context, name string, passHash []byte) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, errors.New("empty user name")
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO users(name, pass_hash, created_at) VALUES (?, ?, ?)`,
		name, passHash, ts(time.Now()))
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *DB) UserByName(ctx context.Context, name string) (store.User, error) {
	var u store.User
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, pass_hash, created_at FROM users WHERE name = ?`, name).
		Scan(&u.ID, &u.Name, &u.PassHash, &created)
	if err != nil {
		return u, notFound(err)
	}
	u.Created = parseTS(created)
	return u, nil
}

// SetPassword changes the password and ends all sessions of the user.
func (s *DB) SetPassword(ctx context.Context, id int64, passHash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE users SET pass_hash = ? WHERE id = ?`, passHash, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// --- sessions ---

func (s *DB) CreateSession(ctx context.Context, tokenHash []byte, userID int64, passHash []byte, expires time.Time) error {
	r, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires_at)
		SELECT ?, id, ? FROM users WHERE id = ? AND pass_hash = ?`,
		tokenHash, ts(expires), userID, passHash)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *DB) SessionUser(ctx context.Context, tokenHash []byte, now time.Time) (store.User, error) {
	var u store.User
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT u.id, u.name, u.pass_hash, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, ts(now)).
		Scan(&u.ID, &u.Name, &u.PassHash, &created)
	if err != nil {
		return u, notFound(err)
	}
	u.Created = parseTS(created)
	return u, nil
}

func (s *DB) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *DB) PurgeSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, ts(now))
	return err
}

// --- events ---

func (s *DB) AddEvent(ctx context.Context, e store.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events(at, type, actor, summary, data) VALUES (?, ?, ?, ?, ?)`,
		ts(e.At), e.Type, e.Actor, e.Summary, e.Data)
	return err
}

// PurgeEvents deletes events older than before.
func (s *DB) PurgeEvents(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE at < ?`, ts(before))
	return err
}

func (s *DB) ListEvents(ctx context.Context, limit int) ([]store.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, type, actor, summary, COALESCE(data, '')
		FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		var e store.Event
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Type, &e.Actor, &e.Summary, &e.Data); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentDeviceClaims includes the structured device reference and the exact
// legacy event title. It never matches device #1 against device #10, nor depends
// on the bounded general event feed.
func (s *DB) RecentDeviceClaims(ctx context.Context, device int64, since, until time.Time) ([]store.DeviceClaim, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT actor,at FROM events WHERE type='device.claimed' AND at>=? AND at<=?
		AND (CASE WHEN json_valid(data) THEN json_extract(data,'$.device_id')=? ELSE 0 END
		OR summary='Agent '||actor||' took over device #'||?) ORDER BY at DESC,id DESC`, ts(since), ts(until), device, device)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.DeviceClaim{}
	for rows.Next() {
		var c store.DeviceClaim
		var at string
		if err := rows.Scan(&c.Agent, &at); err != nil {
			return nil, err
		}
		c.At = parseTS(at)
		out = append(out, c)
	}
	return out, rows.Err()
}
