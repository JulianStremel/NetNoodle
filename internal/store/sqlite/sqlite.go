// Package sqlite implements store.Store on SQLite (pure Go driver, no cgo).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver "sqlite"

	"netnoodle/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB is the SQLite store.
type DB struct {
	db *sql.DB
}

var _ store.Store = (*DB)(nil)

// Open opens (and creates) the database file at path and applies all
// pending migrations. Use ":memory:" for tests.
func Open(ctx context.Context, path string) (*DB, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	if path != ":memory:" {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite allows one writer; this avoids SQLITE_BUSY on
	// lock upgrades and keeps ":memory:" databases shared. Revisit if reads
	// become a bottleneck.
	db.SetMaxOpenConns(1)
	s := &DB{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// SQL gives other store packages in this module access to the handle.
func (s *DB) SQL() *sql.DB { return s.db }

func (s *DB) Close() error { return s.db.Close() }

func (s *DB) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var x int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE name = ?`, n).Scan(&x)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		body, err := migrations.ReadFile(n)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)`,
			n, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

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

func (s *DB) CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, userID, ts(expires))
	return err
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
