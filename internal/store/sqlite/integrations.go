package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

const integrationCols = `id,kind,type,name,settings_json,secrets_json,enabled,created_at,updated_at,last_ok_at,last_error`

func scanIntegration(row interface{ Scan(...any) error }) (store.Integration, error) {
	var i store.Integration
	var settings, secrets, created, updated string
	var ok sql.NullString
	err := row.Scan(&i.ID, &i.Kind, &i.Type, &i.Name, &settings, &secrets, &i.Enabled, &created, &updated, &ok, &i.LastError)
	i.Settings, i.Secrets = []byte(settings), []byte(secrets)
	i.CreatedAt, i.UpdatedAt = parseTS(created), parseTS(updated)
	if ok.Valid {
		i.LastOKAt = parseTS(ok.String)
	}
	return i, notFound(err)
}

func integrationError(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return store.ErrConflict
	}
	return err
}

func (s *DB) CreateIntegration(ctx context.Context, i store.Integration) (store.Integration, error) {
	if i.Kind == "" {
		i.Kind = "source"
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO integrations(kind,type,name,settings_json,secrets_json,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)`, i.Kind, i.Type, i.Name, string(i.Settings), string(i.Secrets), i.Enabled, ts(i.CreatedAt), ts(i.UpdatedAt))
	if err != nil {
		return i, integrationError(err)
	}
	i.ID, err = r.LastInsertId()
	return i, err
}

func (s *DB) UpdateIntegration(ctx context.Context, i store.Integration) error {
	if i.Kind == "" {
		i.Kind = "source"
	}
	return integrationError(affected(s.db.ExecContext(ctx, `UPDATE integrations SET kind=?,type=?,name=?,settings_json=?,secrets_json=?,enabled=?,updated_at=?,last_error='' WHERE id=?`, i.Kind, i.Type, i.Name, string(i.Settings), string(i.Secrets), i.Enabled, ts(i.UpdatedAt), i.ID)))
}

func (s *DB) GetIntegration(ctx context.Context, id int64) (store.Integration, error) {
	return scanIntegration(s.db.QueryRowContext(ctx, `SELECT `+integrationCols+` FROM integrations WHERE id=?`, id))
}

func (s *DB) ListIntegrations(ctx context.Context) ([]store.Integration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+integrationCols+` FROM integrations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Integration{}
	for rows.Next() {
		i, err := scanIntegration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *DB) DeleteIntegration(ctx context.Context, id int64) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM integrations WHERE id=?`, id))
}

func (s *DB) SetIntegrationResult(ctx context.Context, id int64, revision, at time.Time, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE integrations SET last_ok_at=CASE WHEN ?='' THEN ? ELSE last_ok_at END,last_error=? WHERE id=? AND updated_at=?`, errText, ts(at), errText, id, ts(revision))
	return err
}
