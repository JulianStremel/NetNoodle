package store

import (
	"context"
	"encoding/json"
	"time"
)

// Integration is the private persistence record. Never serialize settings or
// secrets directly: the operator API projects settings through the schema.
type Integration struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Settings  json.RawMessage `json:"-"`
	Secrets   json.RawMessage `json:"-"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	LastOKAt  time.Time       `json:"last_ok_at,omitzero"`
	LastError string          `json:"-"`
}

type Integrations interface {
	CreateIntegration(context.Context, Integration) (Integration, error)
	UpdateIntegration(context.Context, Integration) error
	GetIntegration(context.Context, int64) (Integration, error)
	ListIntegrations(context.Context) ([]Integration, error)
	DeleteIntegration(context.Context, int64) error
	// SetIntegrationResult only updates the revision that performed the poll.
	SetIntegrationResult(context.Context, int64, time.Time, time.Time, string) error
}
