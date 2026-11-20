package store

import (
	"context"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

type ActorCaps struct {
	Peer         Peer               `json:"peer"`
	Capabilities []proto.Capability `json:"capabilities"`
	UpdatedAt    time.Time          `json:"updated_at"`
}
type Order struct {
	proto.Order
	ProposalID     int64           `json:"proposal_id"`
	ActorPeerID    int64           `json:"actor_peer_id"`
	State          string          `json:"state"`
	Envelope       orders.Envelope `json:"-"`
	CreatedAt      time.Time       `json:"created_at"`
	SentAt         time.Time       `json:"sent_at,omitzero"`
	DoneAt         time.Time       `json:"done_at,omitzero"`
	Message        string          `json:"message"`
	RevertAction   string          `json:"revert_action,omitempty"`
	RevertDueAt    time.Time       `json:"revert_due_at,omitzero"`
	Reverted       bool            `json:"reverted"`
	RevertAttempts int             `json:"revert_attempts"`
}
type OrderFilter struct {
	ProposalID int64
	State      string
	Limit      int
}
type Orders interface {
	SetActorCaps(context.Context, int64, []proto.Capability, time.Time) error
	ListActors(context.Context) ([]ActorCaps, error)
	QueueOrder(context.Context, Order) error
	GetOrder(context.Context, string) (Order, error)
	ListOrders(context.Context, OrderFilter) ([]Order, error)
	PlanningProposals(context.Context) ([]Proposal, error)
	DueReverts(context.Context, time.Time) ([]Order, error)
	ExpiringOrders(context.Context, time.Time) ([]Order, error)
	SendOrders(context.Context, int64, time.Time) ([]orders.Envelope, error)
	FinishOrder(context.Context, int64, proto.OrderResult, time.Time) error
	ExpireOrders(context.Context, time.Time) error
	SetProposalOrderState(context.Context, int64, string, string, time.Time) error
	ScheduleRevert(context.Context, string, time.Time) error
}
