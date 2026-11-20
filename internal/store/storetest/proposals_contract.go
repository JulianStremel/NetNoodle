package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func testProposalMutableKey(t *testing.T, open func(*testing.T) store.Store) {
	for _, old := range []string{"notify", "pending", "auto", "resolved", "expired"} {
		for _, next := range []string{"notify", "pending", "auto"} {
			t.Run(old+"/"+next, func(t *testing.T) {
				st, ctx, now := open(t), context.Background(), time.Now().UTC()
				in := store.Proposal{DeviceID: decideDevice(t, st), VulnID: "v", Action: "snapshot", State: old, Tier: "auto", CreatedAt: now}
				if old == "resolved" || old == "expired" {
					in.State = "pending"
				}
				p, _, err := st.UpsertProposal(ctx, in)
				must(t, err)
				if old == "resolved" {
					must(t, st.ResolveProposals(ctx, p.DeviceID, nil))
				}
				if old == "expired" {
					must(t, st.ExpireProposals(ctx, now))
				}
				in.State, in.Reason, in.CreatedAt = next, "changed", now.Add(time.Hour)
				if next == "pending" {
					in.Tier = "approve"
				}
				q, _, err := st.UpsertProposal(ctx, in)
				must(t, err)
				if q.ID != p.ID || q.State != next || q.Reason != "changed" {
					t.Fatal(q)
				}
				for range 10 {
					q, fresh, err := st.UpsertProposal(ctx, in)
					must(t, err)
					if fresh || q.ID != p.ID {
						t.Fatal(q, fresh)
					}
				}
				ps, err := st.ListProposals(ctx, store.ProposalFilter{})
				must(t, err)
				if len(ps) != 1 {
					t.Fatal(ps)
				}
			})
		}
	}
}

func testProposalDecisionDeadline(t *testing.T, open func(*testing.T) store.Store) {
	for _, decision := range []string{"approved", "rejected"} {
		for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
			t.Run(fmt.Sprint(decision, delta), func(t *testing.T) {
				st, ctx, now := open(t), context.Background(), time.Now().UTC()
				p, _, err := st.UpsertProposal(ctx, store.Proposal{DeviceID: decideDevice(t, st), VulnID: "v", State: "pending", Tier: "approve", CreatedAt: now})
				must(t, err)
				err = st.DecideProposal(ctx, p.ID, decision, "alice", p.ExpiresAt.Add(delta))
				if delta >= 0 && !errors.Is(err, store.ErrConflict) || delta < 0 && err != nil {
					t.Fatalf("deadline offset %v: %v", delta, err)
				}
				q, err := st.GetProposal(ctx, p.ID)
				must(t, err)
				if delta >= 0 && (q.State != "pending" || q.DecidedUser != "") {
					t.Fatal(q)
				}
			})
		}
	}
	for _, state := range []string{"notify", "auto", "resolved", "expired"} {
		t.Run("from-"+state, func(t *testing.T) {
			st, ctx, now := open(t), context.Background(), time.Now().UTC()
			in := store.Proposal{DeviceID: decideDevice(t, st), VulnID: "v", State: state, Tier: "approve", CreatedAt: now}
			if state == "resolved" || state == "expired" {
				in.State = "pending"
			}
			p, _, err := st.UpsertProposal(ctx, in)
			must(t, err)
			if state == "resolved" {
				must(t, st.ResolveProposals(ctx, p.DeviceID, nil))
			}
			if state == "expired" {
				must(t, st.ExpireProposals(ctx, now))
			}
			if err := st.DecideProposal(ctx, p.ID, "approved", "alice", now); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("decision from %s: %v", state, err)
			}
		})
	}
}

func testProposalRetention(t *testing.T, open func(*testing.T) store.Store) {
	for _, state := range []string{"notify", "pending", "auto", "approved", "rejected", "expired", "resolved"} {
		t.Run(state, func(t *testing.T) {
			st, ctx, now := open(t), context.Background(), time.Now().UTC()
			at := now.Add(-91 * 24 * time.Hour)
			in := store.Proposal{DeviceID: decideDevice(t, st), VulnID: "v", Action: "snapshot", State: state, Tier: "approve", CreatedAt: at}
			if state == "approved" || state == "rejected" || state == "expired" || state == "resolved" {
				in.State = "pending"
			}
			p, _, err := st.UpsertProposal(ctx, in)
			must(t, err)
			switch state {
			case "approved", "rejected":
				must(t, st.DecideProposal(ctx, p.ID, state, "alice", at))
			case "expired":
				must(t, st.ExpireProposals(ctx, at))
			case "resolved":
				must(t, st.ResolveProposals(ctx, p.DeviceID, nil))
			}
			p, err = st.GetProposal(ctx, p.ID)
			must(t, err)
			if p.State != state {
				t.Fatal(p)
			}
			// Retention uses the last update, including transitions whose
			// timestamp is recorded internally, and retains the exact boundary.
			must(t, st.PurgeProposals(ctx, p.UpdatedAt))
			if _, err := st.GetProposal(ctx, p.ID); err != nil {
				t.Fatalf("purged at retention boundary: %v", err)
			}
			must(t, st.PurgeProposals(ctx, p.UpdatedAt.Add(time.Second)))
			got, err := st.GetProposal(ctx, p.ID)
			if state == "pending" || state == "auto" || state == "approved" {
				must(t, err)
				if got.State != state {
					t.Fatal(got)
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("closed history survived retention: %+v %v", got, err)
			}
		})
	}
}
