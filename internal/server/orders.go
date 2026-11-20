package server

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func (s *Server) handleActorHello(w http.ResponseWriter, r *http.Request) {
	var h proto.ActorHello
	if e := readJSON(r, &h); e != nil || h.Version != proto.Version || len(h.Capabilities) > 64 {
		writeErr(w, 400, "invalid actor hello")
		return
	}
	allowed := slices.Clone(decide.KnownActions)
	for _, c := range h.Capabilities {
		if c.Reversible && slices.Contains(decide.KnownActions, c.Action) && c.RevertAction != "" {
			allowed = append(allowed, c.RevertAction)
		}
	}
	for _, c := range h.Capabilities {
		if !slices.Contains(allowed, c.Action) || len(c.TargetIDKinds) == 0 || len(c.TargetIDKinds) > 16 || (c.Reversible && (c.RevertAction == "" || len(c.RevertAction) > 64)) {
			writeErr(w, 400, "invalid capability")
			return
		}
		for _, k := range c.TargetIDKinds {
			if k == "" || len(k) > 64 {
				writeErr(w, 400, "invalid target kind")
				return
			}
		}
	}
	p, _ := peerFrom(r.Context())
	if e := s.st.SetActorCaps(r.Context(), p.ID, h.Capabilities, s.now()); e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	s.kickPlanner()
	writeJSON(w, 200, map[string]string{"actor": p.Name})
}
func (s *Server) handleActorOrders(w http.ResponseWriter, r *http.Request) {
	wait := 25
	if v := r.URL.Query().Get("wait"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 {
			writeErr(w, 400, "invalid wait")
			return
		}
		wait = min(n, 30)
	}
	p, _ := peerFrom(r.Context())
	if !s.acquireOrderPoll(p.ID) {
		writeErr(w, 429, "too many order polls")
		return
	}
	defer s.releaseOrderPoll(p.ID)
	t := time.NewTimer(time.Duration(wait) * time.Second)
	defer t.Stop()
	for {
		wake := s.orderWake(p.ID)
		// Recheck peer status after every wake; disabling a waiting actor prevents delivery.
		if r.Context().Err() != nil {
			return // client gone or deadline reached; nothing to answer
		}
		peer, e := s.st.PeerByToken(r.Context(), HashToken(r.Header.Get("Authorization")[7:]))
		if r.Context().Err() != nil {
			return
		}
		if e != nil || peer.Disabled {
			writeErr(w, 401, "invalid token")
			return
		}
		envs, e := s.st.SendOrders(r.Context(), p.ID, s.now())
		if e != nil {
			writeErr(w, 500, "internal error")
			return
		}
		if len(envs) > 0 {
			writeJSON(w, 200, envs)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			writeJSON(w, 200, []orders.Envelope{})
			return
		case <-wake:
		}
	}
}
func (s *Server) handleOrderResult(w http.ResponseWriter, r *http.Request) {
	var result proto.OrderResult
	if e := readJSON(r, &result); e != nil || result.Version != proto.Version || (result.Status != proto.OrderDone && result.Status != proto.OrderFailed && result.Status != proto.OrderRejected) || len(result.Message) > 4096 {
		writeErr(w, 400, "invalid order result")
		return
	}
	p, _ := peerFrom(r.Context())
	s.orders.run.Lock()
	previous, previousErr := s.st.GetOrder(r.Context(), result.OrderID)
	e := s.st.FinishOrder(r.Context(), p.ID, result, s.now())
	s.orders.run.Unlock()
	if errors.Is(e, store.ErrNotFound) {
		writeErr(w, 404, "no such order")
		return
	}
	if errors.Is(e, store.ErrConflict) {
		writeErr(w, 409, "order result conflicts or is outside the reporting window")
		return
	}
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if previousErr == nil && previous.State == string(result.Status) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if result.Status != proto.OrderDone {
		o, e := s.st.GetOrder(r.Context(), result.OrderID)
		if e == nil {
			sev := "warning"
			if o.Revert {
				sev = "critical"
			}
			s.emit(r.Context(), notify.Event{Type: "order." + string(result.Status), Severity: sev, Title: "Order " + o.ID + " " + string(result.Status), Detail: result.Message, Link: "#/actions"}, p.Name, `{"severity":"`+sev+`"}`)
		}
	}
	s.kickPlanner()
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) handleActors(w http.ResponseWriter, r *http.Request) {
	a, e := s.st.ListActors(r.Context())
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) handleOrders(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.OrderFilter{State: q.Get("state")}
	if f.State != "" && !slices.Contains([]string{"queued", "sent", "done", "failed", "rejected", "expired", "cancelled", "uncertain"}, f.State) {
		writeErr(w, 400, "invalid state")
		return
	}
	if v := q.Get("proposal"); v != "" {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n < 1 {
			writeErr(w, 400, "invalid proposal")
			return
		}
		f.ProposalID = n
	}
	if v := q.Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 20000 {
			writeErr(w, 400, "invalid limit")
			return
		}
		f.Limit = n
	}
	os, e := s.st.ListOrders(r.Context(), f)
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, os)
}
func (s *Server) handleRevertOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, e := s.st.GetOrder(r.Context(), id); errors.Is(e, store.ErrNotFound) {
		writeErr(w, 404, "no such order")
		return
	} else if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	s.orders.run.Lock()
	e := s.st.ScheduleRevert(r.Context(), id, s.now())
	s.orders.run.Unlock()
	if errors.Is(e, store.ErrConflict) {
		writeErr(w, 409, "order cannot be reverted")
		return
	}
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	s.kickPlanner()
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "order.revert", u.Name, "revert requested for "+id)
	writeJSON(w, 202, map[string]string{"status": "scheduled"})
}
func (s *Server) orderKeyInfo() (string, string) {
	if len(s.orders.key) != ed25519.PrivateKeySize {
		return "", ""
	}
	return orders.PublicKey(s.orders.key), orders.Fingerprint(s.orders.key.Public().(ed25519.PublicKey))
}

// LoadOrCreateOrderKey loads the server's persistent Ed25519 signing key.
func LoadOrCreateOrderKey(dataDir string) (ed25519.PrivateKey, error) {
	return orders.LoadOrCreateOrderKey(dataDir)
}
