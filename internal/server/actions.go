package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func (s *Server) handleSetTags(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, 400, "bad id")
		return
	}
	var req struct {
		Tags *[]string `json:"tags"`
	}
	if e := readJSON(r, &req); e != nil || req.Tags == nil {
		writeErr(w, 400, "bad request")
		return
	}
	if e := store.ValidateTags(*req.Tags); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if e := s.st.SetTags(r.Context(), id, *req.Tags); e != nil {
		if errors.Is(e, store.ErrNotFound) {
			writeErr(w, 404, "device not found")
		} else {
			writeErr(w, 500, "internal error")
		}
		return
	}
	tags, e := s.st.Tags(r.Context(), id)
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "device.tags", u.Name, "updated tags on device #"+strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]any{"tags": tags})
}
func (s *Server) handleProposals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ProposalFilter{State: q.Get("state")}
	switch f.State {
	case "", "all", "notify", "auto", "pending", "approved", "rejected", "expired", "resolved":
	default:
		writeErr(w, 400, "bad state")
		return
	}
	if v := q.Get("device"); v != "" {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n < 1 {
			writeErr(w, 400, "bad device")
			return
		}
		f.DeviceID = n
	}
	if v := q.Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 20000 {
			writeErr(w, 400, "limit must be 1 to 20000")
			return
		}
		f.Limit = n
	}
	ps, e := s.st.ListProposals(r.Context(), f)
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, ps)
}
func (s *Server) handleProposalDecision(state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(r)
		if !ok {
			writeErr(w, 400, "bad id")
			return
		}
		u, _ := userFrom(r.Context())
		if e := s.st.DecideProposal(r.Context(), id, state, u.Name, s.now()); e != nil {
			if errors.Is(e, store.ErrConflict) {
				writeErr(w, 409, "proposal is no longer pending")
			} else {
				writeErr(w, 500, "internal error")
			}
			return
		}
		s.event(r.Context(), "proposal."+state, u.Name, "proposal #"+strconv.FormatInt(id, 10)+" "+state)
		p, e := s.st.GetProposal(r.Context(), id)
		if e != nil {
			writeErr(w, 500, "internal error")
			return
		}
		writeJSON(w, 200, p)
	}
}
func (s *Server) handleReevaluate(w http.ResponseWriter, r *http.Request) {
	s.decide.mu.Lock()
	started := !s.decide.reevaluating
	if started {
		s.decide.reevaluating = true
	}
	s.decide.mu.Unlock()
	if started {
		s.startReevaluate()
	}
	writeJSON(w, 202, map[string]string{"status": "started"})
}
func (s *Server) handleDecideSettings(w http.ResponseWriter, r *http.Request) {
	v, e := s.st.GetSetting(r.Context(), "decide.killswitch")
	if e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	names := []string{}
	guards := []string{}
	s.decide.mu.Lock()
	for _, d := range s.decide.deciders {
		if n, ok := d.(interface{ RuleNames() []string }); ok {
			names = append(names, n.RuleNames()...)
		}
	}
	for _, g := range s.decide.guards {
		guards = append(guards, g.Name())
	}
	s.decide.mu.Unlock()
	writeJSON(w, 200, map[string]any{"killswitch": v == "on", "rules": names, "guards": guards})
}
func (s *Server) handleSetDecideSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Killswitch *bool `json:"killswitch"`
	}
	if e := readJSON(r, &req); e != nil || req.Killswitch == nil {
		writeErr(w, 400, "killswitch boolean required")
		return
	}
	v := "off"
	if *req.Killswitch {
		v = "on"
	}
	if e := s.st.SetSetting(r.Context(), "decide.killswitch", v); e != nil {
		writeErr(w, 500, "internal error")
		return
	}
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "decide.killswitch", u.Name, "kill switch "+v)
	writeJSON(w, 200, map[string]bool{"killswitch": *req.Killswitch})
}
