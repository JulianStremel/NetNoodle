package server

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netnoodle/internal/store"
)

const peerKey ctxKey = 2

var peerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func peerFrom(ctx context.Context) (store.Peer, bool) {
	p, ok := ctx.Value(peerKey).(store.Peer)
	return p, ok
}

// requirePeer accepts requests with a valid peer bearer token of one of
// the given roles.
func (s *Server) requirePeer(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || tok == "" {
			writeErr(w, http.StatusUnauthorized, "bearer token required")
			return
		}
		p, err := s.st.PeerByToken(r.Context(), HashToken(tok))
		if err != nil || p.Disabled {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		allowed := false
		for _, role := range roles {
			if p.Role == role {
				allowed = true
			}
		}
		if !allowed {
			writeErr(w, http.StatusForbidden, "role "+p.Role+" may not use this endpoint")
			return
		}
		_ = s.st.TouchPeer(r.Context(), p.ID, s.now())
		next(w, r.WithContext(context.WithValue(r.Context(), peerKey, p)))
	}
}

// handleEnroll exchanges a join token for a peer token.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JoinToken string `json:"join_token"`
		Name      string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ip, now := clientIP(r), s.now()
	if !s.limiter.allowed(ip, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts, wait a few minutes")
		return
	}
	if req.Name != "" && !peerNameRE.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+peerNameRE.String())
		return
	}
	tok := RandomToken(32)
	p, err := s.st.Enroll(r.Context(), HashToken(req.JoinToken), req.Name, HashToken(tok), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.limiter.fail(ip, now)
		writeErr(w, http.StatusUnauthorized, "invalid or expired join token")
		return
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "a peer with this name exists already")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r.Context(), "peer.enrolled", p.Name, "peer "+p.Name+" enrolled as "+p.Role+" from "+ip)
	writeJSON(w, http.StatusOK, map[string]string{"name": p.Name, "role": p.Role, "token": tok})
}

// --- operator API for peers and join tokens ---

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	ps, err := s.st.ListPeers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleSetPeerDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad id")
			return
		}
		if err := s.st.SetPeerDisabled(r.Context(), id, disabled); err != nil {
			writeErr(w, http.StatusNotFound, "no such peer")
			return
		}
		u, _ := userFrom(r.Context())
		verb := "enabled"
		if disabled {
			verb = "disabled"
		}
		s.event(r.Context(), "peer."+verb, u.Name, "peer #"+strconv.FormatInt(id, 10)+" "+verb)
		writeJSON(w, http.StatusOK, map[string]string{})
	}
}

func (s *Server) handleListJoinTokens(w http.ResponseWriter, r *http.Request) {
	js, err := s.st.ListJoinTokens(r.Context(), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, js)
}

func (s *Server) handleCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role  string `json:"role"`
		Name  string `json:"name"`
		Uses  int    `json:"uses"`
		Hours int    `json:"hours"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	switch req.Role {
	case store.RoleSource, store.RoleAgent, store.RoleActor:
	default:
		writeErr(w, http.StatusBadRequest, "role must be source, agent or actor")
		return
	}
	if req.Name != "" && !peerNameRE.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+peerNameRE.String())
		return
	}
	if req.Uses < 1 {
		req.Uses = 1
	}
	if req.Name != "" {
		req.Uses = 1 // a fixed name can enroll only once
	}
	if req.Hours < 1 || req.Hours > 24*30 {
		req.Hours = 24
	}
	tok := RandomToken(24)
	exp := s.now().Add(time.Duration(req.Hours) * time.Hour)
	id, err := s.st.CreateJoinToken(r.Context(), HashToken(tok), req.Role, req.Name, req.Uses, exp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "jointoken.created", u.Name, "join token #"+strconv.FormatInt(id, 10)+" for role "+req.Role)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "token": tok, "expires": exp, "fingerprint": s.fingerprint})
}

func (s *Server) handleDeleteJoinToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.st.DeleteJoinToken(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{})
}
