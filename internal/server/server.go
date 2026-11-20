// Package server is the HTTP side of nn-server: the web UI, the operator
// API (/api/...) and the component protocol (/v1/...).
package server

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// Server holds the HTTP handlers and their dependencies.
type Server struct {
	cfg         Config
	st          store.Store
	log         *slog.Logger
	ui          fs.FS
	fingerprint string
	limiter     *loginLimiter
	notifiers   []notify.Notifier
	notifySem   chan struct{}
	enrollLim   *loginLimiter
	bcryptSem   chan struct{}
	peerRate    *rateLimiter
	reserved    map[string]bool
	decide      *decideState
	intel       *intelState
	pull        *pullState
	orders      *orderState
	now         func() time.Time
}

// New creates a server. ui is the static web UI file system.
func New(cfg Config, st store.Store, ui fs.FS, fingerprint string, log *slog.Logger) *Server {
	return &Server{
		cfg:         cfg,
		st:          st,
		log:         log,
		ui:          ui,
		fingerprint: fingerprint,
		limiter:     newLoginLimiter(),
		enrollLim:   newLoginLimiter(),
		bcryptSem:   make(chan struct{}, 4),
		notifySem:   make(chan struct{}, 8),
		peerRate:    newRateLimiter(60, 10*time.Minute),
		reserved:    reservedNames(cfg),
		intel:       newIntelState(),
		decide:      newDecideState(),
		pull:        newPullState(),
		orders:      newOrderState(),
		now:         time.Now,
	}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Component protocol.
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/observations", s.requirePeer(s.handleObservations, store.RoleSource, store.RoleAgent))
	mux.HandleFunc("POST /v1/actor/hello", s.requirePeer(s.handleActorHello, store.RoleActor))
	mux.HandleFunc("GET /v1/orders", s.requirePeer(s.handleActorOrders, store.RoleActor))
	mux.HandleFunc("POST /v1/orders/result", s.requirePeer(s.handleOrderResult, store.RoleActor))
	mux.HandleFunc("GET /api/orders", requireUser(s.handleOrders))
	mux.HandleFunc("GET /api/actors", requireUser(s.handleActors))
	mux.HandleFunc("POST /api/orders/{id}/revert", requireUser(s.handleRevertOrder))

	// Operator API for the web UI.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", requireUser(s.handleMe))
	mux.HandleFunc("GET /api/info", requireUser(s.handleInfo))
	mux.HandleFunc("GET /api/overview", requireUser(s.handleOverview))
	mux.HandleFunc("GET /api/findings", requireUser(s.handleFindings))
	mux.HandleFunc("POST /api/intel/refresh", requireUser(s.handleIntelRefresh))
	mux.HandleFunc("GET /api/events", requireUser(s.handleEvents))
	mux.HandleFunc("GET /api/graph", requireUser(s.handleGraph))
	mux.HandleFunc("GET /api/devices", requireUser(s.handleListDevices))
	mux.HandleFunc("GET /api/devices/{id}", requireUser(s.handleGetDevice))
	mux.HandleFunc("GET /api/devices/{id}/related", requireUser(s.handleRelated))
	mux.HandleFunc("POST /api/devices/{id}/name", requireUser(s.handleRenameDevice))
	mux.HandleFunc("GET /api/peers", requireUser(s.handleListPeers))
	mux.HandleFunc("POST /api/peers/{id}/disable", requireUser(s.handleSetPeerDisabled(true)))
	mux.HandleFunc("POST /api/peers/{id}/enable", requireUser(s.handleSetPeerDisabled(false)))
	mux.HandleFunc("GET /api/pull-peers", requireUser(s.handleListPullPeers))
	mux.HandleFunc("POST /api/pull-peers", requireUser(s.handleCreatePullPeer))
	mux.HandleFunc("POST /api/pull-peers/{id}/pair", requireUser(s.handleNewPairCode))
	mux.HandleFunc("POST /api/pull-peers/{id}/pull", requireUser(s.handlePullNow))
	mux.HandleFunc("GET /api/join-tokens", requireUser(s.handleListJoinTokens))
	mux.HandleFunc("POST /api/join-tokens", requireUser(s.handleCreateJoinToken))
	mux.HandleFunc("DELETE /api/join-tokens/{id}", requireUser(s.handleDeleteJoinToken))

	mux.HandleFunc("PUT /api/devices/{id}/tags", requireUser(s.handleSetTags))
	mux.HandleFunc("GET /api/proposals", requireUser(s.handleProposals))
	mux.HandleFunc("POST /api/proposals/reevaluate", requireUser(s.handleReevaluate))
	mux.HandleFunc("POST /api/proposals/{id}/approve", requireUser(s.handleProposalDecision("approved")))
	mux.HandleFunc("POST /api/proposals/{id}/reject", requireUser(s.handleProposalDecision("rejected")))
	mux.HandleFunc("GET /api/decide/settings", requireUser(s.handleDecideSettings))
	mux.HandleFunc("PUT /api/decide/settings", requireUser(s.handleSetDecideSettings))

	// Static UI. Unknown /api/ and /v1/ paths get a JSON 404, not a page.
	files := http.FileServerFS(s.ui)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			writeErr(w, http.StatusNotFound, "no such endpoint")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		files.ServeHTTP(w, r)
	})

	return securityHeaders(bodyLimits(jsonOnlyWrites(s.withUser(mux))))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// jsonOnlyWrites rejects state-changing requests that are not JSON. A
// cross-site form cannot send application/json without a CORS preflight,
// so together with SameSite=Strict cookies this blocks CSRF.
func jsonOnlyWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimits sets a small body limit and a short read deadline on every
// request (before any other check), except for POSTs of observations,
// which can be large. This bounds memory and stops slow-body requests,
// also on paths that reject the request without reading the body.
func bodyLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, deadline := int64(64<<10), 20*time.Second
		if r.Method == http.MethodPost && r.URL.Path == "/v1/observations" {
			limit, deadline = maxObservation, 5*time.Minute
		}
		// The order long poll waits up to 30 s; the read deadline also
		// cancels the request context, so it must be longer.
		if r.Method == http.MethodGet && r.URL.Path == "/v1/orders" {
			deadline = time.Minute
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(deadline))
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "protocol": "v1"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ip := clientIP(r)
	now := s.now()
	// Reserve the attempt before the password check, so parallel requests
	// cannot pass the limit; free it again on success.
	if !s.limiter.reserve(ip, now) {
		writeErr(w, http.StatusTooManyRequests, "too many failed logins, wait a few minutes")
		return
	}
	select {
	case s.bcryptSem <- struct{}{}:
	case <-time.After(10 * time.Second):
		writeErr(w, http.StatusServiceUnavailable, "busy, try again")
		return
	}
	u, ok := s.checkLogin(r.Context(), req.User, req.Password)
	<-s.bcryptSem
	if ok {
		s.limiter.release(ip)
	}
	if !ok {
		s.event(r.Context(), "login.failed", ip, "failed login for "+truncate(req.User, 64))
		writeErr(w, http.StatusUnauthorized, errBadLogin.Error())
		return
	}
	tok := RandomToken(32)
	exp := now.Add(s.cfg.SessionTTL.Duration)
	if err := s.st.CreateSession(r.Context(), HashToken(tok), u.ID, u.PassHash, exp); err != nil {
		s.log.Error("create session", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.st.PurgeSessions(r.Context(), now)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	s.event(r.Context(), "login", u.Name, "login from "+ip)
	writeJSON(w, http.StatusOK, map[string]string{"user": u.Name})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.st.DeleteSession(r.Context(), HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"user": u.Name})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	key, fp := s.orderKeyInfo()
	writeJSON(w, http.StatusOK, map[string]string{
		"order_key":             key,
		"order_key_fingerprint": fp,
		"protocol":              "v1",
		"tls_fingerprint":       s.fingerprint,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ev, err := s.st.ListEvents(r.Context(), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ev == nil {
		ev = []store.Event{}
	}
	writeJSON(w, http.StatusOK, ev)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
