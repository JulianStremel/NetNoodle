package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

func (s *Server) integrationRoutes(mux *http.ServeMux) {
	admin := func(fn http.HandlerFunc) http.HandlerFunc {
		return requireUser(func(w http.ResponseWriter, r *http.Request) {
			if adminUpdate(w, r) {
				fn(w, r)
			}
		})
	}
	mux.HandleFunc("GET /api/integrations", admin(s.handleIntegrations))
	mux.HandleFunc("GET /api/integrations/types", admin(s.handleIntegrationTypes))
	mux.HandleFunc("POST /api/integrations/probe", admin(s.handleIntegrationProbe))
	mux.HandleFunc("POST /api/integrations/test", admin(s.handleIntegrationTest))
	mux.HandleFunc("POST /api/integrations", admin(s.handleSaveIntegration))
	mux.HandleFunc("PUT /api/integrations/{id}", admin(s.handleSaveIntegration))
	mux.HandleFunc("DELETE /api/integrations/{id}", admin(s.handleChangeIntegration))
	mux.HandleFunc("POST /api/integrations/{id}/enable", admin(s.handleChangeIntegration))
	mux.HandleFunc("POST /api/integrations/{id}/disable", admin(s.handleChangeIntegration))
}

func (s *Server) handleIntegrationTypes(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Kind string `json:"kind"`
		Type string `json:"type"`
		source.Schema
	}
	entries := []entry{}
	for _, typ := range source.Registry.Types() {
		if schema, ok := source.Registry.Schema(typ); ok {
			entries = append(entries, entry{"source", typ, schema})
		}
	}
	writeJSON(w, 200, entries)
}

type integrationView struct {
	ID         int64                      `json:"id"`
	Kind       string                     `json:"kind"`
	Type       string                     `json:"type"`
	Name       string                     `json:"name"`
	Settings   map[string]json.RawMessage `json:"settings"`
	Secrets    map[string]secretFlag      `json:"secrets"`
	Enabled    bool                       `json:"enabled"`
	FromConfig bool                       `json:"from_config"`
	Running    bool                       `json:"running"`
	LastPoll   time.Time                  `json:"last_poll,omitzero"`
	LastOKAt   time.Time                  `json:"last_ok_at,omitzero"`
	LastError  string                     `json:"last_error"`
}

type secretFlag struct {
	Set bool `json:"set"`
}

func publicIntegration(i store.Integration, config bool) integrationView {
	v := integrationView{ID: i.ID, Kind: "source", Type: i.Type, Name: i.Name, Enabled: i.Enabled, FromConfig: config, LastOKAt: i.LastOKAt, Settings: map[string]json.RawMessage{}, Secrets: map[string]secretFlag{}}
	var settings map[string]json.RawMessage
	var secrets map[string]string
	_ = json.Unmarshal(i.Settings, &settings)
	_ = json.Unmarshal(i.Secrets, &secrets)
	schema, _ := source.Registry.Schema(i.Type)
	for _, f := range schema.Fields {
		if f.Type == "secret" {
			set := secrets[f.Key] != ""
			if config {
				var direct, file string
				_ = json.Unmarshal(settings[f.Key], &direct)
				_ = json.Unmarshal(settings[f.Key+"_file"], &file)
				set = direct != "" || file != ""
			}
			v.Secrets[f.Key] = secretFlag{set}
		} else if b, ok := settings[f.Key]; ok {
			v.Settings[f.Key] = b
		}
	}
	if i.LastError != "" {
		v.LastError = "Poll failed; check credentials, URL and TLS settings."
	}
	return v
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	sup := s.integrations
	sup.mu.Lock()
	defer sup.mu.Unlock()
	rows, err := s.st.ListIntegrations(r.Context())
	if err != nil {
		writeErr(w, 500, "cannot list integrations")
		return
	}
	out := []integrationView{}
	add := func(i store.Integration, key string, config bool) {
		v := publicIntegration(i, config)
		if worker := sup.workers[key]; worker != nil {
			worker.mu.Lock()
			v.Running, v.LastPoll, v.LastError = worker.running, worker.lastPoll, worker.lastError
			if !worker.lastOKAt.IsZero() {
				v.LastOKAt = worker.lastOKAt
			}
			worker.mu.Unlock()
		}
		out = append(out, v)
	}
	for _, i := range rows {
		if i.Kind != "source" {
			continue
		}
		add(i, integrationKey(i.ID), false)
	}
	specs := s.cfg.Sources
	if sup.ctx != nil {
		specs = sup.config
	}
	for index, spec := range specs {
		name := spec.Name
		if name == "" {
			name = spec.Type
		}
		var settings map[string]json.RawMessage
		_ = json.Unmarshal(spec.Settings, &settings)
		if settings == nil {
			settings = map[string]json.RawMessage{}
		}
		interval := spec.Interval.Duration
		if interval <= 0 {
			interval = 10 * time.Minute
		}
		settings["interval"], _ = json.Marshal(interval.String())
		raw, _ := json.Marshal(settings)
		add(store.Integration{Type: spec.Type, Name: name, Settings: raw, Enabled: !spec.Disabled}, configIntegrationKey(index), true)
	}
	writeJSON(w, 200, out)
}

type integrationRequest struct {
	Kind     string                     `json:"kind,omitempty"`
	ID       int64                      `json:"id,omitempty"` // optional saved credentials for an edit dry run
	Type     string                     `json:"type"`
	Name     string                     `json:"name"`
	Settings map[string]json.RawMessage `json:"settings"`
	Secrets  map[string]string          `json:"secrets"`
	Enabled  *bool                      `json:"enabled,omitempty"`
	Password string                     `json:"password,omitempty"`
}

// prepareIntegration admits only schema keys and moves secrets into a separate
// object. File paths and insecure TLS options remain config-file-only settings.
func prepareIntegration(req integrationRequest, old *store.Integration) (store.Integration, error) {
	i := store.Integration{Kind: "source", Type: req.Type, Name: req.Name, Enabled: true}
	if req.Kind != "" && req.Kind != "source" {
		return i, errors.New("unsupported integration kind")
	}
	if old != nil {
		i = *old
		if old.Kind != "source" {
			return i, errors.New("unsupported integration kind")
		}
		if req.Type != old.Type {
			return i, errors.New("integration type cannot change")
		}
		i.Name = req.Name
	}
	if !peerNameRE.MatchString(i.Name) {
		return i, errors.New("name must contain 1 to 63 letters, numbers, dots, underscores or hyphens")
	}
	if req.Enabled != nil {
		i.Enabled = *req.Enabled
	}
	schema, ok := source.Registry.Schema(i.Type)
	if !ok {
		return i, errors.New("unknown integration type")
	}
	fields := map[string]source.Field{}
	for _, f := range schema.Fields {
		fields[f.Key] = f
	}
	settings := map[string]json.RawMessage{}
	secrets := map[string]string{}
	if old != nil {
		_ = json.Unmarshal(old.Secrets, &secrets)
		if secrets == nil {
			secrets = map[string]string{}
		}
	}
	for key := range req.Settings {
		f, ok := fields[key]
		if !ok || f.Type == "secret" {
			return i, errors.New("settings contain an unsupported field; send credentials in secrets")
		}
	}
	for key, value := range req.Secrets {
		f, ok := fields[key]
		if !ok || f.Type != "secret" {
			return i, errors.New("secrets contain an unsupported field")
		}
		if value != "" {
			secrets[key] = value
		}
	}
	for _, f := range schema.Fields {
		if f.Type == "secret" {
			if f.Required && strings.TrimSpace(secrets[f.Key]) == "" {
				return i, fmt.Errorf("%s is required", f.Label)
			}
			continue
		}
		b, exists := req.Settings[f.Key]
		if !exists && f.Default != nil {
			b, _ = json.Marshal(f.Default)
			exists = true
		}
		if !exists {
			if f.Required {
				return i, fmt.Errorf("%s is required", f.Label)
			}
			continue
		}
		valid := true
		switch f.Type {
		case "bool":
			var value bool
			valid = string(b) != "null" && json.Unmarshal(b, &value) == nil
		case "list":
			var value []string
			valid = string(b) != "null" && json.Unmarshal(b, &value) == nil
			if f.Required && len(value) == 0 {
				valid = false
			}
		default:
			var value string
			valid = string(b) != "null" && json.Unmarshal(b, &value) == nil
			if valid && f.Required && strings.TrimSpace(value) == "" {
				valid = false
			}
			if valid && f.Type == "duration" {
				d, err := time.ParseDuration(value)
				valid = err == nil && d > 0
				if f.Key == "interval" && d < 30*time.Second {
					valid = false
				}
			}
			if valid && f.Type == "fingerprint" && value != "" {
				_, err := tlspin.Parse(value)
				valid = err == nil
			}
			if valid && f.Type == "url" {
				valid = tlspin.CheckURL(value, false) == nil
			}
		}
		if !valid {
			return i, fmt.Errorf("invalid %s", f.Label)
		}
		settings[f.Key] = b
	}
	i.Settings, _ = json.Marshal(settings)
	i.Secrets, _ = json.Marshal(secrets)
	return i, nil
}

func integrationAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, "integration not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, 409, "a source or peer with this name already exists")
	default:
		writeErr(w, 500, "cannot save integration")
	}
}

func (s *Server) handleSaveIntegration(w http.ResponseWriter, r *http.Request) {
	var req integrationRequest
	if readJSON(r, &req) != nil || len(req.Password) > 1024 {
		writeErr(w, 400, "invalid integration request")
		return
	}
	if !s.updateStepUp(w, r, req.Password) {
		return
	}
	sup := s.integrations
	sup.mu.Lock()
	defer sup.mu.Unlock()
	var old *store.Integration
	if r.Method == http.MethodPut {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, 404, "integration not found")
			return
		}
		i, err := s.st.GetIntegration(r.Context(), id)
		if err != nil {
			integrationAPIError(w, err)
			return
		}
		old = &i
	}
	i, err := prepareIntegration(req, old)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if s.reservedName(i.Name) {
		writeErr(w, 409, "this name is reserved by the server or config file")
		return
	}
	if _, _, err = buildIntegration(i); err != nil {
		writeErr(w, 400, "Invalid settings; check required fields, URL and TLS settings.")
		return
	}
	i.UpdatedAt = s.now().UTC()
	if old == nil {
		i.CreatedAt = i.UpdatedAt
		i, err = s.st.CreateIntegration(r.Context(), i)
	} else {
		err = s.st.UpdateIntegration(r.Context(), i)
	}
	if err != nil {
		integrationAPIError(w, err)
		return
	}
	if err = s.reconcileIntegrationsLocked(r.Context()); err != nil {
		writeErr(w, 503, "saved; source refresh will retry shortly")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": i.ID})
}

func (s *Server) handleChangeIntegration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil || len(req.Password) > 1024 {
		writeErr(w, 400, "invalid integration request")
		return
	}
	if !s.updateStepUp(w, r, req.Password) {
		return
	}
	sup := s.integrations
	sup.mu.Lock()
	defer sup.mu.Unlock()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 404, "integration not found")
		return
	}
	i, err := s.st.GetIntegration(r.Context(), id)
	if err != nil {
		integrationAPIError(w, err)
		return
	}
	if i.Kind != "source" {
		writeErr(w, 404, "integration not found")
		return
	}
	if r.Method == http.MethodDelete {
		err = s.st.DeleteIntegration(r.Context(), id)
	} else {
		i.Enabled = strings.HasSuffix(r.URL.Path, "/enable")
		if i.Enabled {
			if _, _, err := buildIntegration(i); err != nil {
				writeErr(w, 400, "Invalid settings; check required fields, URL and TLS settings.")
				return
			}
		}
		i.UpdatedAt = s.now().UTC()
		err = s.st.UpdateIntegration(r.Context(), i)
	}
	if err != nil {
		integrationAPIError(w, err)
		return
	}
	if err = s.reconcileIntegrationsLocked(r.Context()); err != nil {
		writeErr(w, 503, "saved; source refresh will retry shortly")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleIntegrationProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if readJSON(r, &req) != nil {
		writeErr(w, 400, "invalid probe request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), integrationProbeTimeout)
	defer cancel()
	fp, subject, err := probeIntegration(ctx, req.URL)
	if err != nil {
		writeErr(w, 400, "cannot fetch certificate; use an HTTPS URL with a reachable TLS server")
		return
	}
	writeJSON(w, 200, map[string]string{"fingerprint": fp, "subject": subject})
}

func probeIntegration(ctx context.Context, raw string) (string, string, error) {
	if len(raw) > 4096 || tlspin.CheckURL(raw, false) != nil {
		return "", "", errors.New("invalid URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("HTTPS required")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: integrationProbeTimeout}, Config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // operator must compare and confirm the returned pin
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return "", "", errors.New("TLS handshake failed")
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	size := 0
	for _, cert := range certs {
		size += len(cert.Raw)
	}
	if len(certs) == 0 || size > 1<<20 {
		return "", "", errors.New("certificate exceeds size limit")
	}
	subject := certs[0].Subject.String()
	if len(subject) > 4096 {
		return "", "", errors.New("certificate subject exceeds size limit")
	}
	hash := sha256.Sum256(certs[0].Raw)
	// Only a TLS handshake is sent: no HTTP request or response body is read.
	return hex.EncodeToString(hash[:]), subject, nil
}

func (s *Server) handleIntegrationTest(w http.ResponseWriter, r *http.Request) {
	var req integrationRequest
	if readJSON(r, &req) != nil {
		writeErr(w, 400, "invalid test request")
		return
	}
	var old *store.Integration
	if req.ID != 0 {
		i, err := s.st.GetIntegration(r.Context(), req.ID)
		if err != nil {
			integrationAPIError(w, err)
			return
		}
		old = &i
		if req.Name == "" {
			req.Name = i.Name
		}
	}
	if req.Name == "" {
		req.Name = "connection-test"
	}
	i, err := prepareIntegration(req, old)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	src, _, err := buildIntegration(i)
	if err != nil {
		writeErr(w, 400, "Invalid settings; check required fields, URL and TLS settings.")
		return
	}
	select {
	case s.integrations.testSlots <- struct{}{}:
	default:
		writeErr(w, 429, "too many connection tests")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), integrationPollTimeout)
	defer cancel()
	var entities atomic.Int64
	done := make(chan error, 1)
	go func() {
		defer func() { <-s.integrations.testSlots }()
		done <- pollIntegration(ctx, src, func(obs proto.Observation) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var count func([]proto.Entity) int64
			count = func(es []proto.Entity) int64 {
				n := int64(len(es))
				for _, e := range es {
					n += count(e.Children)
				}
				return n
			}
			entities.Add(count(obs.Entities))
			return nil
		})
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	errText := ""
	if ctx.Err() != nil {
		err = ctx.Err()
		errText = "Connection test timed out or was canceled."
	} else if err != nil {
		errText = "Poll failed; check credentials, URL and TLS settings."
	}
	writeJSON(w, 200, map[string]any{"ok": err == nil, "entities": entities.Load(), "error": errText})
}
