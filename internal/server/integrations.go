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
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
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
		registry.Schema
	}
	entries := []entry{}
	for _, r := range integrationRegistries() {
		for _, typ := range r.types() {
			if schema, ok := r.schema(typ); ok {
				entries = append(entries, entry{r.kind, typ, schema})
			}
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
	if i.Kind == "" {
		i.Kind = "source"
	}
	v := integrationView{ID: i.ID, Kind: i.Kind, Type: i.Type, Name: i.Name, Enabled: i.Enabled, FromConfig: config, LastOKAt: i.LastOKAt, Settings: map[string]json.RawMessage{}, Secrets: map[string]secretFlag{}}
	var settings map[string]json.RawMessage
	var secrets map[string]string
	_ = json.Unmarshal(i.Settings, &settings)
	_ = json.Unmarshal(i.Secrets, &secrets)
	schema, _ := integrationSchema(i.Kind, i.Type)
	for _, f := range schema.Fields {
		if f.Type == "secret" || secrets[f.Key] != "" {
			set := secrets[f.Key] != ""
			if config {
				var direct, file string
				_ = json.Unmarshal(settings[f.Key], &direct)
				_ = json.Unmarshal(settings[f.Key+"_file"], &file)
				set = direct != "" || file != ""
				if f.Key == "headers_json" && len(settings["headers"]) > 2 {
					set = true
				}
			}
			v.Secrets[f.Key] = secretFlag{set}
		} else if b, ok := settings[f.Key]; ok {
			var raw string
			_ = json.Unmarshal(b, &raw)
			if integrationURLField(f) && tlspin.CredentialURL(raw) {
				v.Secrets[f.Key] = secretFlag{true}
			} else {
				v.Settings[f.Key] = b
			}
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
		if a := sup.plugins[key]; a != nil {
			v.Running = a.plugin != nil && a.row.Enabled
			v.LastError = a.errText
		}
		out = append(out, v)
	}
	for _, i := range rows {
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
	for index, i := range s.configPlugins() {
		add(i, configPluginKey(index), true)
	}
	if len(s.cfg.MQTT) > 0 && strings.TrimSpace(string(s.cfg.MQTT)) != "null" {
		add(store.Integration{Kind: "notify", Type: "mqtt", Name: "mqtt", Settings: s.cfg.MQTT, Enabled: true}, "legacy-mqtt", true)
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

func integrationURLField(f registry.Field) bool {
	return f.Type == "url" || f.Key == "url" || f.Key == "base_url"
}

// prepareIntegration admits only schema keys and moves secrets into a separate
// object. File paths and source TLS bypasses remain config-file-only settings.
func prepareIntegration(req integrationRequest, old *store.Integration, allowEndpointReuse ...bool) (store.Integration, error) {
	kind := req.Kind
	if kind == "" {
		if old != nil {
			kind = old.Kind
		} else {
			kind = "source"
		}
	}
	i := store.Integration{Kind: kind, Type: req.Type, Name: req.Name, Enabled: true}
	if old != nil {
		i = *old
		if kind != old.Kind || req.Type != old.Type {
			return i, errors.New("integration kind and type cannot change")
		}
		i.Name = req.Name
	}
	if !peerNameRE.MatchString(i.Name) {
		return i, errors.New("name must contain 1 to 63 letters, numbers, dots, underscores or hyphens")
	}
	if req.Enabled != nil {
		i.Enabled = *req.Enabled
	}
	schema, ok := integrationSchema(i.Kind, i.Type)
	if !ok {
		return i, errors.New("unknown integration type")
	}
	fields := map[string]registry.Field{}
	for _, f := range schema.Fields {
		fields[f.Key] = f
	}
	settings := map[string]json.RawMessage{}
	secrets := map[string]string{}
	if old != nil {
		secrets = storedIntegrationSecrets(*old)
	}

	for key := range req.Settings {
		f, ok := fields[key]
		if !ok || f.Type == "secret" {
			return i, errors.New("settings contain an unsupported field; send credentials in secrets")
		}
	}
	for key, value := range req.Secrets {
		f, ok := fields[key]
		if !ok || (f.Type != "secret" && !integrationURLField(f)) {
			return i, errors.New("secrets contain an unsupported field")
		}
		if value != "" {
			secrets[key] = value
		}
	}
	for _, f := range schema.Fields {
		if f.Type == "secret" {
			if f.Key == "url" || f.Key == "base_url" {
				if err := tlspin.CheckURL(secrets[f.Key], false); err != nil || !strings.HasPrefix(secrets[f.Key], "https://") {
					return i, errors.New("HTTPS endpoint required")
				}
			}
			if f.Required && strings.TrimSpace(secrets[f.Key]) == "" {
				return i, fmt.Errorf("%s is required", f.Label)
			}
			continue
		}
		b, exists := req.Settings[f.Key]
		if integrationURLField(f) && (!exists || string(b) == `""`) && secrets[f.Key] != "" {
			b, _ = json.Marshal(secrets[f.Key])
			exists = true
		}
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
		case "int":
			var value int
			valid = string(b) != "null" && json.Unmarshal(b, &value) == nil && value > 0
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
				if i.Kind == "source" && f.Key == "interval" && d < 30*time.Second {
					valid = false
				}
			}
			if valid && f.Type == "fingerprint" && value != "" {
				_, err := tlspin.Parse(value)
				valid = err == nil
			}
			if valid && integrationURLField(f) {
				valid = tlspin.CheckURL(value, false) == nil && strings.HasPrefix(value, "https://")
			}
		}
		if !valid {
			return i, fmt.Errorf("invalid %s", f.Label)
		}
		if integrationURLField(f) {
			var raw string
			_ = json.Unmarshal(b, &raw)
			if tlspin.CredentialURL(raw) {
				secrets[f.Key] = raw
				continue
			}
			delete(secrets, f.Key)
		}
		if f.Key == "broker" {
			var broker string
			_ = json.Unmarshal(b, &broker)
			if !strings.HasPrefix(broker, "mqtts://") {
				return i, errors.New("MQTT TLS required")
			}
		}
		settings[f.Key] = b
	}
	i.Settings, _ = json.Marshal(settings)
	i.Secrets, _ = json.Marshal(secrets)
	if old != nil && integrationEndpointChanged(*old, i) && (len(allowEndpointReuse) == 0 || !allowEndpointReuse[0]) {
		saved := storedIntegrationSecrets(*old)
		for key, value := range saved {
			var submitted string
			if fields[key].Type != "secret" && integrationURLField(fields[key]) {
				_ = json.Unmarshal(req.Settings[key], &submitted)
			}
			if value != "" && req.Secrets[key] == "" && submitted == "" {
				return i, errors.New("endpoint changed; enter all stored secrets again")
			}
		}
	}
	return i, nil
}

// Older rows may still carry credential URLs among settings. Preserve their
// write-only behavior while they are migrated into secrets on the next save.
func storedIntegrationSecrets(i store.Integration) map[string]string {
	secrets := map[string]string{}
	_ = json.Unmarshal(i.Secrets, &secrets)
	if secrets == nil {
		secrets = map[string]string{}
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(i.Settings, &settings)
	schema, _ := integrationSchema(i.Kind, i.Type)
	for _, f := range schema.Fields {
		var raw string
		_ = json.Unmarshal(settings[f.Key], &raw)
		if secrets[f.Key] == "" && raw != "" && (f.Type == "secret" || (integrationURLField(f) && tlspin.CredentialURL(raw))) {
			secrets[f.Key] = raw
		}
	}
	return secrets
}

// Compare effective endpoints, including write-only webhook URLs and defaults.
func integrationEndpointChanged(old, next store.Integration) bool {
	a, _ := integrationSettings(old)
	b, _ := integrationSettings(next)
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(a, &before)
	_ = json.Unmarshal(b, &after)
	schema, _ := integrationSchema(next.Kind, next.Type)
	for _, f := range schema.Fields {
		if f.Type != "url" && f.Type != "fingerprint" && f.Key != "url" && f.Key != "fingerprint" && f.Key != "broker" && f.Key != "base_url" {
			continue
		}
		var x, y any
		_ = json.Unmarshal(before[f.Key], &x)
		_ = json.Unmarshal(after[f.Key], &y)
		if x == nil && f.Default != nil {
			x = f.Default
		}
		if y == nil && f.Default != nil {
			y = f.Default
		}
		if !reflect.DeepEqual(x, y) {
			return true
		}
	}
	return false
}

func integrationAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, "integration not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, 409, "an integration or peer with this name already exists")
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
	if _, err = buildPlugin(i); err != nil {
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
		writeErr(w, 503, "saved; integration refresh will retry shortly")
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
	if !supportedIntegrationKind(i.Kind) {
		writeErr(w, 404, "integration not found")
		return
	}
	if r.Method == http.MethodDelete {
		err = s.st.DeleteIntegration(r.Context(), id)
	} else {
		i.Enabled = strings.HasSuffix(r.URL.Path, "/enable")
		if i.Enabled {
			if _, err := buildPlugin(i); err != nil {
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
		writeErr(w, 503, "saved; integration refresh will retry shortly")
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
	select {
	case s.integrations.testSlots <- struct{}{}:
	default:
		writeErr(w, 429, "too many probes or tests")
		return
	}
	defer func() { <-s.integrations.testSlots }()
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
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: integrationProbeTimeout, Control: tlspin.SafeControl}, Config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} // operator must compare and confirm the returned pin
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
	if readJSON(r, &req) != nil || len(req.Password) > 1024 {
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
	reuse := false
	if req.Password != "" {
		if !s.updateStepUp(w, r, req.Password) {
			return
		}
		reuse = true
	}
	i, err := prepareIntegration(req, old, reuse)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	plugin, err := buildPlugin(i)
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
	type testResult struct {
		fields map[string]any
		err    error
	}
	done := make(chan testResult, 1)
	go func() {
		result := testResult{}
		defer func() {
			if recover() != nil {
				result.err = errors.New("integration test failed")
			}
			<-s.integrations.testSlots
			done <- result
		}()
		if src, ok := plugin.(source.Source); ok {
			result.err = pollIntegration(ctx, src, func(obs proto.Observation) error {
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
		} else {
			result.fields, result.err = testPlugin(ctx, plugin)
		}
	}()
	fields := map[string]any{}
	select {
	case result := <-done:
		err = result.err
		if result.fields != nil {
			fields = result.fields
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	errText := ""
	if ctx.Err() != nil {
		err = ctx.Err()
		errText = "Connection test timed out or was canceled."
	} else if err != nil {
		errText = "Connection test failed; check credentials, URL and settings."
	}
	fields["ok"], fields["entities"], fields["error"] = err == nil, entities.Load(), errText
	writeJSON(w, 200, fields)
}
