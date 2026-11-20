package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JulianStremel/netnoodle/internal/installscripts"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/pull"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/version"
)

const releaseBase = "https://github.com/JulianStremel/NetNoodle/releases/download"

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`)
var sessionID = regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`)

type onboardState struct {
	mu           sync.Mutex
	base         string
	client       *http.Client
	hashes       map[string]map[string]string
	fetching     bool
	failureUntil time.Time
	rate         *rateLimiter
}

func newOnboardState() *onboardState {
	return &onboardState{base: releaseBase, client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 5 {
			return fmt.Errorf("unsafe release redirect")
		}
		return nil
	}}, hashes: make(map[string]map[string]string), rate: newRateLimiter(30, time.Minute)}
}

// SetInstallReleaseSource permits a local release fixture in tests. Production
// callers use the default HTTPS GitHub source and normal certificate checks.
func (s *Server) SetInstallReleaseSource(base string, client *http.Client) {
	s.onboard.mu.Lock()
	defer s.onboard.mu.Unlock()
	s.onboard.base = strings.TrimRight(base, "/")
	s.onboard.client = client
	s.onboard.hashes = make(map[string]map[string]string)
	s.onboard.failureUntil = time.Time{}
}

var setupKeys = []string{"server", "fingerprint", "spki", "session", "secret", "token", "name", "kind", "version", "expires"}

func encodeSetup(fields map[string]string) string {
	var b strings.Builder
	for _, key := range setupKeys {
		fmt.Fprintf(&b, "%s=%s\n", key, fields[key])
	}
	return "nnsetup1:" + base64.RawURLEncoding.EncodeToString([]byte(b.String()))
}
func decodeSetup(code string) (map[string]string, error) {
	if len(code) > 16384 || !strings.HasPrefix(code, "nnsetup1:") {
		return nil, fmt.Errorf("invalid setup code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "nnsetup1:"))
	if err != nil || !utf8.Valid(b) {
		return nil, fmt.Errorf("invalid setup encoding")
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(v, "\r\x00") {
			return nil, fmt.Errorf("invalid setup line")
		}
		if !slices.Contains(setupKeys, k) {
			continue
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate setup key")
		}
		out[k] = v
	}
	for _, k := range setupKeys {
		if out[k] == "" {
			return nil, fmt.Errorf("missing %s", k)
		}
	}
	return out, nil
}
func onboardRole(kind string) string {
	switch kind {
	case "agent", "agent-pull":
		return store.RoleAgent
	case "scan":
		return store.RoleSource
	case "actor-host", "actor-unifi", "actor-proxmox":
		return store.RoleActor
	}
	return ""
}
func (s *Server) installPins() (string, error) {
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "tls", "cert.pem"))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("missing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if Fingerprint(cert.Raw) != s.fingerprint {
		return "", fmt.Errorf("certificate changed")
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}
func shellQuote(s string) string      { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func powershellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func installOneLiner(server, platform, spki, fp string) string {
	if platform == "linux" {
		return `curl -fsSLk --proto '=https' --pinnedpubkey ` + shellQuote("sha256//"+spki) + ` ` + shellQuote(server+"/install.sh") + ` | sudo NN_EXPECTED_SERVER=` + shellQuote(server) + ` NN_EXPECTED_SPKI=` + shellQuote(spki) + ` NN_EXPECTED_FINGERPRINT=` + shellQuote(fp) + ` /bin/sh -s --`
	}
	callback := `public static class NNBootstrapPin { public static string Expected; public static readonly System.Net.Security.RemoteCertificateValidationCallback Callback = Check; public static bool Check(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors errors) { if(cert==null) return false; using(var hash=System.Security.Cryptography.SHA256.Create()) { return System.String.Equals(System.BitConverter.ToString(hash.ComputeHash(cert.GetRawCertData())).Replace("-", ""), Expected, System.StringComparison.OrdinalIgnoreCase); } } }`
	command := `$ErrorActionPreference='Stop'; if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open PowerShell as Administrator first.' }; $old=[Net.ServicePointManager]::ServerCertificateValidationCallback; $protocol=[Net.ServicePointManager]::SecurityProtocol; try { Add-Type -TypeDefinition ` + powershellQuote(callback) + `; [NNBootstrapPin]::Expected=` + powershellQuote(fp) + `; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::ServerCertificateValidationCallback=[NNBootstrapPin]::Callback; $script=(New-Object Net.WebClient).DownloadString(` + powershellQuote(server+"/install.ps1") + `); & ([scriptblock]::Create($script)) -ExpectedServer ` + powershellQuote(server) + ` -ExpectedSPKI ` + powershellQuote(spki) + ` -ExpectedFingerprint ` + powershellQuote(fp) + ` } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback=$old; [Net.ServicePointManager]::SecurityProtocol=$protocol }`
	return `& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command { ` + command + ` }`
}
func (s *Server) handleCreateOnboard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind     string `json:"kind"`
		Name     string `json:"name"`
		Platform string `json:"platform"`
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil || len(req.Password) > 1024 || !peerNameRE.MatchString(req.Name) || onboardRole(req.Kind) == "" || (req.Platform != "linux" && req.Platform != "windows") || (req.Platform == "windows" && req.Kind != "agent" && req.Kind != "scan") {
		writeErr(w, 400, "invalid onboarding request")
		return
	}
	if !s.updateStepUp(w, r, req.Password) {
		return
	}
	if s.reserved[strings.ToLower(req.Name)] {
		writeErr(w, 409, "this name is reserved")
		return
	}
	// The Host header is data, never shell syntax. Permit only an HTTPS origin.
	u, err := url.Parse("https://" + r.Host)
	if err != nil || u.Host == "" || u.Host != r.Host || u.User != nil || u.Path != "" || len(r.Host) > 255 || strings.ContainsAny(r.Host, "\r\n\x00") {
		writeErr(w, 400, "invalid server address")
		return
	}
	spki, err := s.installPins()
	if err != nil {
		writeErr(w, 503, "server certificate unavailable")
		return
	}
	now := s.now()
	if err = s.st.ExpireOnboard(r.Context(), now); err != nil {
		writeErr(w, 503, "try again")
		return
	}
	secret, token := RandomToken(32), RandomToken(24)
	o := store.OnboardSession{ID: updateID(), SecretHash: HashToken(secret), Kind: req.Kind, Name: req.Name, Platform: req.Platform, Expires: now.Add(30 * time.Minute)}
	if err = s.st.CreateOnboard(r.Context(), o, HashToken(token), onboardRole(req.Kind), now); err != nil {
		writeErr(w, 409, "name exists or 20 installations are already open")
		return
	}
	code := encodeSetup(map[string]string{"server": u.String(), "fingerprint": s.fingerprint, "spki": spki, "session": o.ID, "secret": secret, "token": token, "name": o.Name, "kind": o.Kind, "version": version.Version, "expires": o.Expires.UTC().Format(time.RFC3339)})
	s.onboardEvent(r.Context(), "created", o)
	writeJSON(w, 200, map[string]any{"session": o.ID, "setup_code": code, "one_liner": installOneLiner(u.String(), o.Platform, spki, s.fingerprint), "expires": o.Expires})
}
func (s *Server) onboardSession(w http.ResponseWriter, r *http.Request, script bool) (store.OnboardSession, bool) {
	var empty store.OnboardSession
	id := r.PathValue("id")
	if !sessionID.MatchString(id) {
		writeErr(w, 404, "no such session")
		return empty, false
	}
	if !script && !adminUpdate(w, r) {
		return empty, false
	}
	o, err := s.st.GetOnboard(r.Context(), id)
	if script {
		secret := r.Header.Get("X-NN-Onboard-Secret")
		if len(secret) != 43 {
			writeErr(w, 401, "invalid session secret")
			return empty, false
		}
		expected := make([]byte, 32)
		if err == nil {
			copy(expected, o.SecretHash)
		}
		valid := subtle.ConstantTimeCompare(HashToken(secret), expected) == 1
		if err != nil || !valid {
			writeErr(w, 401, "invalid session secret")
			return empty, false
		}
	} else if err != nil {
		writeErr(w, 404, "no such session")
		return empty, false
	}
	// Expiry also applies between periodic ticks.
	if !o.Expires.After(s.now()) && (o.State == "created" || o.State == "enrolled" || o.State == "connected") {
		if err = s.st.ExpireOnboard(r.Context(), s.now()); err != nil {
			writeErr(w, 503, "try again")
			return empty, false
		}
		o, err = s.st.GetOnboard(r.Context(), id)
		if err != nil {
			writeErr(w, 404, "no such session")
			return empty, false
		}
	}
	return o, true
}
func (s *Server) handleOnboardStatus(w http.ResponseWriter, r *http.Request) {
	o, ok := s.onboardSession(w, r, false)
	if ok {
		writeJSON(w, 200, o)
	}
}
func (s *Server) handleScriptStatus(w http.ResponseWriter, r *http.Request) {
	o, ok := s.onboardSession(w, r, true)
	if ok {
		writeJSON(w, 200, map[string]any{"state": o.State, "peer_seen": o.State == "connected" || o.State == "done"})
	}
}
func (s *Server) abortOnboard(w http.ResponseWriter, r *http.Request, script bool) {
	o, ok := s.onboardSession(w, r, script)
	if !ok {
		return
	}
	reason := "cancelled by operator"
	if script {
		var req struct {
			Reason string `json:"reason"`
		}
		if readJSON(r, &req) != nil || len(req.Reason) > 1024 {
			writeErr(w, 400, "invalid reason")
			return
		}
		reason = req.Reason
	}
	if err := s.st.AbortOnboard(r.Context(), o.ID, reason, s.now()); err != nil {
		writeErr(w, 409, "cannot abort this session")
		return
	}
	if o.State != "aborted" && o.State != "expired" {
		event := "cancelled"
		if script {
			event = "aborted"
		}
		s.onboardEvent(r.Context(), event, o)
	}
	writeJSON(w, 200, map[string]string{"state": "aborted"})
}
func (s *Server) handleOnboardStep(w http.ResponseWriter, r *http.Request) {
	o, ok := s.onboardSession(w, r, true)
	if !ok {
		return
	}
	var step store.OnboardStep
	if readJSON(r, &step) != nil || len(step.Name) == 0 || len(step.Name) > 64 || len(step.Message) > 1024 {
		writeErr(w, 400, "invalid step")
		return
	}
	step.At = s.now()
	// Pull pairing needs the address reachable from the server. This progress
	// step returns the existing pairing command's inputs only to this script.
	if step.Name == "pair" && step.OK {
		if err := pull.ValidAddress(step.Message); err != nil {
			writeErr(w, 400, "invalid pull address")
			return
		}
		s.pull.mu.Lock()
		fp := s.pull.clientFP
		s.pull.mu.Unlock()
		if fp == "" {
			writeErr(w, 503, "pull transport unavailable")
			return
		}
		code := newPairCode()
		if err := s.st.PairOnboard(r.Context(), o.ID, step.Message, code, s.now()); err != nil {
			writeErr(w, 409, "cannot pair this session")
			return
		}
		if err := s.st.AddOnboardStep(r.Context(), o.ID, step); err != nil {
			writeErr(w, 409, "cannot record step")
			return
		}
		s.kickPull()
		writeJSON(w, 200, map[string]string{"code": code, "fingerprint": fp})
		return
	}
	if err := s.st.AddOnboardStep(r.Context(), o.ID, step); err != nil {
		writeErr(w, 409, "cannot record step")
		return
	}
	if step.Name == "done" {
		s.onboardEvent(r.Context(), "done", o)
		s.kickPlanner()
		s.kickPull()
	}
	writeJSON(w, 200, map[string]string{})
}
func (s *Server) onboardEvent(ctx context.Context, state string, o store.OnboardSession) {
	s.emit(ctx, notify.Event{Type: "onboarding." + state, Severity: "info", Title: "Onboarding " + state + ": " + o.Name, Link: "#/peers"}, o.Name, `{}`)
}
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Path == "/install.sh" {
		_, _ = w.Write(installscripts.Shell)
	} else {
		_, _ = w.Write(installscripts.PowerShell)
	}
}

type installArtifact struct {
	URL    string   `json:"url"`
	SHA256 string   `json:"sha256"`
	Kind   string   `json:"kind"`
	Files  []string `json:"files"`
}
type installManifest struct {
	Version   string            `json:"version"`
	Artifacts []installArtifact `json:"artifacts"`
}

func releaseAsset(tag, platform, kind string) (string, []string, error) {
	parts := strings.Split(platform, "-")
	if len(parts) != 2 || onboardRole(kind) == "" {
		return "", nil, fmt.Errorf("invalid platform or kind")
	}
	osname, arch := parts[0], parts[1]
	goarch := map[string]string{"x86_64": "amd64", "aarch64": "arm64", "armv7": "armv7", "arm64": "arm64"}[arch]
	if goarch == "" || (osname != "linux" && osname != "windows") || (osname == "linux" && arch == "arm64") || (osname == "windows" && arch != "x86_64" && arch != "arm64") || (osname == "windows" && kind != "agent" && kind != "scan") {
		return "", nil, fmt.Errorf("unsupported platform")
	}
	ext := "tar.gz"
	if osname == "windows" {
		ext = "zip"
	}
	prefix := "netnoodle"
	assetArch := goarch
	binary := "nn-scan"
	if strings.HasPrefix(kind, "actor-") {
		binary = "nn-actor"
	}
	if kind == "agent" || kind == "agent-pull" {
		prefix = "nn-agent"
		binary = "nn-agent"
		if osname == "linux" {
			assetArch = arch
		}
	}
	if osname == "windows" {
		binary += ".exe"
	}
	return fmt.Sprintf("%s_%s_%s_%s.%s", prefix, tag, osname, assetArch, ext), []string{binary}, nil
}
func (s *Server) releaseHashes(ctx context.Context, tag string) (map[string]string, string, error) {
	s.onboard.mu.Lock()
	base := s.onboard.base + "/" + tag + "/"
	if h := s.onboard.hashes[tag]; h != nil {
		s.onboard.mu.Unlock()
		return h, base, nil
	}
	if s.onboard.fetching || time.Now().Before(s.onboard.failureUntil) {
		s.onboard.mu.Unlock()
		return nil, "", fmt.Errorf("checksums temporarily unavailable")
	}
	s.onboard.fetching = true
	client := s.onboard.client
	s.onboard.mu.Unlock()
	success := false
	defer func() {
		s.onboard.mu.Lock()
		s.onboard.fetching = false
		if !success {
			s.onboard.failureUntil = time.Now().Add(5 * time.Second)
		}
		s.onboard.mu.Unlock()
	}()
	req, err := http.NewRequestWithContext(ctx, "GET", base+"SHA256SUMS", nil)
	if err != nil {
		return nil, "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("checksums unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, "", fmt.Errorf("checksums too large")
	}
	hashes := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		sum, e := hex.DecodeString(f[0])
		name := strings.TrimPrefix(f[1], "*")
		if e != nil || len(sum) != 32 || strings.ContainsAny(name, "/\\") {
			return nil, "", fmt.Errorf("invalid checksum")
		}
		if _, ok := hashes[name]; ok {
			return nil, "", fmt.Errorf("duplicate checksum")
		}
		hashes[name] = strings.ToLower(f[0])
	}
	s.onboard.mu.Lock()
	s.onboard.hashes[tag] = hashes
	s.onboard.mu.Unlock()
	success = true
	return hashes, base, nil
}
func (s *Server) handleInstallManifest(w http.ResponseWriter, r *http.Request) {
	if !s.onboard.rate.allow(clientIP(r), s.now()) {
		writeErr(w, 429, "too many manifest requests")
		return
	}
	if len(r.URL.RawQuery) > 512 {
		writeErr(w, 400, "manifest query too large")
		return
	}
	q := r.URL.Query()
	tag, platform, kind := q.Get("version"), q.Get("platform"), q.Get("kind")
	if !releaseTag.MatchString(version.Version) || tag != version.Version {
		writeErr(w, 503, "release version unavailable")
		return
	}
	asset, files, err := releaseAsset(tag, platform, kind)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	hashes, base, err := s.releaseHashes(r.Context(), tag)
	if err != nil || hashes[asset] == "" {
		writeErr(w, 503, "release checksums unavailable")
		return
	}
	ext := "tar.gz"
	if strings.HasSuffix(asset, ".zip") {
		ext = "zip"
	}
	writeJSON(w, 200, installManifest{Version: tag, Artifacts: []installArtifact{{URL: base + asset, SHA256: hashes[asset], Kind: ext, Files: files}}})
}
