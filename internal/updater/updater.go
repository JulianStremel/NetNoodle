package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Health struct {
	Version string `json:"version"`
	Schema  int    `json:"schema"`
	Status  string `json:"status"`
}
type State struct {
	Status
	Request    Request `json:"request"`
	Backup     string  `json:"backup"`
	Schema     int     `json:"schema"`
	Restore    bool    `json:"restore"`
	Stage      string  `json:"stage,omitempty"`
	Previous   string  `json:"previous,omitempty"`
	ReleaseURL string  `json:"release_url,omitempty"`
}
type Updater struct {
	Config Config
	Runner Runner
	Health func(context.Context) (Health, error)
	Client *http.Client // release download client; pinned health uses a separate client
	Now    func() time.Time
}

func New(c Config, r Runner) (*Updater, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if r == nil {
		r = ExecRunner{}
	}
	cl, e := tlspin.Client(c.HealthFingerprint, false, 5*time.Second)
	if e != nil {
		return nil, e
	}
	u := &Updater{Config: c, Runner: r, Now: time.Now, Client: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: tlspin.HTTPSRedirects}}
	u.Health = func(ctx context.Context) (Health, error) {
		var h Health
		req, e := http.NewRequestWithContext(ctx, "GET", c.HealthURL, nil)
		if e != nil {
			return h, e
		}
		res, e := cl.Do(req)
		if e != nil {
			return h, e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return h, fmt.Errorf("health HTTP %d", res.StatusCode)
		}
		e = json.NewDecoder(io.LimitReader(res.Body, MaxJSON)).Decode(&h)
		if e == nil && (h.Status != "ok" || h.Version == "" || len(h.Version) > 64 || h.Schema < 0) {
			e = fmt.Errorf("invalid health response")
		}
		return h, e
	}
	return u, nil
}
func (u *Updater) Init() error {
	for _, d := range []string{"requests", "status", "state"} {
		p, e := SafePath(u.Config.SharedDir, d)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(p, 0755); e != nil {
			return e
		}
		if d == "state" {
			if e = os.Chmod(p, 0700); e != nil {
				return e
			}
		}
	}
	return nil
}
func (u *Updater) compose(ctx context.Context, image string, args ...string) (string, error) {
	base := []string{"compose", "--file", u.Config.ComposeFile, "--project-name", u.Config.ComposeProject}
	env := []string{"NN_UPDATER_DIR=" + u.Config.SharedDir}
	if image != "" {
		env = append(env, "NN_SERVER_IMAGE="+image)
	}
	return u.Runner.Run(ctx, env, "docker", append(base, args...)...)
}
func (u *Updater) save(s *State) error {
	// Host state is private and never mounted as writable into the server.
	if e := WriteJSON(u.Config.SharedDir, s, "state", s.ID+".json"); e != nil {
		return e
	}
	p, _ := SafePath(u.Config.SharedDir, "state", s.ID+".json")
	if e := os.Chmod(p, 0600); e != nil {
		return e
	}
	return WriteJSON(u.Config.SharedDir, &s.Status, "status", s.ID+".json")
}
func (u *Updater) step(s *State, name string, err error) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	s.Steps = append(s.Steps, Step{Name: name, OK: err == nil, At: u.Now().UTC(), Message: msg})
	return u.save(s)
}
func (u *Updater) RunOnce(ctx context.Context) error {
	if e := u.Init(); e != nil {
		return e
	}
	entries, e := os.ReadDir(filepath.Join(u.Config.SharedDir, "requests"))
	if e != nil {
		return e
	}
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !ValidID(id) {
			// Report an invalid filename under a safe synthetic status ID.
			sum := sha256.Sum256([]byte(name))
			id = "rejected-" + hex.EncodeToString(sum[:12])
			s := State{Status: Status{ID: id, State: "rejected", Error: "invalid request filename"}}
			if e := u.step(&s, "validate", fmt.Errorf("invalid request filename")); e != nil {
				errs = append(errs, e)
				continue
			}
			if e := os.Remove(filepath.Join(u.Config.SharedDir, "requests", name)); e != nil {
				errs = append(errs, e)
			}
			continue
		}
		var s State
		e := ReadJSON(u.Config.SharedDir, &s, "state", name)
		if e == nil {
			if s.ID != id {
				return fmt.Errorf("state id mismatch")
			}
			if Terminal(s.State) {
				if e = u.save(&s); e == nil {
					e = os.Remove(filepath.Join(u.Config.SharedDir, "requests", name))
				}
				if e != nil {
					errs = append(errs, e)
				}
				continue
			}
		} else if !os.IsNotExist(e) {
			errs = append(errs, e)
			continue
		} else {
			var r Request
			e = ReadJSON(u.Config.SharedDir, &r, "requests", name)
			if e == nil {
				e = r.Validate()
			}
			if e == nil && r.ID != id {
				e = fmt.Errorf("request id differs from filename")
			}
			s = State{Status: Status{ID: id, Kind: r.Kind, State: "validate", RequestedBy: r.RequestedBy}, Request: r}
			if e != nil {
				s.State = "rejected"
				s.Error = e.Error()
				if e = u.step(&s, "validate", e); e != nil {
					errs = append(errs, e)
					continue
				}
			} else if r.RequestedAt.After(u.Now().Add(time.Minute)) {
				s.State = "rejected"
				s.Error = "future requests must be scheduled by the server"
				if e = u.step(&s, "validate", fmt.Errorf("future request refused")); e != nil {
					errs = append(errs, e)
					continue
				}
			} else if e = u.step(&s, "validate", nil); e != nil {
				errs = append(errs, e)
				continue
			}
		}
		if !Terminal(s.State) {
			e = u.process(ctx, &s)
			if e != nil {
				errs = append(errs, e)
			}
		}
		if Terminal(s.State) {
			if e = os.Remove(filepath.Join(u.Config.SharedDir, "requests", name)); e != nil && !os.IsNotExist(e) {
				errs = append(errs, e)
			}
		}
	}
	return errors.Join(errs...)
}
func (u *Updater) process(ctx context.Context, s *State) error {
	// Persisted swap intent is deliberately ambiguous: the external process may
	// have completed before the host lost power. Always recover conservatively.
	if s.State == "swap" || s.State == "health" || s.State == "rollback" {
		if s.Error == "" {
			s.Error = "interrupted update; recovering previous version"
		}
		s.Restore = true
		return u.recover(ctx, s)
	}
	if s.Request.Kind == "rollback" {
		return u.rollback(ctx, s)
	}
	for _, name := range []string{"resolve", "verify", "downgrade", "backup", "swap", "health"} {
		if hasStep(s, name) {
			continue
		}
		s.State = name
		if e := u.save(s); e != nil {
			return e
		}
		var e error
		switch name {
		case "resolve":
			e = u.resolve(ctx, s)
		case "verify":
			e = u.verify(ctx, s)
		case "downgrade":
			var h Health
			h, e = u.Health(ctx)
			if e == nil {
				s.FromVersion = h.Version
				s.Schema = h.Schema
				cmp, ok := Compare(s.ToVersion, s.FromVersion)
				if !ok || cmp < 0 {
					e = fmt.Errorf("downgrade or unknown version refused: %s to %s", s.FromVersion, s.ToVersion)
				}
			}
		case "backup":
			e = u.backup(ctx, s)
		case "swap":
			s.Restore = true
			if e = u.save(s); e == nil {
				e = u.swap(ctx, s, s.ToDigest)
			}
		case "health":
			e = u.healthy(ctx, s, s.ToVersion)
		}
		if se := u.step(s, name, e); se != nil {
			return se
		}
		if e != nil {
			s.Error = e.Error()
			if name == "swap" || name == "health" {
				// If swap failed while the old service is demonstrably still
				// healthy, restoring would unnecessarily discard new writes.
				if name == "swap" {
					if h, he := u.Health(ctx); he == nil && h.Version == s.FromVersion && h.Schema == s.Schema {
						s.Restore = false
					}
				}
				return u.recover(ctx, s)
			}
			s.State = "failed"
			s.FinishedAt = u.Now().UTC()
			return errors.Join(e, u.save(s))
		}
	}
	s.State = "done"
	s.FinishedAt = u.Now().UTC()
	s.KeepUntil = s.FinishedAt.Add(time.Duration(u.Config.KeepDays) * 24 * time.Hour)
	return u.save(s)
}
func hasStep(s *State, name string) bool {
	for _, v := range s.Steps {
		if v.Name == name && v.OK {
			return true
		}
	}
	return false
}
func (u *Updater) resolve(ctx context.Context, s *State) error {
	tag := s.Request.Version
	if tag == "" {
		tag = s.Request.Channel
	}
	if tag == "" {
		tag = u.Config.Channel
	}
	if u.Config.Mode == "binary" {
		return u.resolveBinary(ctx, s, tag)
	}
	ref := u.Config.ImageRepo + ":" + tag
	if _, e := u.Runner.Run(ctx, nil, "docker", "pull", ref); e != nil {
		return e
	}
	out, e := u.Runner.Run(ctx, nil, "docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", ref)
	if e != nil {
		return e
	}
	s.ToDigest = strings.TrimSpace(out)
	if !u.validDigest(s.ToDigest) {
		s.ToDigest = ""
		return fmt.Errorf("resolved digest is outside configured repository")
	}
	out, e = u.Runner.Run(ctx, nil, "docker", "image", "inspect", "--format", `{{index .Config.Labels "org.opencontainers.image.version"}}`, s.ToDigest)
	if e != nil {
		return e
	}
	s.ToVersion = "v" + strings.TrimPrefix(strings.TrimSpace(out), "v")
	if !release.MatchString(s.ToVersion) || s.Request.Version != "" && s.ToVersion != s.Request.Version {
		s.ToVersion = ""
		return fmt.Errorf("image version label does not match release")
	}
	return nil
}
func (u *Updater) validDigest(d string) bool {
	return strings.HasPrefix(d, u.Config.ImageRepo+"@sha256:") && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(strings.TrimPrefix(d, u.Config.ImageRepo+"@sha256:"))
}
func (u *Updater) signatureArgs() []string {
	if u.Config.Cosign.Key != "" {
		return []string{"--key", u.Config.Cosign.Key}
	}
	return []string{"--certificate-identity-regexp", u.Config.Cosign.Identity, "--certificate-oidc-issuer", u.Config.Cosign.Issuer}
}
func (u *Updater) verify(ctx context.Context, s *State) error {
	if u.Config.Mode == "binary" {
		return u.verifyBinary(ctx, s)
	}
	if !u.Config.RequireSignature {
		return nil
	}
	_, e := u.Runner.Run(ctx, nil, u.Config.Cosign.Path, append(append([]string{"verify"}, u.signatureArgs()...), s.ToDigest)...)
	return e
}
func (u *Updater) backup(ctx context.Context, s *State) error {
	var out string
	var e error
	if u.Config.Mode == "compose" {
		out, e = u.compose(ctx, "", "ps", "-q", u.Config.Service)
		if e != nil {
			return e
		}
		container := strings.TrimSpace(out)
		if container == "" || strings.ContainsAny(container, "\r\n") {
			return fmt.Errorf("expected one running container")
		}
		out, e = u.Runner.Run(ctx, nil, "docker", "inspect", "--format", "{{.Image}}", container)
		if e != nil {
			return e
		}
		out, e = u.Runner.Run(ctx, nil, "docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", strings.TrimSpace(out))
		if e != nil {
			return e
		}
		s.FromDigest = strings.TrimSpace(out)
		if !u.validDigest(s.FromDigest) {
			s.FromDigest = ""
			return fmt.Errorf("running image is not a pinned release in configured repository")
		}
		out, e = u.compose(ctx, "", "exec", "-T", u.Config.Service, "nn-server", "backup", "--config", "/etc/netnoodle/netnoodle.json", "--json")
	} else {
		out, e = u.Runner.Run(ctx, nil, u.Config.BinaryPath, "backup", "--config", "/etc/netnoodle/netnoodle.json", "--json")
	}
	if e != nil {
		return e
	}
	var result struct {
		Path string `json:"path"`
	}
	if e = Decode([]byte(out), &result); e != nil {
		return e
	}
	if len(result.Path) > 4096 || !filepath.IsAbs(result.Path) {
		return fmt.Errorf("backup returned non-absolute path")
	}
	s.Backup = result.Path
	if u.Config.Mode == "binary" {
		s.Previous = u.Config.BinaryPath + "." + s.ID + ".prev"
		if e = copyFile(u.Config.BinaryPath, s.Previous, 0755); e != nil {
			return e
		}
		s.FromDigest = s.Previous
	}
	return nil
}
func (u *Updater) swap(ctx context.Context, s *State, image string) error {
	if u.Config.Mode == "binary" {
		if e := copyFile(s.Stage, u.Config.BinaryPath+".next", 0755); e != nil {
			return e
		}
		if e := os.Rename(u.Config.BinaryPath+".next", u.Config.BinaryPath); e != nil {
			return e
		}
		if e := syncDir(filepath.Dir(u.Config.BinaryPath)); e != nil {
			return e
		}
		_, e := u.Runner.Run(ctx, nil, "systemctl", "restart", u.Config.ServiceUnit)
		return e
	}
	if !u.validDigest(image) {
		return fmt.Errorf("unsafe image in host state")
	}
	_, e := u.compose(ctx, image, "up", "-d", "--no-deps", "--no-build", "--pull", "never", u.Config.Service)
	return e
}
func (u *Updater) healthy(ctx context.Context, s *State, want string) error {
	d, _ := time.ParseDuration(u.Config.HealthTimeout)
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var last error
	for {
		h, e := u.Health(ctx)
		if e == nil {
			if h.Schema > s.Schema {
				s.Restore = true
			}
			if h.Version == want {
				s.Restore = h.Schema > s.Schema
				return nil
			}
			last = fmt.Errorf("health version %s, expected %s", h.Version, want)
		} else {
			last = e
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("health timeout: %v", last)
		case <-time.After(time.Second):
		}
	}
}
func (u *Updater) recover(ctx context.Context, s *State) error {
	s.State = "rollback"
	if e := u.save(s); e != nil {
		return e
	}
	// Stop before restoring: no process may write the database during restore.
	var e error
	if u.Config.Mode == "compose" {
		if !u.validDigest(s.FromDigest) || s.Backup == "" {
			return fmt.Errorf("missing recovery image or backup")
		}
		if s.Restore {
			_, e = u.compose(ctx, s.FromDigest, "stop", u.Config.Service)
			if e == nil {
				_, e = u.compose(ctx, s.FromDigest, "run", "--rm", "--no-deps", "--pull", "never", u.Config.Service, "restore", "--config", "/etc/netnoodle/netnoodle.json", "--file", s.Backup)
			}
		}
		if e == nil {
			_, e = u.compose(ctx, s.FromDigest, "up", "-d", "--no-deps", "--no-build", "--pull", "never", u.Config.Service)
		}
	} else {
		if s.Previous == "" || s.Backup == "" {
			return fmt.Errorf("missing recovery binary or backup")
		}
		_, e = u.Runner.Run(ctx, nil, "systemctl", "stop", u.Config.ServiceUnit)
		if e == nil && s.Restore {
			_, e = u.Runner.Run(ctx, nil, s.Previous, "restore", "--config", "/etc/netnoodle/netnoodle.json", "--file", s.Backup)
		}
		if e == nil {
			e = copyFile(s.Previous, u.Config.BinaryPath+".next", 0755)
		}
		if e == nil {
			e = os.Rename(u.Config.BinaryPath+".next", u.Config.BinaryPath)
		}
		if e == nil {
			e = syncDir(filepath.Dir(u.Config.BinaryPath))
		}
		if e == nil {
			_, e = u.Runner.Run(ctx, nil, "systemctl", "start", u.Config.ServiceUnit)
		}
	}
	if e == nil {
		e = u.healthy(ctx, s, s.FromVersion)
	}
	if se := u.step(s, "rollback", e); se != nil {
		return se
	}
	if e != nil {
		return e
	}
	if s.Request.Kind == "rollback" {
		s.State = "done"
		s.Error = ""
		s.FromVersion, s.ToVersion = s.ToVersion, s.FromVersion
		s.FromDigest, s.ToDigest = s.ToDigest, s.FromDigest
	} else {
		s.State = "rolled-back"
	}
	s.FinishedAt = u.Now().UTC()
	return u.save(s)
}
func (u *Updater) rollback(ctx context.Context, s *State) error {
	var target State
	e := ReadJSON(u.Config.SharedDir, &target, "state", s.Request.To+".json")
	if e == nil && (target.ID != s.Request.To || target.State != "done" || target.Kind == "rollback" || !target.KeepUntil.After(u.Now())) {
		e = fmt.Errorf("rollback target is not retained")
	}
	if e == nil {
		var h Health
		h, e = u.Health(ctx)
		if e == nil && h.Version != target.ToVersion {
			e = fmt.Errorf("rollback target is not current")
		}
	}
	if e != nil {
		s.State = "rejected"
		s.Error = e.Error()
		return u.step(s, "rollback", e)
	}
	s.FromVersion = target.FromVersion
	s.ToVersion = target.ToVersion
	s.FromDigest = target.FromDigest
	s.ToDigest = target.ToDigest
	s.Previous = target.Previous
	s.Backup = target.Backup
	s.Schema = target.Schema
	s.Restore = true
	return u.recover(ctx, s)
}
func (u *Updater) Check(ctx context.Context) error {
	if e := u.Init(); e != nil {
		return e
	}
	s := State{Status: Status{ID: "check-release"}, Request: Request{Channel: u.Config.Channel}}
	if e := u.resolve(ctx, &s); e != nil {
		return e
	}
	if e := u.verify(ctx, &s); e != nil {
		return e
	}
	a := Available{Version: s.ToVersion, Digest: s.ToDigest, Channel: u.Config.Channel, CheckedAt: u.Now().UTC(), KeepDays: u.Config.KeepDays}
	// For GitHub-hosted images this is a release page on the configured project.
	if strings.HasPrefix(u.Config.ImageRepo, "ghcr.io/") {
		project := strings.TrimSuffix(strings.TrimPrefix(u.Config.ImageRepo, "ghcr.io/"), "-server")
		a.NotesURL = "https://github.com/" + project + "/releases/tag/" + s.ToVersion
	}
	if strings.HasPrefix(s.ReleaseURL, "https://github.com/") {
		parts := strings.Split(strings.TrimPrefix(s.ReleaseURL, "https://github.com/"), "/")
		if len(parts) >= 2 {
			a.NotesURL = "https://github.com/" + parts[0] + "/" + parts[1] + "/releases/tag/" + s.ToVersion
		}
	}
	return WriteJSON(u.Config.SharedDir, a, "status", "available.json")
}

func copyFile(src, dst string, mode os.FileMode) error {
	f, e := os.Open(src)
	if e != nil {
		return e
	}
	defer f.Close()
	o, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(o, f)
	if e == nil {
		e = o.Sync()
	}
	if e = errors.Join(e, o.Close()); e != nil {
		return e
	}
	return syncDir(filepath.Dir(dst))
}
func (u *Updater) download(ctx context.Context, url, path string) error {
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return e
	}
	res, e := u.Client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", res.StatusCode)
	}
	if res.ContentLength > 256<<20 {
		return fmt.Errorf("download too large")
	}
	if res.ContentLength > 0 {
		free, e := freeSpace(filepath.Dir(path))
		if e != nil {
			return e
		}
		if uint64(res.ContentLength) > free/3 {
			return fmt.Errorf("insufficient space for download and staging")
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(res.Body, (256<<20)+1))
	if n > 256<<20 {
		e = fmt.Errorf("download too large")
	}
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func (u *Updater) resolveBinary(ctx context.Context, s *State, tag string) error {
	s.Stage = filepath.Join(u.Config.SharedDir, "state", s.ID+".bin")
	var e error
	tag, e = u.binaryTag(ctx, tag)
	if e != nil {
		return e
	}
	url := strings.ReplaceAll(u.Config.ReleaseURLTemplate, "{version}", tag)
	s.ReleaseURL = url
	if strings.HasSuffix(url, ".tar.gz") {
		return u.downloadArchive(ctx, s)
	}
	if e := u.download(ctx, url, s.Stage); e != nil {
		return e
	}
	if u.Config.RequireSignature {
		if e := u.download(ctx, url+".bundle", s.Stage+".bundle"); e != nil {
			return e
		}
	}
	return nil
}
func (u *Updater) verifyBinary(ctx context.Context, s *State) error {
	archive := strings.HasSuffix(s.ReleaseURL, ".tar.gz")
	if archive {
		if e := u.verifyArchive(ctx, s); e != nil {
			return e
		}
	} else if u.Config.RequireSignature {
		args := append([]string{"verify-blob", "--bundle", s.Stage + ".bundle"}, u.signatureArgs()...)
		args = append(args, s.Stage)
		if _, e := u.Runner.Run(ctx, nil, u.Config.Cosign.Path, args...); e != nil {
			return e
		}
	}
	if e := os.Chmod(s.Stage, 0755); e != nil {
		return e
	}
	out, e := u.Runner.Run(ctx, nil, s.Stage, "version")
	if e != nil {
		return e
	}
	fields := strings.Fields(out)
	if len(fields) < 1 || !release.MatchString(fields[0]) {
		return fmt.Errorf("invalid binary version")
	}
	s.ToVersion = fields[0]
	if s.Request.Version != "" && s.Request.Version != s.ToVersion {
		return fmt.Errorf("binary version mismatch")
	}
	f, e := os.Open(s.Stage)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	s.ToDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return nil
}
