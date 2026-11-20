// Package updater implements the host-owned update protocol. Requests are
// untrusted; only host configuration and host-owned state select executables.
package updater

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxJSON = 256 << 10

var identifier = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
var release = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func ValidID(id string) bool { return identifier.MatchString(id) }

type Request struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind,omitempty"`
	Channel     string    `json:"channel"`
	Version     string    `json:"version,omitempty"`
	To          string    `json:"to,omitempty"` // rollback target request ID, never an image or path
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

func (r Request) Validate() error {
	if !ValidID(r.ID) || (r.Channel != "stable" && r.Channel != "latest") || (r.Kind != "" && r.Kind != "update" && r.Kind != "rollback") {
		return fmt.Errorf("invalid request id, channel or kind")
	}
	if r.Version != "" && !release.MatchString(r.Version) {
		return fmt.Errorf("version must be exact vX.Y.Z")
	}
	if r.RequestedAt.IsZero() || len(r.RequestedBy) == 0 || len(r.RequestedBy) > 128 {
		return fmt.Errorf("invalid requester or timestamp")
	}
	if r.Kind == "rollback" {
		if !ValidID(r.To) || r.Version != "" {
			return fmt.Errorf("rollback requires a target id")
		}
	} else if r.To != "" {
		return fmt.Errorf("unexpected rollback target")
	}
	return nil
}

type Step struct {
	Name    string    `json:"name"`
	OK      bool      `json:"ok"`
	At      time.Time `json:"at"`
	Message string    `json:"message"`
}
type Status struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind,omitempty"`
	State       string    `json:"state"`
	Steps       []Step    `json:"steps"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	FromDigest  string    `json:"from_digest"`
	ToDigest    string    `json:"to_digest"`
	Error       string    `json:"error,omitempty"`
	RequestedBy string    `json:"requested_by,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	KeepUntil   time.Time `json:"keep_until,omitempty"`
}

func Terminal(s string) bool {
	return s == "done" || s == "failed" || s == "rejected" || s == "rolled-back"
}

type Available struct {
	Version   string    `json:"version"`
	Digest    string    `json:"digest"`
	Channel   string    `json:"channel"`
	NotesURL  string    `json:"notes_url,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	KeepDays  int       `json:"keep_days"`
}

// Newer only accepts complete release versions. Unknown/dev versions fail closed.
func Newer(a, b string) bool { c, ok := Compare(a, b); return ok && c > 0 }
func Compare(a, b string) (int, bool) {
	aa, bb := release.FindStringSubmatch(a), release.FindStringSubmatch(b)
	if aa == nil || bb == nil {
		return 0, false
	}
	for i := 1; i < 4; i++ {
		x, e := strconv.ParseUint(aa[i], 10, 64)
		y, f := strconv.ParseUint(bb[i], 10, 64)
		if e != nil || f != nil {
			return 0, false
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}
func Decode(b []byte, v any) error {
	if len(b) > MaxJSON {
		return fmt.Errorf("JSON too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

// SafePath refuses symlinks in every existing component, including the root.
// The installation must make status/state and their parents host-owned.
func SafePath(root string, parts ...string) (string, error) {
	p, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `/\`) {
			return "", fmt.Errorf("unsafe path component")
		}
		p = filepath.Join(p, part)
	}
	for q := p; ; q = filepath.Dir(q) {
		i, e := os.Lstat(q)
		if e == nil && i.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink refused: %s", q)
		}
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return p, nil
}
func ReadJSON(root string, v any, parts ...string) error {
	p, e := SafePath(root, parts...)
	if e != nil {
		return e
	}
	f, e := openJSON(p)
	if e != nil {
		return e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || i.Size() > MaxJSON {
		return fmt.Errorf("invalid JSON file")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxJSON+1))
	if e != nil {
		return e
	}
	return Decode(b, v)
}
func WriteJSON(root string, v any, parts ...string) error {
	p, e := SafePath(root, parts...)
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if len(b) > MaxJSON {
		return fmt.Errorf("JSON too large")
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".pending-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0644); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), p); e != nil {
		return e
	}
	return syncDir(filepath.Dir(p))
}
