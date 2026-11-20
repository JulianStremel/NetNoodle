package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

// The repository publishes signed SHA256SUMS and platform tarballs. Direct
// binary mirrors may instead publish <binary>.bundle (Sigstore verify-blob).
func (u *Updater) downloadArchive(ctx context.Context, s *State) error {
	if e := u.download(ctx, s.ReleaseURL, s.Stage+".tar.gz"); e != nil {
		return e
	}
	if !u.Config.RequireSignature {
		return nil
	}
	base, e := url.Parse(s.ReleaseURL)
	if e != nil {
		return e
	}
	for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sigstore.json"} {
		remote := base.ResolveReference(&url.URL{Path: name}).String()
		if e = u.download(ctx, remote, s.Stage+"."+name); e != nil {
			return e
		}
	}
	return nil
}
func (u *Updater) verifyArchive(ctx context.Context, s *State) error {
	if u.Config.RequireSignature {
		args := append([]string{"verify-blob", "--bundle", s.Stage + ".SHA256SUMS.sigstore.json"}, u.signatureArgs()...)
		args = append(args, s.Stage+".SHA256SUMS")
		if _, e := u.Runner.Run(ctx, nil, u.Config.Cosign.Path, args...); e != nil {
			return e
		}
		b, e := os.ReadFile(s.Stage + ".SHA256SUMS")
		if e != nil {
			return e
		}
		if len(b) > MaxJSON {
			return fmt.Errorf("checksums too large")
		}
		parsed, e := url.Parse(s.ReleaseURL)
		if e != nil {
			return e
		}
		name := path.Base(parsed.Path)
		want := ""
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
				if want != "" {
					return fmt.Errorf("duplicate checksum")
				}
				want = fields[0]
			}
		}
		if len(want) != 64 {
			return fmt.Errorf("release checksum missing")
		}
		f, e := os.Open(s.Stage + ".tar.gz")
		if e != nil {
			return e
		}
		hash := sha256.New()
		_, e = io.Copy(hash, f)
		_ = f.Close()
		if e != nil {
			return e
		}
		if hex.EncodeToString(hash.Sum(nil)) != want {
			return fmt.Errorf("release checksum mismatch")
		}
	}
	f, e := os.Open(s.Stage + ".tar.gz")
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 512<<20))
	found := false
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if path.Base(h.Name) != "nn-server" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 128<<20 {
			return fmt.Errorf("invalid server binary in archive")
		}
		found = true
		out, e := os.OpenFile(s.Stage, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = io.Copy(out, tr)
		if e == nil {
			e = out.Sync()
		}
		closeErr := out.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !found {
		return fmt.Errorf("release has no nn-server binary")
	}
	return nil
}
func (u *Updater) fetchReleaseJSON(ctx context.Context, address string, v any) error {
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "nn-host-updater")
	res, e := u.Client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("release lookup HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, MaxJSON+1))
	if e != nil {
		return e
	}
	if len(b) > MaxJSON {
		return fmt.Errorf("release metadata too large")
	}
	return json.Unmarshal(b, v)
}
func (u *Updater) binaryTag(ctx context.Context, tag string) (string, error) {
	if release.MatchString(tag) {
		return tag, nil
	}
	p, e := url.Parse(u.Config.ReleaseURLTemplate)
	if e != nil {
		return "", e
	}
	parts := strings.Split(strings.Trim(p.Path, "/"), "/")
	if p.Host != "github.com" || len(parts) < 5 || parts[2] != "releases" || parts[3] != "download" {
		return tag, nil
	}
	api := "https://api.github.com/repos/" + parts[0] + "/" + parts[1]
	if tag == "latest" {
		var r struct {
			Tag string `json:"tag_name"`
		}
		if e = u.fetchReleaseJSON(ctx, api+"/releases/latest", &r); e != nil {
			return "", e
		}
		if !release.MatchString(r.Tag) {
			return "", fmt.Errorf("latest is not a release")
		}
		return r.Tag, nil
	}
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if e = u.fetchReleaseJSON(ctx, api+"/git/ref/heads/stable", &ref); e != nil {
		return "", e
	}
	var tags []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	// Promotion fast-forwards stable to the release commit. Refuse to guess a
	// release when no exact match exists in the bounded tag response.
	if e = u.fetchReleaseJSON(ctx, api+"/tags?per_page=100", &tags); e != nil {
		return "", e
	}
	best := ""
	for _, t := range tags {
		if ref.Object.SHA != "" && t.Commit.SHA == ref.Object.SHA && release.MatchString(t.Name) && (best == "" || Newer(t.Name, best)) {
			best = t.Name
		}
	}
	if best == "" {
		return "", fmt.Errorf("stable branch has no matching release tag")
	}
	return best, nil
}
