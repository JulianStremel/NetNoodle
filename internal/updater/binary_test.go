package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestBinaryChannelResolution(t *testing.T) {
	u, _, _ := fixture(t)
	u.Config.ReleaseURLTemplate = "https://github.com/JulianStremel/netnoodle/releases/download/{version}/netnoodle_{version}_linux_amd64.tar.gz"
	u.Client = &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.Path {
		case "/repos/JulianStremel/netnoodle/releases/latest":
			body = `{"tag_name":"v1.4.0"}`
		case "/repos/JulianStremel/netnoodle/git/ref/heads/stable":
			body = `{"object":{"sha":"stable-commit"}}`
		case "/repos/JulianStremel/netnoodle/tags":
			body = `[{"name":"v1.4.0","commit":{"sha":"latest-commit"}},{"name":"v1.3.0","commit":{"sha":"stable-commit"}}]`
		default:
			t.Fatalf("unexpected release lookup %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	for _, tc := range []struct{ channel, want string }{{"latest", "v1.4.0"}, {"stable", "v1.3.0"}, {"v1.2.3", "v1.2.3"}} {
		got, e := u.binaryTag(context.Background(), tc.channel)
		if e != nil || got != tc.want {
			t.Fatal(got, e)
		}
	}
}

func TestSignedReleaseArchive(t *testing.T) {
	for _, tampered := range []bool{false, true} {
		t.Run(fmt.Sprint(tampered), func(t *testing.T) {
			u, r, req := fixture(t)
			req.Version = newVersion
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			data := []byte("signed nn-server executable")
			if e := tw.WriteHeader(&tar.Header{Name: "netnoodle_v1.3.0_linux_amd64/nn-server", Mode: 0755, Size: int64(len(data))}); e != nil {
				t.Fatal(e)
			}
			if _, e := tw.Write(data); e != nil {
				t.Fatal(e)
			}
			if e := tw.Close(); e != nil {
				t.Fatal(e)
			}
			if e := gz.Close(); e != nil {
				t.Fatal(e)
			}
			archive := buf.Bytes()
			sum := sha256.Sum256(archive)
			checksum := fmt.Sprintf("%x  netnoodle_v1.3.0_linux_amd64.tar.gz\n", sum)
			if tampered {
				checksum = strings.Repeat("0", 64) + "  netnoodle_v1.3.0_linux_amd64.tar.gz\n"
			}
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, ".tar.gz"):
					_, _ = w.Write(archive)
				case strings.HasSuffix(r.URL.Path, "SHA256SUMS"):
					fmt.Fprint(w, checksum)
				default:
					fmt.Fprint(w, "sigstore bundle")
				}
			}))
			defer ts.Close()
			u.Config.Mode = "binary"
			u.Client = ts.Client()
			u.Config.ReleaseURLTemplate = ts.URL + "/releases/{version}/netnoodle_{version}_linux_amd64.tar.gz"
			u.Runner = &binaryRunner{fake: r, version: newVersion}
			s := State{Status: Status{ID: req.ID}, Request: req}
			if e := u.resolve(context.Background(), &s); e != nil {
				t.Fatal(e)
			}
			e := u.verify(context.Background(), &s)
			if tampered {
				if e == nil || !strings.Contains(e.Error(), "checksum mismatch") {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(s.Stage)
			if e != nil || !bytes.Equal(b, data) {
				t.Fatal(e, string(b))
			}
			if !strings.Contains(strings.Join(r.calls, " "), "verify-blob --bundle") {
				t.Fatal(r.calls)
			}
		})
	}
}

func TestUntrustedArchiveNeverExtractsPaths(t *testing.T) {
	u, _, req := fixture(t)
	u.Config.RequireSignature = false
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if e := tw.WriteHeader(&tar.Header{Name: "../../nn-server", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); e != nil {
		t.Fatal(e)
	}
	_ = tw.Close()
	_ = gz.Close()
	s := State{Status: Status{ID: req.ID}, Stage: u.Config.SharedDir + "/state/staged", ReleaseURL: "https://example.com/release.tar.gz"}
	if e := os.WriteFile(s.Stage+".tar.gz", buf.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	if e := u.verifyArchive(context.Background(), &s); e == nil {
		t.Fatal("accepted symlink as executable")
	}
}
