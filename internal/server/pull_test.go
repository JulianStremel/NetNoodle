package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/pull"
	pullhttps "github.com/JulianStremel/netnoodle/internal/pull/https"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// fakeAgent implements the agent side of docs/design/pull-mode.md.
type fakeAgent struct {
	srv     *httptest.Server
	fp      string
	code    atomic.Value // string
	reports atomic.Int32
	body    string
}

func newFakeAgent(t *testing.T, serverFP string, body string) *fakeAgent {
	a := &fakeAgent{body: body}
	a.code.Store("")
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pair":
			code := a.code.Load().(string)
			if code == "" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"version":"v1","proof":"` + pull.Proof(code, a.fp, serverFP) + `"}`))
		case "/v1/report":
			a.reports.Add(1)
			w.Write([]byte(a.body))
		default:
			http.NotFound(w, r)
		}
	}))
	a.srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != serverFP {
				return errors.New("not the pinned server")
			}
			return nil
		},
	}
	// Each fake agent has its own certificate (httptest shares one).
	cert, _, err := LoadOrCreateCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.srv.TLS.Certificates = []tls.Certificate{cert}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	sum := sha256.Sum256(cert.Certificate[0])
	a.fp = hex.EncodeToString(sum[:])
	return a
}

func (a *fakeAgent) addr() string { return strings.TrimPrefix(a.srv.URL, "https://") }

func TestPullPairAndReport(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	cert, fp, err := LoadOrCreatePullCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetPull(map[string]pull.Transport{"https": pullhttps.New(cert, fp)}, fp)

	agent := newFakeAgent(t, fp, `{"version":"v1","source":"liar","observed_at":"2026-11-20T10:00:00Z",
		"entities":[{"kind":"host","name":"rproxy","identifiers":[{"kind":"agent","value":"db01","strength":"strong"}],
		"components":[{"purl":"pkg:deb/debian/nginx@1.22.1-9","name":"nginx","version":"1.22.1-9"}]}]}`)

	var info struct {
		Peer    struct{ ID int64 }
		Code    string
		Command string
	}
	if code := doJSON(t, c, "POST", ts.URL+"/api/pull-peers", "", `{"name":"rproxy","address":"`+agent.addr()+`","interval":"1h"}`, &info); code != 200 {
		t.Fatalf("create = %d", code)
	}
	if len(info.Code) != 32 || !strings.Contains(info.Command, "--server-fingerprint "+fp) || !strings.HasPrefix(info.Command, "NN_PAIR_CODE=") {
		t.Fatalf("pair info = %+v", info)
	}
	ctx := context.Background()
	pullNow := func() {
		t.Helper()
		if code := doJSON(t, c, "POST", ts.URL+"/api/pull-peers/"+itoa(info.Peer.ID)+"/pull", "", ``, nil); code != 200 {
			t.Fatalf("pull now = %d", code)
		}
		p, _ := s.st.GetPullPeer(ctx, info.Peer.ID)
		s.pullOne(ctx, p)
	}

	// 1. Wrong code on the agent: no pairing.
	agent.code.Store("WRONGWRONGWRONGWRONGWRONGWRONG22")
	pullNow()
	p, _ := s.st.GetPullPeer(ctx, info.Peer.ID)
	if p.Pin != "" || !strings.Contains(p.LastError, "proof") {
		t.Fatalf("paired with wrong code: %+v", p)
	}

	// 2. Right code: paired and pulled.
	agent.code.Store(info.Code)
	pullNow()
	p, _ = s.st.GetPullPeer(ctx, info.Peer.ID)
	if p.Pin != agent.fp || p.PairCode != "" || p.LastError != "" || p.LastPull.IsZero() {
		t.Fatalf("after pairing: %+v", p)
	}
	if p.NextPull.Before(time.Now().Add(50 * time.Minute)) {
		t.Fatalf("next pull too early: %v", p.NextPull)
	}
	ds := devices(t, c, ts.URL)
	if len(ds) != 1 || ds[0].Name != "rproxy" {
		t.Fatalf("devices = %+v", ds)
	}
	for _, id := range ds[0].Identifiers {
		if id.Kind == "agent" && id.Value != "rproxy" {
			t.Fatalf("agent rules not applied to pulled report: %+v", ds[0].Identifiers)
		}
	}

	// 3. Another host on the same address (new certificate): refused by the pin.
	agent.srv.Close()
	other := newFakeAgent(t, fp, agent.body)
	if err := s.st.SetPullResult(ctx, p.ID, false, time.Now(), time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	s.pullOne(ctx, store1(t, s, p.ID, other.addr()))
	p, _ = s.st.GetPullPeer(ctx, info.Peer.ID)
	if other.reports.Load() != 0 || !strings.Contains(p.LastError, "does not match the pinned") {
		t.Fatalf("pulled from unpinned host: reports=%d err=%q", other.reports.Load(), p.LastError)
	}

	// 4. Disabled pull peers are not due.
	doJSON(t, c, "POST", ts.URL+"/api/peers/"+itoa(p.ID)+"/disable", "", ``, nil)
	if due, _ := s.st.DuePullPeers(ctx, time.Now().Add(48*time.Hour)); len(due) != 0 {
		t.Fatalf("disabled peer is due: %+v", due)
	}

	// 5. A pull peer has no usable token: it cannot push.
	if code := doJSON(t, c, "POST", ts.URL+"/v1/observations", "", agent.body, nil); code != http.StatusUnauthorized {
		t.Fatalf("push without token = %d", code)
	}
}

// store1 returns the peer with a changed address (test only).
func store1(t *testing.T, s *Server, id int64, addr string) (p store.PullPeer) {
	t.Helper()
	got, err := s.st.GetPullPeer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	got.Address = addr
	return got
}

func TestPullPeerValidation(t *testing.T) {
	ts, c, pw := newTestServer(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	for _, body := range []string{
		`{"name":"x","address":"https://x:1"}`,
		`{"name":"x","address":"x"}`,
		`{"name":"bad name","address":"x:1"}`,
		`{"name":"x","address":"x:1","interval":"10s"}`,
	} {
		if code := doJSON(t, c, "POST", ts.URL+"/api/pull-peers", "", body, nil); code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d", body, code)
		}
	}
	doJSON(t, c, "POST", ts.URL+"/api/pull-peers", "", `{"name":"x","address":"x:1"}`, nil)
	if code := doJSON(t, c, "POST", ts.URL+"/api/pull-peers", "", `{"name":"x","address":"x:1"}`, nil); code != http.StatusConflict {
		t.Errorf("duplicate = %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
