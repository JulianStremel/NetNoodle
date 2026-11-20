package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

func tlsFingerprint(ts *httptest.Server) string {
	h := sha256.Sum256(ts.Certificate().Raw)
	return hex.EncodeToString(h[:])
}
func TestCommandRunDryRunDenyAndReplay(t *testing.T) {
	for _, test := range []string{"dry run", "deny", "replay"} {
		t.Run(test, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			env, e := orders.Sign(key, proto.Order{Version: proto.Version, ID: "order-1", Actor: "actor", Action: "isolate", Nonce: "one", NotAfter: time.Now().UTC().Add(time.Minute), Targets: []proto.Identifier{{Kind: "mac", Value: "aa:bb:cc:dd:ee:ff", Strength: proto.Strong}}})
			if e != nil {
				t.Fatal(e)
			}
			results := make(chan proto.OrderResult, 2)
			polls := 0
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer secret" {
					w.WriteHeader(401)
					return
				}
				switch r.URL.Path {
				case "/v1/actor/hello":
					var h proto.ActorHello
					if e := json.NewDecoder(r.Body).Decode(&h); e != nil || len(h.Capabilities) != 7 {
						t.Errorf("hello %+v %v", h, e)
					}
					_, _ = w.Write([]byte("{}"))
				case "/v1/orders":
					polls++
					if polls == 1 || (test == "replay" && polls == 2) {
						_ = json.NewEncoder(w).Encode([]orders.Envelope{env})
					} else {
						<-r.Context().Done()
					}
				case "/v1/orders/result":
					var res proto.OrderResult
					if e := json.NewDecoder(r.Body).Decode(&res); e != nil {
						t.Error(e)
					}
					results <- res
					_, _ = w.Write([]byte("{}"))
				default:
					w.WriteHeader(404)
				}
			}))
			defer ts.Close()
			dir := t.TempDir()
			credsPath := filepath.Join(dir, "creds.json")
			if e = client.SaveCredentials(credsPath, client.Credentials{Server: ts.URL, Fingerprint: tlsFingerprint(ts), Name: "actor", Role: "actor", Token: "secret", OrderKey: orders.PublicKey(key)}); e != nil {
				t.Fatal(e)
			}
			cfg := actor.Config{Credentials: credsPath, NonceFile: filepath.Join(dir, "nonces.json"), Backends: []registry.Spec{{Type: "log"}}}
			if test != "deny" {
				cfg.Allow = []actor.AllowRule{{Action: "isolate", Targets: []string{"mac=aa:*"}}, {Action: "unisolate", Targets: []string{"mac=aa:*"}}}
			}
			b, _ := json.Marshal(cfg)
			configPath := filepath.Join(dir, "actor.json")
			if e = os.WriteFile(configPath, b, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- command(ctx, []string{"run", "-config", configPath}) }()
			count := 1
			if test == "replay" {
				count = 2
			}
			for i := 0; i < count; i++ {
				select {
				case res := <-results:
					if test == "deny" {
						if res.Status != proto.OrderRejected || !strings.Contains(res.Message, "allow list") {
							t.Fatal(res)
						}
					} else if i == 1 {
						if res.Status != proto.OrderRejected || !strings.Contains(res.Message, "replay") {
							t.Fatal(res)
						}
					} else if res.Status != proto.OrderDone || !strings.HasPrefix(res.Message, "dry run: would isolate") {
						t.Fatal(res)
					}
				case <-time.After(30 * time.Second): // generous: CI runners can be slow
					t.Fatal("actor did not post result")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("run did not stop")
			}
		})
	}
}
func TestEnrollPinsOrderKey(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub := orders.PublicKey(key)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["join_token"] != "join" {
			t.Error("join token")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "actor", "role": "actor", "token": "peer", "order_key": pub})
	}))
	defer ts.Close()
	t.Setenv("NN_JOIN_TOKEN", "join")
	out := filepath.Join(t.TempDir(), "creds.json")
	args := []string{"enroll", "-server", ts.URL, "-fingerprint", tlsFingerprint(ts), "-name", "actor", "-creds", out}
	if e := command(context.Background(), append(args, "-order-key", base64.StdEncoding.EncodeToString(make([]byte, 32)))); e == nil {
		t.Fatal("mismatched key accepted")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("credentials saved on mismatch")
	}
	if e := command(context.Background(), append(args, "-order-key", pub)); e != nil {
		t.Fatal(e)
	}
	c, e := client.LoadCredentials(out)
	if e != nil || c.OrderKey != pub {
		t.Fatal(c, e)
	}
}
