package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviders(t *testing.T) {
	for _, kind := range []string{"openai", "anthropic"} {
		t.Run(kind, func(t *testing.T) {
			const secret = "never-echo-api-key"
			mode := "ok"
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				path := "/v1/chat/completions"
				if kind == "anthropic" {
					path = "/v1/messages"
				}
				if r.Method != "POST" || r.URL.Path != path || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request %s %s", r.Method, r.URL)
				}
				if kind == "anthropic" {
					if r.Header.Get("x-api-key") != secret || r.Header.Get("anthropic-version") != "2023-06-01" || r.Header.Get("Authorization") != "" {
						t.Error("anthropic headers")
					}
				} else if r.Header.Get("Authorization") != "Bearer "+secret || r.Header.Get("x-api-key") != "" {
					t.Error("openai headers")
				}
				var body struct {
					Model     string                           `json:"model"`
					MaxTokens int                              `json:"max_tokens"`
					System    string                           `json:"system"`
					Messages  []struct{ Role, Content string } `json:"messages"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Model != "operator-model" || body.MaxTokens != 7 {
					t.Error("request body")
				}
				if kind == "anthropic" {
					if body.System != "system text" || len(body.Messages) != 1 {
						t.Error("anthropic system")
					}
				} else if len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[0].Content != "system text" {
					t.Error("openai system")
				}
				last := body.Messages[len(body.Messages)-1]
				if last.Role != "user" || last.Content != "user text" {
					t.Error("user message")
				}
				switch mode {
				case "error":
					w.WriteHeader(401)
					fmt.Fprint(w, secret)
				case "large":
					fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
				case "invalid":
					fmt.Fprint(w, secret)
				case "empty":
					fmt.Fprint(w, `{}`)
				case "timeout":
					<-r.Context().Done()
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/"+secret)
					w.WriteHeader(302)
				default:
					if kind == "anthropic" {
						fmt.Fprint(w, `{"content":[{"type":"text","text":"OK"}]}`)
					} else {
						fmt.Fprint(w, `{"choices":[{"message":{"content":"OK"}}]}`)
					}
				}
			}))
			defer srv.Close()
			for _, suffix := range []string{"", "/v1/"} {
				raw, _ := json.Marshal(Settings{BaseURL: srv.URL + suffix, Model: "operator-model", APIKey: secret, Timeout: "1s"})
				p, err := Registry.Build(kind, "instance", raw)
				if err != nil {
					t.Fatal(err)
				}
				if p.Name() != "instance" {
					t.Fatal(p.Name())
				}
				for _, m := range []string{"ok", "error", "large", "invalid", "empty", "redirect", "timeout"} {
					mode = m
					reply, err := p.Complete(t.Context(), Request{System: "system text", User: "user text", MaxTokens: 7, Timeout: 100 * time.Millisecond})
					if m == "ok" {
						if err != nil || reply.Text != "OK" {
							t.Fatal(reply, err)
						}
					} else if err == nil || strings.Contains(err.Error(), secret) {
						t.Fatalf("%s: %v", m, err)
					}
				}
			}
			if calls != 14 {
				t.Fatal(calls)
			}
		})
	}
}

func TestLocalWithoutKeyAndValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("local key header")
		}
		fmt.Fprint(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer srv.Close()
	p, err := New("openai", "local", json.RawMessage(`{"base_url":"`+srv.URL+`","model":"local-model"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Complete(context.Background(), Request{User: "Reply with OK"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"openai", "anthropic"} {
		for _, raw := range []string{`{}`, `{"model":"x","base_url":"http://remote.example"}`, `{"model":"x","base_url":"https://user:secret@host"}`, `{"model":"x","api_key":"secret","timeout":"bad-secret"}`, `{"model":"x","base_url":"https://host?secret"}`, `{"model":"x","api_key":"secret","extra":"secret"}`} {
			if _, err := New(kind, "bad", json.RawMessage(raw)); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("%s %s: %v", kind, raw, err)
			}
		}
		schema, _ := Registry.Schema(kind)
		for _, f := range schema.Fields {
			if f.Key == "model" && f.Default != nil {
				t.Fatal("default model")
			}
			if (f.Key == "send_device_names" || f.Key == "send_ip_addresses") && f.Default != false {
				t.Fatal("privacy default")
			}
		}
	}
	if _, err := New("anthropic", "missing-key", json.RawMessage(`{"model":"entered"}`)); err == nil {
		t.Fatal("missing anthropic key accepted")
	}
}
