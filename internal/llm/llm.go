// Package llm provides advisory text completion. It has no decision or action hooks.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

type Provider interface {
	Name() string
	Complete(context.Context, Request) (Response, error)
}

type Request struct {
	System    string
	User      string
	MaxTokens int
	Timeout   time.Duration
}

type Response struct{ Text string }

var Registry = registry.New[Provider]("llm")

// The privacy switches are saved for the future M7 advisor. Complete only sends
// the text explicitly supplied by its caller.
type Settings struct {
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	APIKey          string `json:"api_key"`
	Timeout         string `json:"timeout"`
	SendDeviceNames bool   `json:"send_device_names"`
	SendIPAddresses bool   `json:"send_ip_addresses"`
}

type provider struct {
	name, kind string
	settings   Settings
	timeout    time.Duration
	client     *http.Client
	endpoint   string
}

func init() {
	for _, kind := range []string{"openai", "anthropic"} {
		Registry.RegisterWithSchema(kind, func(name string, raw json.RawMessage) (Provider, error) { return New(kind, name, raw) }, schema(kind))
	}
}

func schema(kind string) registry.Schema {
	base := "https://api.openai.com"
	if kind == "anthropic" {
		base = "https://api.anthropic.com"
	}
	return registry.Schema{Fields: []registry.Field{
		{Key: "base_url", Label: "API base URL", Type: "url", Default: base, Help: "Server root or URL ending in /v1. Local OpenAI-compatible servers are supported."},
		{Key: "model", Label: "Model", Type: "string", Required: true, Help: "Enter the model name provided by your server."},
		{Key: "api_key", Label: "API key", Type: "secret", Required: kind == "anthropic", Help: "Optional for local OpenAI-compatible servers."},
		{Key: "timeout", Label: "Timeout", Type: "duration", Default: "30s"},
		{Key: "send_device_names", Label: "Send device names", Type: "bool", Default: false, Help: "Saved for the future M7 advisor; not used yet."},
		{Key: "send_ip_addresses", Label: "Send IP addresses", Type: "bool", Default: false, Help: "Saved for the future M7 advisor; not used yet."},
	}}
}

// New validates settings without making a network request. Errors never include
// the URL, key, prompt, response body or server status text.
func New(kind, name string, raw json.RawMessage) (Provider, error) {
	if kind != "openai" && kind != "anthropic" {
		return nil, errors.New("llm: unknown provider")
	}
	base := "https://api.openai.com"
	if kind == "anthropic" {
		base = "https://api.anthropic.com"
	}
	s := Settings{BaseURL: base, Timeout: "30s"}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil {
		return nil, errors.New("llm: invalid settings")
	}
	if tlspin.CheckURL(s.BaseURL, false) != nil {
		return nil, errors.New("llm: HTTPS required except loopback")
	}
	u, err := url.Parse(s.BaseURL)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("llm: invalid base URL")
	}
	if strings.TrimSpace(s.Model) == "" {
		return nil, errors.New("llm: model required")
	}
	if kind == "anthropic" && strings.TrimSpace(s.APIKey) == "" {
		return nil, errors.New("llm: API key required")
	}
	timeout, err := time.ParseDuration(s.Timeout)
	if err != nil || timeout <= 0 {
		return nil, errors.New("llm: invalid timeout")
	}
	endpoint := strings.TrimRight(s.BaseURL, "/")
	if !strings.HasSuffix(endpoint, "/v1") {
		endpoint += "/v1"
	}
	if kind == "anthropic" {
		endpoint += "/messages"
	} else {
		endpoint += "/chat/completions"
	}
	return &provider{name: name, kind: kind, settings: s, timeout: timeout, endpoint: endpoint, client: &http.Client{CheckRedirect: tlspin.NoRedirects}}, nil
}

func (p *provider) Name() string { return p.name }
func (p *provider) Complete(ctx context.Context, r Request) (Response, error) {
	timeout := p.timeout
	if r.Timeout > 0 && r.Timeout < timeout {
		timeout = r.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maxTokens := r.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 64
	}
	messages := []map[string]string{}
	body := map[string]any{"model": p.settings.Model, "max_tokens": maxTokens}
	if p.kind == "anthropic" {
		if r.System != "" {
			body["system"] = r.System
		}
	} else if r.System != "" {
		messages = append(messages, map[string]string{"role": "system", "content": r.System})
	}
	messages = append(messages, map[string]string{"role": "user", "content": r.User})
	body["messages"] = messages
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(raw))
	if err != nil {
		return Response{}, errors.New("llm: request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if p.kind == "anthropic" {
		req.Header.Set("x-api-key", p.settings.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else if p.settings.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.settings.APIKey)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return Response{}, errors.New("llm: connection failed or timed out")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return Response{}, errors.New("llm: response exceeds limit or could not be read")
	}
	if res.StatusCode/100 != 2 {
		return Response{}, errors.New("llm: provider rejected request")
	}
	var reply struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(data, &reply) != nil {
		return Response{}, errors.New("llm: invalid response")
	}
	text := ""
	if p.kind == "anthropic" {
		for _, c := range reply.Content {
			if c.Type == "text" {
				text += c.Text
			}
		}
	} else if len(reply.Choices) > 0 {
		text = reply.Choices[0].Message.Content
	}
	if text == "" {
		return Response{}, errors.New("llm: empty response")
	}
	return Response{Text: text}, nil
}
