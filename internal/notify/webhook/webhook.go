// Package webhook is a notifier that POSTs each event as JSON to a URL.
// It works with generic receivers (ntfy, Gotify via a proxy, n8n, Home
// Assistant webhooks, Slack-compatible endpoints with "format": "slack").
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netnoodle/internal/notify"
	"netnoodle/internal/registry"
	"netnoodle/internal/tlspin"
)

func init() {
	notify.Registry.Register("webhook", New)
}

// Settings for the webhook notifier.
type Settings struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// Types limits the event types sent (prefix match, e.g. "device.").
	// Empty means all.
	Types []string `json:"types,omitempty"`
	// Format is "json" (the event as is, default) or "slack" ({"text": ...}).
	Format string `json:"format,omitempty"`
}

type hook struct {
	name string
	s    Settings
	c    *http.Client
}

// New builds a webhook notifier.
func New(name string, raw json.RawMessage) (notify.Notifier, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(s.URL, "https://") && !strings.HasPrefix(s.URL, "http://") {
		return nil, errors.New("url must start with http:// or https://")
	}
	if s.Format == "" {
		s.Format = "json"
	}
	if s.Format != "json" && s.Format != "slack" {
		return nil, fmt.Errorf("unknown format %q", s.Format)
	}
	return &hook{name: name, s: s, c: &http.Client{Timeout: 10 * time.Second, CheckRedirect: tlspin.NoRedirects}}, nil
}

func (h *hook) Name() string { return h.name }

func (h *hook) wants(t string) bool {
	if len(h.s.Types) == 0 {
		return true
	}
	for _, p := range h.s.Types {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func (h *hook) Notify(ctx context.Context, e notify.Event) error {
	if !h.wants(e.Type) {
		return nil
	}
	var body any = e
	if h.s.Format == "slack" {
		text := e.Title
		if e.Detail != "" {
			text += "\n" + e.Detail
		}
		body = map[string]string{"text": text}
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.s.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.s.Headers {
		req.Header.Set(k, v)
	}
	res, err := h.c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned %s", res.Status)
	}
	return nil
}
