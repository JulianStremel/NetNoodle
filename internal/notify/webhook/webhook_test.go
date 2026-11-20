package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/notify"
)

func TestWebhook(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		if r.Header.Get("X-Key") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		got = append(got, m)
	}))
	defer srv.Close()

	n, err := New("hook", json.RawMessage(`{"url":"`+srv.URL+`","headers":{"X-Key":"k"},"types":["device."]}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := n.Notify(ctx, notify.Event{Type: "device.new", Title: "New device"}); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, notify.Event{Type: "login", Title: "skip me"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["title"] != "New device" {
		t.Fatalf("got %v", got)
	}

	if _, err := New("bad", json.RawMessage(`{"url":"ftp://x"}`)); err == nil {
		t.Fatal("bad url accepted")
	}
}
