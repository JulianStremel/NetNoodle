package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
)

const endpointTestType = "endpoint-security-test"

func init() {
	source.Registry.RegisterWithSchema(endpointTestType, func(name string, raw json.RawMessage) (source.Source, error) {
		return &integrationFixture{name: name}, nil
	}, source.SettingsSchema(
		registry.Field{Key: "key", Label: "Key", Type: "secret", Required: true},
		registry.Field{Key: "headers", Label: "Headers", Type: "secret"},
		registry.Field{Key: "url", Label: "URL", Type: "url", Default: "https://original.example"},
		registry.Field{Key: "fingerprint", Label: "Fingerprint", Type: "fingerprint"},
		registry.Field{Key: "base_url", Label: "Base", Type: "string", Default: "https://original.example"},
		registry.Field{Key: "broker", Label: "Broker", Type: "string", Default: "mqtts://original.example"},
		registry.Field{Key: "other_url", Label: "Other URL", Type: "url", Default: "https://original.example"},
		registry.Field{Key: "other_pin", Label: "Other pin", Type: "fingerprint"},
	))
}

func TestEndpointChangesRequireFreshSecrets(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	for _, key := range []string{"url", "fingerprint", "base_url", "broker", "other_url", "other_pin"} {
		t.Run(key, func(t *testing.T) {
			body := map[string]any{"type": endpointTestType, "name": "security-" + key, "settings": map[string]any{}, "secrets": map[string]string{"key": integrationTestSecret, "headers": "saved-optional-secret"}, "enabled": false, "password": pw}
			code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body)
			if code != 200 {
				t.Fatal(code, string(b))
			}
			var saved struct{ ID int64 }
			_ = json.Unmarshal(b, &saved)
			body["id"] = saved.ID
			body["password"] = ""
			body["secrets"] = map[string]string{}
			if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body); code != 200 {
				t.Fatal("unchanged", code, string(b))
			}
			value := "https://attacker.example"
			if key == "broker" {
				value = "mqtts://attacker.example"
			}
			if key == "fingerprint" || strings.Contains(key, "pin") {
				value = strings.Repeat("a", 64)
			}
			body["settings"] = map[string]any{key: value}
			for _, secrets := range []map[string]string{{}, {"key": "fresh-key"}} {
				body["secrets"] = secrets
				if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body); code != 400 {
					t.Fatal("stored secret reused", code, string(b))
				}
			}
			body["password"] = "wrong"
			if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body); code != 403 {
				t.Fatal("bad step-up", code, string(b))
			}
			body["password"] = pw
			if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body); code != 200 {
				t.Fatal("step-up reuse", code, string(b))
			}
			path := fmt.Sprintf("%s/api/integrations/%d", ts.URL, saved.ID)
			if code, b := integrationCall(t, c, "PUT", path, body); code != 400 {
				t.Fatal("PUT reused secrets despite endpoint change", code, string(b))
			}
			body["password"] = ""
			body["secrets"] = map[string]string{"key": "fresh-key", "headers": "fresh-headers"}
			if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body); code != 200 {
				t.Fatal("fresh secrets", code, string(b))
			}
			body["password"] = pw
			if code, b := integrationCall(t, c, "PUT", path, body); code != 200 {
				t.Fatal("fresh PUT", code, string(b))
			}
			row, err := s.st.GetIntegration(t.Context(), saved.ID)
			if err != nil || strings.Contains(string(row.Secrets), integrationTestSecret) {
				t.Fatal("old secret persisted", err)
			}
		})
	}
}

func TestProbeConcurrencyAndMetadata(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	for range cap(s.integrations.testSlots) {
		s.integrations.testSlots <- struct{}{}
	}
	if code, _ := integrationCall(t, c, "POST", ts.URL+"/api/integrations/probe", map[string]string{"url": "https://127.0.0.1"}); code != 429 {
		t.Fatal(code)
	}
	for range cap(s.integrations.testSlots) {
		<-s.integrations.testSlots
	}
	for _, url := range []string{"http://127.0.0.1", "https://169.254.169.254", "https://[fe80::1]", "https://[fd00:ec2::254]"} {
		if code, _ := integrationCall(t, c, "POST", ts.URL+"/api/integrations/probe", map[string]string{"url": url}); code != 400 {
			t.Fatalf("%s: %d", url, code)
		}
	}
}

func TestCredentialURLsAreWriteOnly(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	endpoint := "https://service.example/hooks/super-private-token?token=hidden"
	for _, typ := range []string{"webhook", endpointTestType} {
		body := map[string]any{"kind": "source", "type": typ, "name": "secret-url-" + typ, "settings": map[string]any{"url": endpoint}, "secrets": map[string]string{"key": integrationTestSecret}, "enabled": false, "password": pw}
		if typ == "webhook" {
			body["kind"] = "notify"
			body["settings"] = map[string]any{}
			body["secrets"] = map[string]string{"url": endpoint}
		}
		code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body)
		if code != 200 {
			t.Fatal(code, string(b))
		}
		var saved struct{ ID int64 }
		_ = json.Unmarshal(b, &saved)
		row, err := s.st.GetIntegration(t.Context(), saved.ID)
		if err != nil || strings.Contains(string(row.Settings), "super-private-token") || !strings.Contains(string(row.Secrets), "super-private-token") {
			t.Fatalf("URL not secret: %+v %v", row, err)
		}
		body["secrets"] = map[string]string{}
		body["settings"] = map[string]any{}
		if code, b := integrationCall(t, c, "PUT", fmt.Sprintf("%s/api/integrations/%d", ts.URL, saved.ID), body); code != 200 {
			t.Fatal("blank secret URL not retained", code, string(b))
		}
	}
	code, b := integrationCall(t, c, "GET", ts.URL+"/api/integrations", nil)
	if code != 200 || strings.Contains(string(b), "super-private-token") || strings.Contains(string(b), "?token=") {
		t.Fatal("URL exposed", code, string(b))
	}
}
