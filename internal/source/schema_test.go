package source_test

import (
	"encoding/json"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/source"
	_ "github.com/JulianStremel/netnoodle/internal/source/homeassistant"
	_ "github.com/JulianStremel/netnoodle/internal/source/proxmox"
	_ "github.com/JulianStremel/netnoodle/internal/source/tailscale"
	_ "github.com/JulianStremel/netnoodle/internal/source/unifi"
)

func TestSchemas(t *testing.T) {
	for _, typ := range []string{"unifi", "proxmox", "tailscale", "homeassistant"} {
		schema, ok := source.Registry.Schema(typ)
		if !ok {
			t.Fatalf("missing schema: %s", typ)
		}
		secret, interval := false, false
		for _, f := range schema.Fields {
			if f.Key == "" || f.Label == "" || f.Help == "" {
				t.Fatalf("incomplete %s field: %+v", typ, f)
			}
			secret = secret || f.Type == "secret" && f.Required
			interval = interval || f.Type == "duration" && f.Key == "interval"
		}
		if !secret || !interval {
			t.Fatalf("%s needs credentials and poll interval", typ)
		}
		schema.Fields[0].Key = "mutated"
		again, _ := source.Registry.Schema(typ)
		if again.Fields[0].Key == "mutated" {
			t.Fatal("schema is mutable")
		}
	}
}

func TestSchemaDefaultsBuildSources(t *testing.T) {
	for _, typ := range []string{"unifi", "proxmox", "tailscale", "homeassistant"} {
		t.Run(typ, func(t *testing.T) {
			schema, _ := source.Registry.Schema(typ)
			settings := map[string]any{}
			for _, f := range schema.Fields {
				if f.Key == "interval" {
					continue
				}
				if f.Default != nil {
					settings[f.Key] = f.Default
				}
				if f.Type == "secret" {
					settings[f.Key] = "test-credential"
				}
				if f.Type == "url" {
					settings[f.Key] = "https://127.0.0.1:7443"
				}
				if f.Key == "token_id" {
					settings[f.Key] = "test@pve!audit"
				}
			}
			raw, _ := json.Marshal(settings)
			built, err := source.Registry.Build(typ, "schema-instance", raw)
			if err != nil || built.Name() != "schema-instance" {
				t.Fatalf("constructor does not accept schema: %v", err)
			}
		})
	}
}
