package registry

import (
	"encoding/json"
	"testing"
)

type thing interface{ Name() string }

type named struct {
	name string
	Port int `json:"port"`
}

func (n named) Name() string { return n.name }

func TestBuildAll(t *testing.T) {
	r := New[thing]("thing")
	r.Register("a", func(name string, s json.RawMessage) (thing, error) {
		n := named{name: name, Port: 1}
		return n, Decode(s, &n)
	})

	got, err := BuildAll(r, []Spec{
		{Type: "a", Name: "one", Settings: json.RawMessage(`{"port":2}`)},
		{Type: "a"},
		{Type: "a", Name: "off", Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name() != "one" || got[0].(named).Port != 2 || got[1].Name() != "a" {
		t.Fatalf("got %+v", got)
	}

	if _, err := BuildAll(r, []Spec{{Type: "missing"}}); err == nil {
		t.Fatal("unknown type accepted")
	}
	if _, err := BuildAll(r, []Spec{{Type: "a", Name: "x"}, {Type: "a", Name: "x"}}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err := BuildAll(r, []Spec{{Type: "a", Settings: json.RawMessage(`{"nope":1}`)}}); err == nil {
		t.Fatal("unknown setting accepted")
	}
}

func TestDuplicateRegisterPanics(t *testing.T) {
	r := New[thing]("thing")
	f := func(string, json.RawMessage) (thing, error) { return named{}, nil }
	r.Register("a", f)
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	r.Register("a", f)
}

func TestSchemaRegistration(t *testing.T) {
	f := func(name string, raw json.RawMessage) (thing, error) { return named{name: name}, nil }
	r := New[thing]("schema")
	schema := Schema{Fields: []Field{{Key: "names", Label: "Names", Type: "list", Default: []string{"first"}}, {Key: "password", Label: "Password", Type: "secret", Required: true}}}
	r.RegisterWithSchema("one", f, schema)
	schema.Fields[0].Label = "changed"
	got, ok := r.Schema("one")
	if !ok || got.Fields[0].Label != "Names" {
		t.Fatal(got, ok)
	}
	got.Fields[0].Default.([]any)[0] = "changed"
	again, _ := r.Schema("one")
	if again.Fields[0].Default.([]any)[0] != "first" {
		t.Fatal("default is mutable")
	}
	if _, ok := r.Schema("unknown"); ok {
		t.Fatal("unknown schema exists")
	}
	if built, err := r.Build("one", "instance", nil); err != nil || built.Name() != "instance" {
		t.Fatal(built, err)
	}
	for _, tc := range []struct {
		name   string
		schema Schema
	}{
		{"duplicate", schema},
		{"bad-type", Schema{Fields: []Field{{Key: "x", Type: "invalid"}}}},
		{"bad-key", Schema{Fields: []Field{{Key: "", Type: "string"}}}},
		{"duplicate-key", Schema{Fields: []Field{{Key: "x", Type: "string"}, {Key: "x", Type: "bool"}}}},
		{"secret-default", Schema{Fields: []Field{{Key: "secret", Type: "secret", Default: "must-not-publish"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registration must panic")
				}
			}()
			typ := tc.name
			if tc.name == "duplicate" {
				typ = "one"
			}
			r.RegisterWithSchema(typ, f, tc.schema)
		})
	}
}
