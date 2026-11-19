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
