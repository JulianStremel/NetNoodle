package inventory

import (
	"testing"

	"netnoodle/internal/proto"
)

func TestNormalizeIdentifiers(t *testing.T) {
	in := []proto.Identifier{
		{Kind: "MAC", Value: "00-1A-2B-DD-EE-01", Strength: proto.Weak},
		{Kind: "mac", Value: "00:1a:2b:dd:ee:01", Strength: proto.Strong}, // duplicate, raises strength
		{Kind: "ip", Value: "::ffff:10.0.0.1", Strength: proto.Strong},    // forced weak, unmapped
		{Kind: "ip", Value: "fe80::1", Strength: proto.Weak},              // link-local: dropped
		{Kind: "hostname", Value: "Web1.Lan.", Strength: proto.Strong},    // forced weak
		{Kind: "Bad Kind", Value: "x", Strength: proto.Strong},            // dropped
		{Kind: "agent", Value: "  ", Strength: proto.Strong},              // empty: dropped
		{Kind: "mac", Value: "06:00:00:00:00:01", Strength: proto.Strong}, // local: weak
	}
	got := NormalizeIdentifiers(in)
	want := []proto.Identifier{
		{Kind: "mac", Value: "00:1a:2b:dd:ee:01", Strength: proto.Strong},
		{Kind: "ip", Value: "10.0.0.1", Strength: proto.Weak},
		{Kind: "hostname", Value: "web1.lan", Strength: proto.Weak},
		{Kind: "mac", Value: "06:00:00:00:00:01", Strength: proto.Weak},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestCleanText(t *testing.T) {
	if got := CleanText("a\x00b\nc  ", 10); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := CleanText("ääää", 3); got != "ä" {
		t.Errorf("cut in rune: got %q", got)
	}
}
