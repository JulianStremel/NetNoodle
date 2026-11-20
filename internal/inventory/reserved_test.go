package inventory

import (
	"testing"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

// TestStripReservedAttributes: a peer cannot set attributes of the
// in-process sources, for example tailscale.routes (security review
// 2026-11-20: one agent could make every device tunnel-reachable).
func TestStripReservedAttributes(t *testing.T) {
	es := []proto.Entity{{
		Attributes: map[string]string{"tailscale.routes": "0.0.0.0/1", "os.name": "debian"},
		Children:   []proto.Entity{{Attributes: map[string]string{"proxmox.node": "x", "ha.area": "y", "container.image": "nginx"}}},
	}}
	StripReservedAttributes(es)
	if len(es[0].Attributes) != 1 || es[0].Attributes["os.name"] != "debian" {
		t.Fatal(es[0].Attributes)
	}
	if c := es[0].Children[0].Attributes; len(c) != 1 || c["container.image"] != "nginx" {
		t.Fatal(c)
	}
}
