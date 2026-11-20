package proto

import "testing"

// TestMatchesScope: server and actor share this matcher (security review
// 2026-11-20: the planner did not know the subtree rule, so the Proxmox
// actor with scope proxmox.guest=pve/* was never selected).
func TestMatchesScope(t *testing.T) {
	g := func(v string) Identifier { return Identifier{Kind: "proxmox.guest", Value: v} }
	for _, tc := range []struct {
		patterns []string
		id       Identifier
		want     bool
	}{
		{nil, g("pve/lab/100"), true},
		{[]string{"proxmox.guest=pve/*"}, g("pve/lab/100"), true},
		{[]string{"proxmox.guest=pve/*"}, g("pve"), false},
		{[]string{"proxmox.guest=pve/*"}, g("pve2/lab/100"), false},
		{[]string{"proxmox.guest=pve/lab/*"}, g("pve/lab/100"), true},
		{[]string{"proxmox.guest=p*/*"}, g("pve/lab/100"), false},
		{[]string{"mac=pve/*"}, g("pve/lab/100"), false},
		{[]string{"proxmox.guest=["}, g("pve/lab/100"), false},
		{[]string{"mac=00:11:*"}, Identifier{Kind: "mac", Value: "00:11:22:33:44:55"}, true},
	} {
		if got := MatchesScope(tc.patterns, tc.id); got != tc.want {
			t.Errorf("%v %v = %v", tc.patterns, tc.id, got)
		}
	}
}
