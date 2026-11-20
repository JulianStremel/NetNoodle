package proto

import (
	"path"
	"strings"
)

// MatchesScope reports whether an identifier is inside the target scope of
// an actor: patterns are "kind=glob", the kind must match exactly and the
// glob uses path.Match. A glob that ends in "/*" with a literal prefix also
// matches the whole subtree (proxmox.guest=pve/* matches pve/lab/100).
// Empty patterns match everything; malformed globs fail closed. The server
// (planner) and the actor use this one function, so they always agree.
func MatchesScope(patterns []string, t Identifier) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		kind, glob, ok := strings.Cut(pattern, "=")
		if !ok || kind != t.Kind {
			continue
		}
		if matched, err := path.Match(glob, t.Value); err == nil && matched {
			return true
		}
		prefix, sub := strings.CutSuffix(glob, "/*")
		if sub && prefix != "" && !strings.ContainsAny(prefix, "*?[\\") && strings.HasPrefix(t.Value, prefix+"/") {
			return true
		}
	}
	return false
}
