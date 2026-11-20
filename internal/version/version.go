// Package version identifies binaries and their compatibility window.
package version

import (
	"regexp"
	"strconv"
)

// Version is replaced by release builds using -ldflags -X.
var Version = "dev"

const Protocol = "v1"

const prerelease = `(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`

var semver = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-` + prerelease + `(?:\.` + prerelease + `)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// Parse returns the release's major and minor numbers. Patch and build metadata
// do not affect compatibility (including git describe's distance/hash suffix).
func Parse(s string) (major, minor int, ok bool) {
	m := semver.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(m[1])
	b, e2 := strconv.Atoi(m[2])
	return a, b, e1 == nil && e2 == nil
}

// Outdated compares major.minor releases. The current and previous minor are
// supported within a major version; a major bump starts a new compatibility
// window. Development and unversioned legacy peers are never marked outdated.
func Outdated(peer, server string) bool {
	pm, pn, pok := Parse(peer)
	sm, sn, sok := Parse(server)
	if !pok || !sok {
		return false
	}
	return pm < sm || (pm == sm && pn < sn-1)
}
