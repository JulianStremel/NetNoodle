package version

import "testing"

func TestParse(t *testing.T) {
	for _, s := range []string{"v1.2.3", "1.2.0", "v1.2.3-4-gabc-dirty", "1.2.3-rc.1+build.2"} {
		a, b, ok := Parse(s)
		if !ok || a != 1 || b != 2 {
			t.Errorf("Parse(%q)=%d,%d,%v", s, a, b, ok)
		}
	}
	for _, s := range []string{"", "dev", "1.2.3-..", "1.2.3-01", "1.2.3+x..y", "abc123", "v1.2", "1.02.3", "1.2.3evil", "-1.2.3", "99999999999999999999999999.2.3"} {
		if _, _, ok := Parse(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestOutdated(t *testing.T) {
	for _, tc := range []struct {
		peer, server string
		want         bool
	}{
		{"v0.1.9", "v0.3.0", true}, {"v0.2.0", "v0.3.8", false}, {"v0.3.0", "v0.3.8", false},
		{"v0.4.0", "v0.3.0", false}, {"v1.8.0", "v2.3.0", true}, {"dev", "v0.3.0", false},
		{"v0.1.0", "dev", false}, {"", "v0.3.0", false}, {"v1.99.0", "v2.0.0", true},
		{"v0.99.0", "v2.0.0", true}, {"v0.1.0", "v0.3.0-2-g123-dirty", true},
	} {
		if got := Outdated(tc.peer, tc.server); got != tc.want {
			t.Errorf("Outdated(%q,%q)=%v", tc.peer, tc.server, got)
		}
	}
}
