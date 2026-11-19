package intel

import (
	"fmt"
	"net/url"
	"strings"
)

// PURL is a parsed package URL (https://github.com/package-url/purl-spec).
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

// ParsePURL parses "pkg:type/namespace/name@version?k=v#subpath".
// The subpath is ignored. Percent-encoding is decoded.
func ParsePURL(s string) (PURL, error) {
	var p PURL
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return p, fmt.Errorf("purl %q: no pkg: prefix", s)
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	if query != "" {
		p.Qualifiers = map[string]string{}
		for _, kv := range strings.Split(query, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if k == "" {
				continue
			}
			dv, err := url.PathUnescape(v)
			if err != nil {
				return p, fmt.Errorf("purl %q: %w", s, err)
			}
			p.Qualifiers[strings.ToLower(k)] = dv
		}
	}
	// The version is after the last "@" of the last path segment.
	slash := strings.LastIndex(rest, "/")
	if at := strings.LastIndex(rest, "@"); at > slash {
		v, err := url.PathUnescape(rest[at+1:])
		if err != nil {
			return p, fmt.Errorf("purl %q: %w", s, err)
		}
		p.Version = v
		rest = rest[:at]
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		return p, fmt.Errorf("purl %q: needs type and name", s)
	}
	p.Type = strings.ToLower(parts[0])
	dec := make([]string, 0, len(parts)-1)
	for _, seg := range parts[1:] {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return p, fmt.Errorf("purl %q: %w", s, err)
		}
		dec = append(dec, d)
	}
	p.Name = dec[len(dec)-1]
	p.Namespace = strings.Join(dec[:len(dec)-1], "/")
	if p.Name == "" {
		return p, fmt.Errorf("purl %q: empty name", s)
	}
	return p, nil
}

// Upstream returns the source package name and version from the
// `upstream` qualifier ("openssl" or "six@1.16.0-3"). Empty if absent.
func (p PURL) Upstream() (name, version string) {
	u := p.Qualifiers["upstream"]
	if u == "" {
		return "", ""
	}
	name, version, _ = strings.Cut(u, "@")
	return name, version
}
