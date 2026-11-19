package inventory

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"unicode"

	"netnoodle/internal/proto"
)

// Limits for one entity. Larger input is cut, not refused, so one bad
// field does not drop a whole agent report.
const (
	maxIdentifiers = 256
	maxComponents  = 100000
	maxServices    = 10000
	maxInterfaces  = 256
	maxAttributes  = 256
	maxChildren    = 10000
	maxDepth       = 4
	maxText        = 1024
)

var kindRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// CleanText removes control characters and cuts s to max bytes.
func CleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		// A cut inside a multi-byte rune leaves invalid bytes; drop them.
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// NormalizeMAC returns the MAC in lower-case colon form, and whether it is
// usable as an identifier, and whether it is locally administered.
func NormalizeMAC(s string) (mac string, local bool, err error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", false, errors.New("bad mac")
	}
	if hw[0]&1 == 1 { // multicast or broadcast
		return "", false, errors.New("multicast mac")
	}
	zero := true
	for _, b := range hw {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return "", false, errors.New("zero mac")
	}
	return hw.String(), hw[0]&2 == 2, nil
}

// NormalizeIP returns the canonical text form of a unicast IP that can
// identify a device. Loopback, unspecified and link-local addresses are refused.
func NormalizeIP(s string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return "", errors.New("not a device address")
	}
	return a.String(), nil
}

// NormalizeHostname lower-cases a host name and removes a trailing dot.
func NormalizeHostname(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || s == "localhost" || len(s) > 253 {
		return "", errors.New("bad hostname")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return "", errors.New("bad hostname")
		}
	}
	return s, nil
}

// normalizeIdentifier applies the server's rules, independent of what the
// source claims:
//   - mac: canonical form; locally administered MACs are weak, because
//     they repeat across hosts (container bridges) or rotate (phones).
//   - ip and hostname: always weak.
func normalizeIdentifier(id proto.Identifier) (proto.Identifier, bool) {
	id.Kind = strings.ToLower(strings.TrimSpace(id.Kind))
	if !kindRE.MatchString(id.Kind) {
		return id, false
	}
	if id.Strength != proto.Strong {
		id.Strength = proto.Weak
	}
	switch id.Kind {
	case "mac":
		mac, local, err := NormalizeMAC(id.Value)
		if err != nil {
			return id, false
		}
		id.Value = mac
		if local {
			id.Strength = proto.Weak
		}
	case "ip":
		ip, err := NormalizeIP(id.Value)
		if err != nil {
			return id, false
		}
		id.Value, id.Strength = ip, proto.Weak
	case "hostname":
		h, err := NormalizeHostname(id.Value)
		if err != nil {
			return id, false
		}
		id.Value, id.Strength = h, proto.Weak
	default:
		id.Value = CleanText(id.Value, 512)
		if id.Value == "" {
			return id, false
		}
	}
	return id, true
}

// NormalizeIdentifiers normalizes a list, drops bad and duplicate entries,
// and keeps the strongest strength for duplicates.
func NormalizeIdentifiers(in []proto.Identifier) []proto.Identifier {
	type key struct{ k, v string }
	idx := map[key]int{}
	var out []proto.Identifier
	for _, raw := range in {
		id, ok := normalizeIdentifier(raw)
		if !ok {
			continue
		}
		k := key{id.Kind, id.Value}
		if i, dup := idx[k]; dup {
			if id.Strength == proto.Strong {
				out[i].Strength = proto.Strong
			}
			continue
		}
		if len(out) >= maxIdentifiers {
			break
		}
		idx[k] = len(out)
		out = append(out, id)
	}
	return out
}

func validKind(k proto.EntityKind) proto.EntityKind {
	switch k {
	case proto.KindHost, proto.KindVM, proto.KindContainer, proto.KindNetworkDevice:
		return k
	}
	return proto.KindUnknown
}

func validConfidence(c proto.Confidence, def proto.Confidence) proto.Confidence {
	if c == proto.High || c == proto.Low {
		return c
	}
	return def
}

// NormalizeEntity cleans an entity tree in place. It adds identifiers that
// follow from the interfaces (MACs and IPs). It returns false if the
// entity has no usable identifier; such an entity is skipped.
func NormalizeEntity(e *proto.Entity) bool { return normalizeEntity(e, 0) }

func normalizeEntity(e *proto.Entity, depth int) bool {
	e.Kind = validKind(e.Kind)
	e.Name = CleanText(e.Name, 255)

	if len(e.Interfaces) > maxInterfaces {
		e.Interfaces = e.Interfaces[:maxInterfaces]
	}
	ids := append([]proto.Identifier(nil), e.Identifiers...)
	for i := range e.Interfaces {
		in := &e.Interfaces[i]
		in.Name = CleanText(in.Name, 64)
		if in.MAC != "" {
			if mac, _, err := NormalizeMAC(in.MAC); err == nil {
				in.MAC = mac
				ids = append(ids, proto.Identifier{Kind: "mac", Value: mac, Strength: proto.Strong})
			} else {
				in.MAC = ""
			}
		}
		var ips []string
		for _, ip := range in.IPs {
			if n, err := NormalizeIP(ip); err == nil {
				ips = append(ips, n)
				ids = append(ids, proto.Identifier{Kind: "ip", Value: n, Strength: proto.Weak})
			}
		}
		in.IPs = ips
	}
	e.Identifiers = NormalizeIdentifiers(ids)
	e.Parent = NormalizeIdentifiers(e.Parent)

	if len(e.Attributes) > 0 {
		attrs := map[string]string{}
		for k, v := range e.Attributes {
			k = strings.ToLower(CleanText(k, 64))
			if !kindRE.MatchString(k) || len(attrs) >= maxAttributes {
				continue
			}
			attrs[k] = CleanText(v, maxText)
		}
		e.Attributes = attrs
	}

	if len(e.Components) > maxComponents {
		e.Components = e.Components[:maxComponents]
	}
	comps := e.Components[:0]
	for _, c := range e.Components {
		c.PURL = CleanText(c.PURL, 512)
		if !strings.HasPrefix(c.PURL, "pkg:") {
			continue
		}
		c.Name = CleanText(c.Name, 255)
		c.Version = CleanText(c.Version, 128)
		c.Confidence = validConfidence(c.Confidence, proto.High)
		comps = append(comps, c)
	}
	e.Components = comps

	if len(e.Services) > maxServices {
		e.Services = e.Services[:maxServices]
	}
	svcs := e.Services[:0]
	for _, s := range e.Services {
		s.Proto = strings.ToLower(s.Proto)
		if (s.Proto != "tcp" && s.Proto != "udp") || s.Port < 0 || s.Port > 65535 {
			continue
		}
		s.Address = CleanText(s.Address, 64)
		s.Product = CleanText(s.Product, 128)
		s.Version = CleanText(s.Version, 128)
		s.Process = CleanText(s.Process, 255)
		s.Component = CleanText(s.Component, 512)
		s.Banner = CleanText(s.Banner, maxText)
		s.Confidence = validConfidence(s.Confidence, proto.Low)
		svcs = append(svcs, s)
	}
	e.Services = svcs

	if depth >= maxDepth {
		e.Children = nil
	}
	if len(e.Children) > maxChildren {
		e.Children = e.Children[:maxChildren]
	}
	kids := e.Children[:0]
	for i := range e.Children {
		if normalizeEntity(&e.Children[i], depth+1) {
			kids = append(kids, e.Children[i])
		}
	}
	e.Children = kids

	return len(e.Identifiers) > 0
}
