package tlspin

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// CheckURL accepts an https URL. Plain http is accepted only to a loopback
// address, or when allowHTTP is set (an explicit, visible opt-in): data and
// credentials from or to such a URL can be read and changed on the network
// (security review 2026-11-20).
func CheckURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("bad url %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); allowHTTP || host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("url %q uses plain http; use https (or set allow_insecure_http)", raw)
	}
	return fmt.Errorf("url %q must use https", raw)
}
