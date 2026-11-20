package tlspin

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// SafeControl checks the resolved socket address immediately before connect,
// including redirects and DNS changes. Private and loopback networks remain
// available for the operator's local integrations; metadata networks never are.
func SafeControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return fmt.Errorf("unsafe integration destination")
	}
	return nil
}

// Transport bypasses environment proxies so every actual destination is checked.
func Transport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: SafeControl}).DialContext
	return tr
}

// CredentialURL conservatively treats every path or query as potentially secret.
// Webhook origins are also secret by schema. URL values remain usable internally.
func CredentialURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && (u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") || u.Fragment != "")
}
