package tlspin

import (
	"net"
	"testing"
)

func TestMetadataDestinations(t *testing.T) {
	for _, host := range []string{"169.254.0.1", "169.254.169.254", "fe80::1", "febf::1234", "fd00:ec2::254", "::ffff:169.254.169.254"} {
		if err := SafeControl("tcp", net.JoinHostPort(host, "443"), nil); err == nil {
			t.Errorf("accepted %s", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "192.168.1.1", "fd00::1", "1.1.1.1"} {
		if err := SafeControl("tcp", net.JoinHostPort(host, "443"), nil); err != nil {
			t.Errorf("rejected %s: %v", host, err)
		}
	}
}
