package scan

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// readARP returns the local neighbour table as ip -> mac.
func readARP() (map[string]string, error) {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/proc/net/arp")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return parseProcARP(f)
	case "windows":
		out, err := exec.Command("arp", "-a").Output()
		if err != nil {
			return nil, err
		}
		return parseArpA(string(out)), nil
	case "darwin", "freebsd", "openbsd", "netbsd":
		out, err := exec.Command("arp", "-an").Output()
		if err != nil {
			return nil, err
		}
		return parseArpA(string(out)), nil
	}
	return nil, errNoARP
}

// parseProcARP reads Linux /proc/net/arp.
func parseProcARP(r interface{ Read([]byte) (int, error) }) (map[string]string, error) {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		// IP address, HW type, Flags, HW address, Mask, Device
		if len(f) < 4 || f[2] == "0x0" {
			continue
		}
		addMAC(m, f[0], f[3])
	}
	return m, sc.Err()
}

var arpLineRE = regexp.MustCompile(`\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9A-Fa-f]{1,2}(?:[-:][0-9A-Fa-f]{1,2}){5})`)

// parseArpA reads the output of "arp -a" (Windows) and "arp -an" (BSD, macOS).
func parseArpA(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if mm := arpLineRE.FindStringSubmatch(line); mm != nil {
			addMAC(m, mm[1], mm[2])
		}
	}
	return m
}

func addMAC(m map[string]string, ip, mac string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	// BSD prints "0:1a:2b:..." without leading zeros.
	parts := strings.FieldsFunc(mac, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	hw, err := net.ParseMAC(strings.Join(parts, ":"))
	if err != nil || hw.String() == "00:00:00:00:00:00" || hw.String() == "ff:ff:ff:ff:ff:ff" {
		return
	}
	m[a.String()] = hw.String()
}
