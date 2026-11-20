package pull

import (
	"strings"
	"testing"
)

func TestProofVector(t *testing.T) {
	// printf 'netnoodle-pair-v1\n<64a>\n<64b>' | openssl dgst -sha256 -hmac ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	got := Proof(" ABCDEFGHIJKLMNOPQRSTUVWXYZ234567\n", a, b)
	if got != wantVector {
		t.Fatalf("proof = %s", got)
	}
	if !CheckProof(strings.ToUpper(got), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", a, b) || CheckProof(got, "x", a, b) {
		t.Fatal("CheckProof")
	}
}

func TestValidAddress(t *testing.T) {
	for _, ok := range []string{"10.0.0.5:7444", "proxy.dmz:7444", "[fe80::1]:7444"} {
		if err := ValidAddress(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.0.0.5", "https://x:1", "x:0", "x:99999", ":7444", "a/b:1"} {
		if ValidAddress(bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

const wantVector = "7ed0c7236c00d91067160e5c434ae2b07c4c257c46d0a2837ade5855e1f9d5dc"
