// Package pull defines how the server pulls reports from agents that it
// cannot reach by push (for example in a DMZ). See docs/design/pull-mode.md.
package pull

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Target is one pull agent.
type Target struct {
	Name    string
	Address string // host:port
	Pin     string // SHA-256 fingerprint of the agent certificate (lower-case hex)
}

// Transport connects to pull agents.
type Transport interface {
	// Pair connects to an unpaired agent, checks its proof of the pairing
	// code and returns the agent certificate fingerprint.
	Pair(ctx context.Context, t Target, code string) (pin string, err error)
	// Pull returns one raw report. It applies size and time limits.
	Pull(ctx context.Context, t Target) ([]byte, error)
}

// ProofLabel is the domain separation prefix of the pairing proof.
const ProofLabel = "netnoodle-pair-v1"

// Proof is HMAC-SHA256(code, label + "\n" + agentFP + "\n" + serverFP)
// in lower-case hex. Both fingerprints are lower-case hex without colons.
func Proof(code, agentFP, serverFP string) string {
	m := hmac.New(sha256.New, []byte(strings.TrimSpace(code)))
	m.Write([]byte(ProofLabel + "\n" + agentFP + "\n" + serverFP))
	return hex.EncodeToString(m.Sum(nil))
}

// CheckProof compares a received proof in constant time.
func CheckProof(got, code, agentFP, serverFP string) bool {
	want := Proof(code, agentFP, serverFP)
	return hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(got))), []byte(want))
}

// ValidAddress checks a host:port address without scheme or path.
func ValidAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || len(addr) > 255 {
		return errors.New("address must be host:port")
	}
	if strings.ContainsAny(host, "/?#@ ") {
		return errors.New("address must be host:port without scheme or path")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("port must be 1-65535")
	}
	return nil
}
