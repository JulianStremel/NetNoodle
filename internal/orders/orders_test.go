package orders

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

func TestSignVerify(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	o := proto.Order{Version: proto.Version, ID: "order", Action: "isolate", Actor: "a", Nonce: "nonce", NotAfter: time.Now().UTC().Add(time.Minute), Targets: []proto.Identifier{{Kind: "mac", Value: "aa", Strength: proto.Strong}}}
	env, e := Sign(key, o)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(pub, env)
	if e != nil || !reflect.DeepEqual(got, o) {
		t.Fatal(got, e)
	}
	if _, e = Verify(wrong, env); e == nil {
		t.Fatal("wrong key accepted")
	}
	tampered := env
	tampered.Payload = append([]byte(nil), env.Payload...)
	tampered.Payload[5] ^= 1
	if _, e = Verify(pub, tampered); e == nil {
		t.Fatal("tampering accepted")
	}
	for _, b := range []string{`{"version":"v1","unknown":true}`, `{"version":"v2"}`, `{"version":"v1"} {}`, `{"version":"v1","targets":[{"kind":"mac","surprise":1}]}`} {
		env := Envelope{Payload: []byte(b), Sig: ed25519.Sign(key, []byte(b))}
		if _, e = Verify(pub, env); e == nil {
			t.Fatal("accepted", b)
		}
	}
	b, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	var wire map[string]string
	if e = json.Unmarshal(b, &wire); e != nil || wire["payload"] == "" || wire["sig"] == "" || len(wire) != 2 {
		t.Fatal(string(b), e)
	}
}
func TestNoncePersistenceReplayAndExpiry(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nonces.json")
	n, e := OpenNonceStore(file)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	until := now.Add(time.Minute)
	if e = n.Use("one", until, now); e != nil {
		t.Fatal(e)
	}
	if e = n.Use("one", until, now); e == nil {
		t.Fatal("replay accepted")
	}
	n, e = OpenNonceStore(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = n.Use("one", until, now); e == nil {
		t.Fatal("replay after restart")
	}
	if e = n.Use("expired", now, now); e == nil {
		t.Fatal("expired accepted")
	}
	if e = n.Use("", until, now); e == nil {
		t.Fatal("empty nonce")
	}
	if e = n.Use("two", now.Add(3*time.Minute), until); e != nil {
		t.Fatal(e)
	}
	if len(n.seen) != 1 {
		t.Fatal("expired nonce not pruned", n.seen)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if e = os.WriteFile(bad, []byte("null"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenNonceStore(bad); e == nil {
		t.Fatal("corrupt store accepted")
	}
}
func TestPersistentOrderKey(t *testing.T) {
	dir := t.TempDir()
	a, e := LoadOrCreateOrderKey(dir)
	if e != nil {
		t.Fatal(e)
	}
	b, e := LoadOrCreateOrderKey(dir)
	if e != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("key changed", e)
	}
	if len(Fingerprint(a.Public().(ed25519.PublicKey))) != 64 {
		t.Fatal("bad fingerprint")
	}
}
