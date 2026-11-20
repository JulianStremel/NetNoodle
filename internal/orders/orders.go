// Package orders signs exact order bytes and persists actor replay protection.
package orders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

type Envelope struct {
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

func Sign(priv ed25519.PrivateKey, order proto.Order) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid order private key")
	}
	b, err := json.Marshal(order)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{b, ed25519.Sign(priv, b)}, nil
}
func Verify(pub ed25519.PublicKey, env Envelope) (proto.Order, error) {
	var o proto.Order
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, env.Payload, env.Sig) {
		return o, errors.New("invalid order signature")
	}
	d := json.NewDecoder(bytes.NewReader(env.Payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing order JSON")
	}
	if o.Version != proto.Version {
		return o, errors.New("unsupported order version")
	}
	return o, nil
}
func PublicKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// LoadOrCreateOrderKey uses dataDir/keys/order-ed25519.pem, in PKCS#8 format.
func LoadOrCreateOrderKey(dataDir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dataDir, "keys", "order-ed25519.pem")
	b, err := os.ReadFile(path)
	if err == nil {
		p, _ := pem.Decode(b)
		if p == nil || p.Type != "PRIVATE KEY" {
			return nil, errors.New("invalid order PEM")
		}
		k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
		if e != nil {
			return nil, e
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("order key is not Ed25519")
		}
		if e = os.Chmod(path, 0600); e != nil {
			return nil, e
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateOrderKey(dataDir)
	}
	if err != nil {
		return nil, err
	}
	_, err = f.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	return priv, err
}

type NonceStore struct {
	mu   sync.Mutex
	path string
	seen map[string]time.Time
}

func OpenNonceStore(path string) (*NonceStore, error) {
	n := &NonceStore{path: path, seen: map[string]time.Time{}}
	b, e := os.ReadFile(path)
	if e == nil {
		e = json.Unmarshal(b, &n.seen)
		if n.seen == nil {
			e = errors.New("invalid nonce store")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	return n, e
}

// Use commits the nonce before execution. Failed persistence denies execution.
// One actor process must exclusively own a nonce file.
func (n *NonceStore) Use(nonce string, notAfter, now time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if nonce == "" || !notAfter.After(now) {
		return errors.New("empty nonce or expired order")
	}
	next := map[string]time.Time{}
	for k, v := range n.seen {
		if v.After(now) {
			next[k] = v
		}
	}
	if _, ok := next[nonce]; ok {
		return errors.New("nonce replay")
	}
	next[nonce] = notAfter
	if e := os.MkdirAll(filepath.Dir(n.path), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(n.path), ".nonces-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(f.Name(), n.path)
	}
	if e == nil {
		n.seen = next
	}
	return e
}
