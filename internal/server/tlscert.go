package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreateCert loads data/tls/{cert,key}.pem, or creates a self-signed
// certificate on first start. Clients pin the returned SHA-256 fingerprint
// of the certificate, so the host names in it do not matter for them.
func LoadOrCreateCert(dataDir string) (tls.Certificate, string, error) {
	dir := filepath.Join(dataDir, "tls")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := createSelfSigned(dir, certPath, keyPath, x509.ExtKeyUsageServerAuth); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return cert, "", err
	}
	return cert, Fingerprint(cert.Certificate[0]), nil
}

// Fingerprint is the lower-case hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// LoadOrCreatePullCert loads or creates the client certificate that the
// server presents to pull agents (data/tls/pull-client-{cert,key}.pem).
// Pull agents pin its fingerprint. It is separate from the HTTPS server
// key, so each one can be replaced alone.
func LoadOrCreatePullCert(dataDir string) (tls.Certificate, string, error) {
	dir := filepath.Join(dataDir, "tls")
	certPath := filepath.Join(dir, "pull-client-cert.pem")
	keyPath := filepath.Join(dir, "pull-client-key.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := createSelfSigned(dir, certPath, keyPath, x509.ExtKeyUsageClientAuth); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return cert, "", err
	}
	return cert, Fingerprint(cert.Certificate[0]), nil
}

func createSelfSigned(dir, certPath, keyPath string, usage x509.ExtKeyUsage) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "netnoodle " + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
