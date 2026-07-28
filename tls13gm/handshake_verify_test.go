package tls13gm

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

// runServerFlight drives the client's ClientHello, feeds it to a fresh server,
// and returns the resulting server flight. Calling client.ClientHello() here
// records the message in the client's transcript, keeping both sides in lockstep
// so CertificateVerify verifies when the client later consumes the flight.
func runServerFlight(t *testing.T, dcid []byte, cert *x509.Certificate, serverKey *sm2.PrivateKey, client *ClientHandshaker) (sh, ee, certMsg, cv, fin []byte) {
	t.Helper()
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("client ClientHello: %v", err)
	}
	server, err := NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatalf("NewServerHandshaker: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}
	sh, ee, certMsg, cv, fin, err = server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	return sh, ee, certMsg, cv, fin
}

// TestClientHandshake_PKIVerification_Succeeds verifies that a client configured
// with a trusted root pool and matching hostname completes the handshake.
func TestClientHandshake_PKIVerification_Succeeds(t *testing.T) {
	dcid := []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	cert, serverKey := generateTestSM2Cert(t)

	roots := smx509.NewCertPool()
	roots.AddCert(cert)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:       dcid,
		ServerName: "localhost",
		Roots:      roots,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	sh, ee, certMsg, cv, fin := runServerFlight(t, dcid, cert, serverKey, client)
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("HandleServerFlight with valid PKI failed: %v", err)
	}
}

// TestClientHandshake_RejectsMissingRoots verifies the fail-closed guarantee:
// omitting Roots (without InsecureSkipVerify) is rejected at construction.
func TestClientHandshake_RejectsMissingRoots(t *testing.T) {
	_, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:       []byte{0x01, 0x02, 0x03, 0x04},
		ServerName: "localhost",
		// Roots intentionally nil, InsecureSkipVerify false
	})
	if err == nil {
		t.Fatal("expected error when Roots is nil and InsecureSkipVerify is false")
	}
}

// TestClientHandshake_RejectsHostnameMismatch verifies a hostname that does not
// match the leaf's SAN is rejected during HandleServerFlight.
func TestClientHandshake_RejectsHostnameMismatch(t *testing.T) {
	dcid := []byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8}
	cert, serverKey := generateTestSM2Cert(t)

	roots := smx509.NewCertPool()
	roots.AddCert(cert)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:       dcid,
		ServerName: "evil.example.com",
		Roots:      roots,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	sh, ee, certMsg, cv, fin := runServerFlight(t, dcid, cert, serverKey, client)
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err == nil {
		t.Fatal("client accepted a hostname mismatch")
	}
}

// TestClientHandshake_RejectsExpiredCert verifies an expired leaf is rejected.
func TestClientHandshake_RejectsExpiredCert(t *testing.T) {
	dcid := []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8}

	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expired pollux-go test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired yesterday
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost"},
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create expired certificate: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse expired certificate: %v", err)
	}

	roots := smx509.NewCertPool()
	roots.AddCert(cert)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:       dcid,
		ServerName: "localhost",
		Roots:      roots,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	sh, ee, certMsg, cv, fin := runServerFlight(t, dcid, cert, priv, client)
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err == nil {
		t.Fatal("client accepted an expired certificate")
	}
}

// TestClientHandshake_RejectsUntrustedRoot verifies a self-signed leaf not in
// the Roots pool is rejected (defense against trusting arbitrary self-signed
// certs even when Roots is configured).
func TestClientHandshake_RejectsUntrustedRoot(t *testing.T) {
	dcid := []byte{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8}
	cert, serverKey := generateTestSM2Cert(t)

	// Roots is non-empty but holds a DIFFERENT self-signed cert, not the peer's.
	decoy, _ := generateTestSM2Cert(t)
	roots := smx509.NewCertPool()
	roots.AddCert(decoy)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:       dcid,
		ServerName: "localhost",
		Roots:      roots,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	sh, ee, certMsg, cv, fin := runServerFlight(t, dcid, cert, serverKey, client)
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err == nil {
		t.Fatal("client accepted a certificate with no chain to a trusted root")
	}
}

// TestClientHandshake_VerifyPeerCertificate verifies the pinning hook is
// invoked and can reject a peer even when chain verification would pass.
func TestClientHandshake_VerifyPeerCertificate(t *testing.T) {
	dcid := []byte{0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8}
	cert, serverKey := generateTestSM2Cert(t)

	roots := smx509.NewCertPool()
	roots.AddCert(cert)

	pinned := errors.New("pin mismatch")
	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                  dcid,
		ServerName:            "localhost",
		Roots:                 roots,
		VerifyPeerCertificate: func(rawCerts [][]byte) error { return pinned },
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	sh, ee, certMsg, cv, fin := runServerFlight(t, dcid, cert, serverKey, client)
	err = client.HandleServerFlight(sh, ee, certMsg, cv, fin)
	if !errors.Is(err, pinned) {
		t.Fatalf("expected pin mismatch error, got %v", err)
	}
}
