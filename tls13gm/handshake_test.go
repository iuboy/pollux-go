package tls13gm

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

// generateTestSM2Cert builds a self-signed SM2 certificate for handshake tests
// and returns the parsed certificate (with .Raw populated) and its private key.
func generateTestSM2Cert(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pollux-go handshake test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost"},
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, priv
}

func keysNonZero(k *QUICPacketKeys) bool {
	return k != nil && len(k.AEADKey) > 0 && len(k.AEADIV) > 0 && len(k.HeaderKey) > 0
}

// TestHandshake_RoundTrip drives a full TLS 1.3 GM handshake between a
// ServerHandshaker and ClientHandshaker through an in-memory pipe, then asserts
// the two sides derive identical three-level secrets and that all keys are
// non-empty.
func TestHandshake_RoundTrip(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cert, serverKey := generateTestSM2Cert(t)

	server, err := NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatalf("NewServerHandshaker: %v", err)
	}
	client, err := NewClientHandshaker(dcid, cert)
	if err != nil {
		t.Fatalf("NewClientHandshaker: %v", err)
	}

	// Initial keys are derived from the DCID, so both sides must agree.
	if !bytes.Equal(client.Secrets().ClientInitialKeys.AEADKey, server.Secrets().ClientInitialKeys.AEADKey) {
		t.Fatal("client/server Initial client keys differ")
	}

	// Client -> Server: ClientHello
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}

	// Server -> Client: flight
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("client HandleServerFlight: %v", err)
	}

	// Handshake keys must now match between the two sides.
	cs := client.Secrets()
	ss := server.Secrets()
	if !bytes.Equal(cs.ClientHandshakeKeys.AEADKey, ss.ClientHandshakeKeys.AEADKey) {
		t.Fatal("Handshake client keys differ")
	}
	if !bytes.Equal(cs.ServerHandshakeKeys.AEADKey, ss.ServerHandshakeKeys.AEADKey) {
		t.Fatal("Handshake server keys differ")
	}

	// Client -> Server: client Finished
	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server HandleClientFinished: %v", err)
	}

	// Application keys must match.
	if !bytes.Equal(cs.ClientApplicationKeys.AEADKey, ss.ClientApplicationKeys.AEADKey) {
		t.Fatal("Application client keys differ")
	}
	if !bytes.Equal(cs.ServerApplicationKeys.AEADKey, ss.ServerApplicationKeys.AEADKey) {
		t.Fatal("Application server keys differ")
	}

	// All three levels must be non-empty and pairwise distinct.
	for _, k := range []*QUICPacketKeys{
		cs.ClientInitialKeys, ss.ServerInitialKeys,
		cs.ClientHandshakeKeys, ss.ServerHandshakeKeys,
		cs.ClientApplicationKeys, ss.ServerApplicationKeys,
	} {
		if !keysNonZero(k) {
			t.Fatal("derived packet keys are empty")
		}
	}
	if bytes.Equal(cs.ClientHandshakeKeys.AEADKey, cs.ClientApplicationKeys.AEADKey) {
		t.Fatal("Handshake and Application keys collide")
	}
	if bytes.Equal(cs.ClientHandshakeKeys.AEADKey, cs.ClientInitialKeys.AEADKey) {
		t.Fatal("Handshake and Initial keys collide")
	}
}

// TestHandshake_RejectsTamperedServerFinished verifies the client rejects a
// server Finished whose verify_data has been corrupted.
func TestHandshake_RejectsTamperedServerFinished(t *testing.T) {
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	cert, serverKey := generateTestSM2Cert(t)
	server, err := NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientHandshaker(dcid, cert)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatal(err)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the last byte of the Finished message body.
	fin[len(fin)-1] ^= 0xFF
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err == nil {
		t.Fatal("client accepted corrupted server Finished")
	}
}
