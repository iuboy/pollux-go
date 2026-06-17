//go:build integration

package quicgm

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
	"github.com/iuboy/pollux-go/tls13gm"
)

// generateSelfSignedSM2 builds a self-signed SM2 certificate for the
// end-to-end handshake test.
func generateSelfSignedSM2(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SM2 key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pollux-go e2e test"},
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

// TestHandshake_DrivesKeyLevels is the Route C end-to-end test: a full TLS 1.3
// GM handshake drives three QUIC encryption levels, and the resulting keys
// protect Initial, Handshake, and 1-RTT packets carrying CRYPTO frames — with
// tamper rejection and cross-level isolation enforced.
func TestHandshake_DrivesKeyLevels(t *testing.T) {
	dcid := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11}
	cert, serverKey := generateSelfSignedSM2(t)

	server, err := tls13gm.NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatalf("NewServerHandshaker: %v", err)
	}
	client, err := tls13gm.NewClientHandshaker(dcid, cert)
	if err != nil {
		t.Fatalf("NewClientHandshaker: %v", err)
	}

	// --- Drive the handshake over an in-memory pipe ---
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("client HandleServerFlight: %v", err)
	}
	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server HandleClientFinished: %v", err)
	}

	cs := client.Secrets()
	ss := server.Secrets()

	// --- Key isolation: the three encryption levels must derive distinct keys.
	// Cross-level Seal/Open rejection (below) proves this functionally; this
	// asserts it directly so a key-derivation collision fails loudly here.
	if bytes.Equal(cs.ClientHandshakeKeys.AEADKey, cs.ClientApplicationKeys.AEADKey) {
		t.Fatal("Handshake and Application AEAD keys collide")
	}
	if bytes.Equal(cs.ClientInitialKeys.AEADKey, cs.ClientHandshakeKeys.AEADKey) {
		t.Fatal("Initial and Handshake AEAD keys collide")
	}

	// --- Initial level: client-sealed, server-opened (CRYPTO frame payload) ---
	var initPayload []byte
	initPayload, err = AppendCryptoFrame(initPayload, 0, ch)
	if err != nil {
		t.Fatal(err)
	}
	initialPkt, err := SealInitialPacket(dcid, []byte("srv-scid"), nil, 0, initPayload)
	if err != nil {
		t.Fatalf("SealInitialPacket: %v", err)
	}
	_, _, _, initPN, initPayloadBack, err := OpenInitialPacket(dcid, initialPkt)
	if err != nil {
		t.Fatalf("OpenInitialPacket: %v", err)
	}
	_, chBack, _, err := ReadCryptoFrame(initPayloadBack)
	if err != nil {
		t.Fatalf("read CRYPTO from Initial: %v", err)
	}
	if !bytes.Equal(chBack, ch) {
		t.Fatal("ClientHello carried in Initial CRYPTO frame was corrupted")
	}
	_ = initPN

	// --- Handshake level: server-sealed (s_hs), client-opened ---
	var hsPayload []byte
	hsPayload, err = AppendCryptoFrame(hsPayload, 0, append(append(sh, ee...), append(append(certMsg, cv...), fin...)...))
	if err != nil {
		t.Fatal(err)
	}
	hsPkt, err := SealHandshakePacket(ss.ServerHandshakeKeys, dcid, []byte("srv-scid"), 1, hsPayload)
	if err != nil {
		t.Fatalf("SealHandshakePacket: %v", err)
	}
	_, _, hsPN, hsPayloadBack, err := OpenHandshakePacket(cs.ServerHandshakeKeys, dcid, hsPkt)
	if err != nil {
		t.Fatalf("OpenHandshakePacket: %v", err)
	}
	if hsPN != 1 {
		t.Errorf("Handshake pn: got %d, want 1", hsPN)
	}
	if !bytes.Equal(hsPayloadBack, hsPayload) {
		t.Fatal("Handshake payload mismatch")
	}

	// --- 1-RTT level: client-sealed (c_ap), server-opened ---
	rttPayload := []byte("application data over 1-RTT")
	rttPkt, err := Seal1RTTPacket(cs.ClientApplicationKeys, dcid, 9, PacketNumberLen2, rttPayload)
	if err != nil {
		t.Fatalf("Seal1RTTPacket: %v", err)
	}
	rttPN, rttPayloadBack, err := Open1RTTPacket(ss.ClientApplicationKeys, dcid, nil, rttPkt)
	if err != nil {
		t.Fatalf("Open1RTTPacket: %v", err)
	}
	if rttPN != 9 {
		t.Errorf("1-RTT pn: got %d, want 9", rttPN)
	}
	if !bytes.Equal(rttPayloadBack, rttPayload) {
		t.Fatal("1-RTT payload mismatch")
	}

	// --- Cross-level isolation: 1-RTT packet cannot be opened with Handshake keys ---
	if _, _, err := Open1RTTPacket(cs.ClientHandshakeKeys, dcid, nil, rttPkt); err == nil {
		t.Fatal("1-RTT packet opened with Handshake keys — level isolation broken")
	}
	// --- Direction isolation: client HS keys cannot open a server-HS-sealed packet ---
	if _, _, _, _, err := OpenHandshakePacket(cs.ClientHandshakeKeys, dcid, hsPkt); err == nil {
		t.Fatal("server Handshake packet opened with client Handshake keys — direction isolation broken")
	}
	// --- Tamper rejection on 1-RTT ---
	rttPkt[len(rttPkt)-1] ^= 0xFF
	if _, _, err := Open1RTTPacket(ss.ClientApplicationKeys, dcid, nil, rttPkt); err == nil {
		t.Fatal("tampered 1-RTT packet was accepted")
	}
}
