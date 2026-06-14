package tls13gm

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

func benchSM2Cert(b *testing.B) (*x509.Certificate, *sm2.PrivateKey) {
	b.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost"},
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return cert, priv
}

// BenchmarkFullHandshake measures a complete client-side handshake (HandleServerFlight +
// ClientFinished), which exercises ECDHE, the HKDF key schedule, transcript hashing,
// CertificateVerify, and Finished MAC.
func BenchmarkFullHandshake(b *testing.B) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	cert, serverKey := benchSM2Cert(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewServerHandshaker(dcid, cert, serverKey)
		if err != nil {
			b.Fatal(err)
		}
		client, err := NewClientHandshakerWithConfig(ClientConfig{DCID: dcid, InsecureSkipVerify: true})
		if err != nil {
			b.Fatal(err)
		}
		ch, err := client.ClientHello()
		if err != nil {
			b.Fatal(err)
		}
		if err := server.HandleClientHello(ch); err != nil {
			b.Fatal(err)
		}
		sh, ee, certMsg, cv, fin, err := server.ServerFlight()
		if err != nil {
			b.Fatal(err)
		}
		if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
			b.Fatal(err)
		}
		if _, err := client.ClientFinished(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTranscriptRehash quantifies the cost of the current Transcript design:
// each DeriveSecret/Finished computation hashes the ENTIRE accumulated buffer from
// scratch (sm3.Sum(t.buf)), instead of maintaining an incremental hash state. A
// real handshake calls this ~8-10 times over a transcript that grows to ~1 KB.
func BenchmarkTranscriptRehash(b *testing.B) {
	// Simulate a late-handshake transcript (~1 KB: ClientHello+ServerHello+
	// EncryptedExtensions+Certificate+CertificateVerify+Finished).
	t := NewTranscript()
	body := make([]byte, 200)
	for j := 0; j < 5; j++ {
		t.AddMessage(HandshakeTypeCertificate, body)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 8 full rehashes, as in DeriveSecret over the growing transcript.
		for k := 0; k < 8; k++ {
			_ = t.Sum()
		}
	}
}
