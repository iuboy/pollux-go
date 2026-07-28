package quicgm

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

func generateSM2ServerCert(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2 GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quicgm test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("smx509 CreateCertificate: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("smx509 ParseCertificate: %v", err)
	}
	return cert, priv
}

// TestListen_Dial_StreamEcho is the Route C end-to-end smoke test: a real UDP
// QUIC handshake (RFC 8998 SM4-GCM-SM3) between quicgm.Listen and quicgm.Dial,
// followed by a single bidirectional stream echo. It exercises the whole stack
// — GMCryptoSetup driving tls13gm, the gm_sealer adapters, CRYPTO-frame
// reassembly, and transport-parameter exchange — without any crypto/tls.
func TestListen_Dial_StreamEcho(t *testing.T) {
	cert, key := generateSM2ServerCert(t)

	ln, err := Listen(context.Background(), ServerConfig{
		Addr:           "127.0.0.1:0",
		Certificate:    cert,
		PrivateKey:     key,
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverErr <- err
			return
		}
		// Echo: buffer the full request (client half-closes its write side to
		// signal EOF), then write it back.
		data, err := io.ReadAll(stream)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := stream.Write(data); err != nil {
			serverErr <- err
			return
		}
		// Close the stream (sends FIN) but leave the connection open so the
		// echo isn't racing a CONNECTION_CLOSE. The connection is torn down
		// when the client closes (or the idle timeout fires).
		stream.Close()
		serverErr <- nil
	}()

	conn, err := Dial(context.Background(), ClientConfig{
		Addr:               ln.Addr().String(),
		InsecureSkipVerify: true,
		MaxIdleTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	stream, err := conn.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	msg := []byte("hello gm quic")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	// Half-close the write side so the server's io.ReadAll returns.
	if err := stream.Close(); err != nil {
		t.Fatalf("client stream Close: %v", err)
	}

	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatalf("client read echo: %v", err)
	}
	if string(echo) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", echo, msg)
	}

	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("server goroutine: %v", err)
	}
}
