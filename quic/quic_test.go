package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func TestServerConfig_EmptyALPN(t *testing.T) {
	_, err := Listen(context.Background(), ServerConfig{
		Addr:         "127.0.0.1:0",
		Certificates: []tls.Certificate{generateTestCert(t)},
	})
	if err == nil {
		t.Error("empty ALPN should fail")
	}
}

func TestClientConfig_EmptyALPN(t *testing.T) {
	_, err := Dial(context.Background(), ClientConfig{
		Addr: "127.0.0.1:0",
	})
	if err == nil {
		t.Error("empty ALPN should fail")
	}
}

func TestClientConfig_NoServerName(t *testing.T) {
	_, err := Dial(context.Background(), ClientConfig{
		Addr:       "127.0.0.1:0",
		NextProtos: []string{"test"},
	})
	if err == nil {
		t.Error("no ServerName should fail")
	}
}

func TestQUIC_EchoRoundTrip(t *testing.T) {
	cert := generateTestCert(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := Listen(ctx, ServerConfig{
		Addr:         "127.0.0.1:0",
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"echo-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		sconn, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		defer sconn.Close()
		stream, aerr := sconn.AcceptStream(ctx)
		if aerr != nil {
			t.Log("server AcceptStream:", aerr)
			return
		}
		defer stream.Close()
		buf := make([]byte, 1024)
		n, rerr := stream.Read(buf)
		if rerr != nil {
			t.Log("server Read:", rerr)
			return
		}
		if _, werr := stream.Write(buf[:n]); werr != nil {
			t.Log("server Write:", werr)
			return
		}
		// Keep stream open until context done to allow client to read
		<-ctx.Done()
	}()

	tlsCfg, _ := (&ClientConfig{
		Addr:               ln.Addr().String(),
		ServerName:         "localhost",
		NextProtos:         []string{"echo-test"},
		InsecureSkipVerify: true,
	}).tlsConfig()

	qc, err := quic.DialAddr(ctx, ln.Addr().String(), tlsCfg, &quic.Config{
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	conn := &Conn{inner: qc}
	defer conn.Close()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	msg := []byte("hello quic")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("echo: got %q, want %q", string(buf[:n]), string(msg))
	}
}
