package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	polluxQUIC "github.com/iuboy/pollux-go/quic"
)

func mustGenerateQUICCerts(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "quic-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	pool := x509.NewCertPool()
	poolPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool.AppendCertsFromPEM(poolPEM)
	return cert, pool
}

func getFreeUDPPort(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().String()
}

func TestBlackBox_QUIC_EchoRoundTrip(t *testing.T) {
	cert, pool := mustGenerateQUICCerts(t)
	addr := getFreeUDPPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := polluxQUIC.Listen(ctx, polluxQUIC.ServerConfig{
		Addr:         addr,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"echo-test"},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		srvConn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer srvConn.Close()

		stream, err := srvConn.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer stream.Close()

		_, _ = io.Copy(stream, stream)
	}()

	clientConn, err := polluxQUIC.Dial(ctx, polluxQUIC.ClientConfig{
		Addr:               addr,
		ServerName:         "localhost",
		RootCAs:            pool,
		NextProtos:         []string{"echo-test"},
		InsecureSkipVerify: false,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	stream, err := clientConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	msg := []byte("QUIC echo test")
	_, _ = stream.Write(msg)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo: got %q, want %q", buf, msg)
	}
}

func TestBlackBox_QUIC_EmptyALPNRejected(t *testing.T) {
	cert, _ := mustGenerateQUICCerts(t)
	ctx := context.Background()

	_, err := polluxQUIC.Listen(ctx, polluxQUIC.ServerConfig{
		Addr:         "127.0.0.1:0",
		Certificates: []tls.Certificate{cert},
		NextProtos:   nil,
	})
	if err == nil {
		t.Error("Listen with empty ALPN should fail")
	}

	_, err = polluxQUIC.Dial(ctx, polluxQUIC.ClientConfig{
		Addr:               "127.0.0.1:0",
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         nil,
	})
	if err == nil {
		t.Error("Dial with empty ALPN should fail")
	}
}

func TestBlackBox_QUIC_NoServerNameRejected(t *testing.T) {
	_, err := polluxQUIC.Dial(context.Background(), polluxQUIC.ClientConfig{
		Addr:       "127.0.0.1:0",
		NextProtos: []string{"test"},
	})
	if err == nil {
		t.Error("Dial without ServerName should fail")
	}
}
