package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	polluxHTTP "github.com/ycq/pollux/http"
)

func TestHybridServerTLSAndTLCP(t *testing.T) {
	tlcpConfig := buildTLCPConfig(t)

	// 使用 ECDSA P256 证书作为 TLS 证书（标准 TLS 不支持 SM2）
	tlsPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-hybrid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	tlsDER, err := x509.CreateCertificate(rand.Reader, tlsTpl, tlsTpl, &tlsPriv.PublicKey, tlsPriv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{tlsDER},
		PrivateKey:  tlsPriv,
	}
	tlsConfig2 := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	go func() {
		srv := &http.Server{Handler: echoHandler()}
		_ = srv.Serve(polluxHTTP.NewHybridListener(ln, tlcpConfig, tlsConfig2))
	}()
	time.Sleep(100 * time.Millisecond)

	// TLCP 客户端
	tlcpTransport, err := polluxHTTP.NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	tlcpClient := &http.Client{Transport: tlcpTransport}

	resp, err := tlcpClient.Get("https://" + addr + "/tlcp-path")
	if err != nil {
		t.Fatalf("TLCP GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("TLCP status: %d", resp.StatusCode)
	}

	// TLS 客户端
	tlsTransport := polluxHTTP.NewTLSTransport(&tls.Config{InsecureSkipVerify: true})
	tlsClient := &http.Client{Transport: tlsTransport}

	resp2, err := tlsClient.Get("https://" + addr + "/tls-path")
	if err != nil {
		t.Fatalf("TLS GET: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("TLS status: %d", resp2.StatusCode)
	}
}

func TestHybridAutoDetect(t *testing.T) {
	opts := &polluxHTTP.ServerOptions{
		Addr:    getFreeAddr(t),
		Handler: echoHandler(),
	}

	err := opts.LoadTLCPCertificates(
		certPath("sm2_sign_cert.pem"), certPath("sm2_sign_key.pem"),
		certPath("sm2_enc_cert.pem"), certPath("sm2_enc_key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}

	mode := opts.DetectMode()
	if mode != polluxHTTP.ModeTLCP {
		t.Errorf("SM2 certs should detect as ModeTLCP, got %v", mode)
	}
}
