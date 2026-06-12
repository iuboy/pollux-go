package test

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxTlcp "github.com/iuboy/pollux-go/tlcp"
)

const certPassword = "test123"

// certPath returns the absolute path to a test certificate file.
func certPath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, "cert", name)
}

// readCert reads a test certificate file.
func readCert(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(certPath(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

// loadSM2KeyPair loads an SM2 private key + certificate pair for TLCP.
func loadSM2KeyPair(t *testing.T, keyFile, certFile string) (*tls.Certificate, error) {
	t.Helper()
	keyPEM := readCert(t, keyFile)
	certPEM := readCert(t, certFile)

	key, err := polluxSM2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatalf("decode cert PEM: %s", certFile)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  key,
	}, nil
}

// buildTLCPConfig builds a TLCP config from Tongsuo-generated SM2 dual certs.
func buildTLCPConfig(t *testing.T) *polluxTlcp.Config {
	t.Helper()
	signCert, err := loadSM2KeyPair(t, "sm2_sign_key.pem", "sm2_sign_cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	encCert, err := loadSM2KeyPair(t, "sm2_enc_key.pem", "sm2_enc_cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	return &polluxTlcp.Config{
		SignCertificate:    signCert,
		EncCertificate:     encCert,
		CipherSuites:       []uint16{polluxTlcp.SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}
}

// echoHandler returns a simple HTTP handler that responds with path + method.
func echoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path))
	}
}

// getFreeAddr returns a free TCP address on 127.0.0.1.
func getFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// serverErr tracks a server goroutine error for deferred checking.
type serverErr struct {
	mu  sync.Mutex
	err error
}

func (s *serverErr) set(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *serverErr) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		t.Errorf("server goroutine error: %v", s.err)
	}
}
