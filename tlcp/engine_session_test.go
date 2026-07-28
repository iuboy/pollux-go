package tlcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// TestNative_Resume_NativeServer verifies session resumption end-to-end: a
// full handshake populates the server's session cache, then a second
// connection (offering the same sessionId) resumes without a full handshake.
// didResume is asserted on the second connection.
func TestNative_Resume_NativeServer(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	signPriv := signCert.PrivateKey.(*polluxSM2.PrivateKey)
	encPriv := encCert.PrivateKey.(*polluxSM2.PrivateKey)

	sharedCache := NewTLCPLRUSessionCache(8)

	serverConfig := &tlcpEngineConfig{
		rand:         rand.Reader,
		cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		serverCerts: &tlcpServerCerts{
			signCertDER:  signCert.Certificate[0],
			encCertDER:   encCert.Certificate[0],
			signSigner:   signPriv,
			encDecrypter: encPriv,
		},
		sessionCache: sharedCache,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{}, 2)
	serve := func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(10 * time.Second))
		conn := newTLCPConn(rawConn, serverConfig, false)
		if err := conn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			t.Errorf("server write: %v", err)
			return
		}
		serverDone <- struct{}{}
	}
	go serve()
	go serve()

	// First connection: full handshake (populates the cache).
	c1Config := &tlcpEngineConfig{
		rand:               rand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		insecureSkipVerify: true,
		sessionCache:       sharedCache,
	}
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	c1.SetDeadline(time.Now().Add(10 * time.Second))
	conn1 := newTLCPConn(c1, c1Config, true)
	if err := conn1.Handshake(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if conn1.didResume {
		t.Error("first connection should be a full handshake, not a resume")
	}
	msg := []byte("first connection full handshake")
	conn1.Write(msg)
	echo := make([]byte, len(msg))
	io.ReadFull(conn1, echo)
	conn1.Close()
	<-serverDone

	// Second connection: should resume (server cache hit).
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	c2.SetDeadline(time.Now().Add(10 * time.Second))
	conn2 := newTLCPConn(c2, c1Config, true)
	if err := conn2.Handshake(); err != nil {
		t.Fatalf("second handshake (resume): %v", err)
	}
	if !conn2.didResume {
		t.Error("second connection should have resumed, but didResume is false")
	}
	msg2 := []byte("second connection resumed handshake")
	conn2.Write(msg2)
	echo2 := make([]byte, len(msg2))
	io.ReadFull(conn2, echo2)
	if !bytes.Equal(echo2, msg2) {
		t.Errorf("resume echo mismatch")
	}
	conn2.Close()
	<-serverDone
}
