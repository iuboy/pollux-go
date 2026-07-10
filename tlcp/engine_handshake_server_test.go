//go:build tlcp_native && integration

package tlcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// TestGotlcpClient_VS_NativeServer drives a gotlcp client against a native
// tlcpConn server and verifies a full ECC handshake + bidirectional data
// transfer. The counterpart to Phase 3's native-client-vs-gotlcp-server test.
func TestGotlcpClient_VS_NativeServer(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	// The native server needs crypto.Signer (sign key) and crypto.Decrypter
	// (enc key). generateTestCertPair produces *tls.Certificate whose PrivateKey
	// is *sm2.PrivateKey — which implements both.
	signPriv, ok := signCert.PrivateKey.(*polluxSM2.PrivateKey)
	if !ok {
		t.Fatalf("sign key is %T, want *sm2.PrivateKey", signCert.PrivateKey)
	}
	encPriv, ok := encCert.PrivateKey.(*polluxSM2.PrivateKey)
	if !ok {
		t.Fatalf("enc key is %T, want *sm2.PrivateKey", encCert.PrivateKey)
	}

	serverConfig := &tlcpEngineConfig{
		rand:         rand.Reader,
		cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3},
		serverCerts: &tlcpServerCerts{
			signCertDER:   signCert.Certificate[0],
			encCertDER:    encCert.Certificate[0],
			signSigner:    signPriv,
			encDecrypter:  encPriv,
		},
	}

	// Native server: accept on a TCP listener, wrap with tlcpConn (server mode),
	// echo once, then close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(10 * time.Second))
		conn := newTLCPConn(rawConn, serverConfig, false)
		if err := conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		// Echo one read then write back.
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	// gotlcp client.
	gotlcpClientConfig := &gotlcp.Config{
		CipherSuites:       []uint16{gotlcp.ECC_SM4_GCM_SM3, gotlcp.ECC_SM4_CBC_SM3},
		InsecureSkipVerify: true,
	}
	conn, err := gotlcp.Dial("tcp", ln.Addr().String(), gotlcpClientConfig)
	if err != nil {
		t.Fatalf("gotlcp dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	message := []byte("hello native server from gotlcp client")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("gotlcp client write: %v", err)
	}
	echoed := make([]byte, len(message))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("gotlcp client read: %v", err)
	}
	if !bytes.Equal(echoed, message) {
		t.Errorf("echo mismatch:\n got %q\n want %q", echoed, message)
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// TestNativeClient_VS_NativeServer drives a native client against a native
// server — the end-to-end self-consistency check (both sides pollux code).
func TestNativeClient_VS_NativeServer(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	signPriv := signCert.PrivateKey.(*polluxSM2.PrivateKey)
	encPriv := encCert.PrivateKey.(*polluxSM2.PrivateKey)

	serverConfig := &tlcpEngineConfig{
		rand:         rand.Reader,
		cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3},
		serverCerts: &tlcpServerCerts{
			signCertDER:  signCert.Certificate[0],
			encCertDER:   encCert.Certificate[0],
			signSigner:   signPriv,
			encDecrypter: encPriv,
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(10 * time.Second))
		conn := newTLCPConn(rawConn, serverConfig, false)
		if err := conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	clientConfig := &tlcpEngineConfig{
		rand:               rand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3},
		insecureSkipVerify: true,
	}
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	client := newTLCPConn(rawConn, clientConfig, true)
	if err := client.Handshake(); err != nil {
		t.Fatalf("native client handshake: %v", err)
	}

	message := []byte("native-to-native round trip")
	if _, err := client.Write(message); err != nil {
		t.Fatalf("native client write: %v", err)
	}
	echoed := make([]byte, len(message))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatalf("native client read: %v", err)
	}
	if !bytes.Equal(echoed, message) {
		t.Errorf("echo mismatch:\n got %q\n want %q", echoed, message)
	}
	client.Close()
	if err := <-serverErr; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// keep imports honest if a conditional path drops them.
var _ = ecdsa.PublicKey{}
