//go:build tlcp_native && integration

package tlcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
)

// TestNativeClient_VS_GotlcpServer drives a native tlcpConn client against a
// gotlcp server and verifies a full ECC handshake + bidirectional data
// transfer. This is the key Phase 3 milestone: the native client must
// interoperate with the reference implementation.
func TestNativeClient_VS_GotlcpServer(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	gotlcpConfig := &gotlcp.Config{
		Certificates: []gotlcp.Certificate{
			{Certificate: [][]byte{signCert.Certificate[0]}, PrivateKey: signCert.PrivateKey},
			{Certificate: [][]byte{encCert.Certificate[0]}, PrivateKey: encCert.PrivateKey},
		},
		CipherSuites:       []uint16{gotlcp.ECC_SM4_GCM_SM3, gotlcp.ECC_SM4_CBC_SM3},
		InsecureSkipVerify: true,
	}

	listener, err := gotlcp.Listen("tcp", "127.0.0.1:0", gotlcpConfig)
	if err != nil {
		t.Fatalf("gotlcp listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		// Echo: read once, write it back, then close.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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

	nativeConfig := &tlcpEngineConfig{
		rand:               rand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3},
		insecureSkipVerify: true,
	}
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	client := newTLCPConn(rawConn, nativeConfig, true)

	if err := client.Handshake(); err != nil {
		t.Fatalf("native client handshake: %v", err)
	}

	// Bidirectional data: write then read back an echo.
	message := []byte("hello TLCP from native client")
	if _, err := client.Write(message); err != nil {
		t.Fatalf("client write: %v", err)
	}
	echoed := make([]byte, len(message))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(echoed, message) {
		t.Errorf("echo mismatch:\n got %q\n want %q", echoed, message)
	}

	client.Close()
	if err := <-serverErr; err != nil {
		t.Errorf("server error: %v", err)
	}
}
