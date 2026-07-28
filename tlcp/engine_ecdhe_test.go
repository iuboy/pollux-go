package tlcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// makeECDHEDualCerts generates a fresh signing + encryption SM2 cert pair for
// use as either a server or client dual certificate set.
func makeECDHEDualCerts(t *testing.T) (signDER, encDER []byte, signPriv, encPriv *polluxSM2.PrivateKey) {
	t.Helper()
	curve := polluxSM2.P256()
	sPriv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	ePriv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	sm2Sign := new(polluxSM2.PrivateKey)
	sm2Sign.FromECPrivateKey(sPriv)
	sm2Enc := new(polluxSM2.PrivateKey)
	sm2Enc.FromECPrivateKey(ePriv)
	// Reuse generateTestCertPair's cert-creation by building minimal self-signed certs.
	sc, ec := generateTestCertPair(t)
	return sc.Certificate[0], ec.Certificate[0], sm2Sign, sm2Enc
}

// TestECDHE_NativeServer_NativeClient verifies an ECDHE (SM2 MQV) handshake
// with mutual authentication end-to-end, both sides native. This exercises the
// full ECDHE path: CertificateRequest, client Certificate + CertificateVerify,
// and SM2 MQV key agreement.
func TestECDHE_NativeServer_NativeClient(t *testing.T) {
	// Server dual certs.
	srvSignCert, srvEncCert := generateTestCertPair(t)
	srvSignPriv := srvSignCert.PrivateKey.(*polluxSM2.PrivateKey)
	srvEncPriv := srvEncCert.PrivateKey.(*polluxSM2.PrivateKey)

	// Client dual certs (ECDHE requires the client to present both).
	cliSignCert, cliEncCert := generateTestCertPair(t)
	cliSignPriv := cliSignCert.PrivateKey.(*polluxSM2.PrivateKey)
	cliEncPriv := cliEncCert.PrivateKey.(*polluxSM2.PrivateKey)

	serverConfig := &tlcpEngineConfig{
		rand:         rand.Reader,
		cipherSuites: []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		serverCerts: &tlcpServerCerts{
			signCertDER:  srvSignCert.Certificate[0],
			encCertDER:   srvEncCert.Certificate[0],
			signSigner:   srvSignPriv,
			encDecrypter: srvEncPriv,
		},
		insecureSkipVerify: true,
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
		_, err = conn.Write(buf[:n])
		serverErr <- err
	}()

	clientConfig := &tlcpEngineConfig{
		rand:               rand.Reader,
		cipherSuites:       []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		insecureSkipVerify: true,
		clientCerts: &tlcpServerCerts{
			signCertDER:  cliSignCert.Certificate[0],
			encCertDER:   cliEncCert.Certificate[0],
			signSigner:   cliSignPriv,
			encDecrypter: cliEncPriv,
		},
	}
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	client := newTLCPConn(rawConn, clientConfig, true)

	if err := client.Handshake(); err != nil {
		t.Fatalf("ECDHE client handshake: %v", err)
	}

	message := []byte("ECDHE SM2 MQV round trip")
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
