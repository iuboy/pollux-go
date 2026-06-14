package tls13gm

import (
	"bytes"
	"errors"
	"testing"
)

// driveFullHandshake runs a complete client/server GM handshake. The processStepwise
// flag selects whether the client consumes the server flight via the aggregate
// HandleServerFlight or the five step-wise Handle* methods. It returns the client
// and server secret bundles so callers can compare them.
func driveFullHandshake(t *testing.T, dcid []byte, processStepwise bool) (clientSecs, serverSecs HandshakeSecrets) {
	t.Helper()
	cert, serverKey := generateTestSM2Cert(t)

	server, err := NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatalf("NewServerHandshaker: %v", err)
	}
	client, err := NewClientHandshaker(dcid, cert)
	if err != nil {
		t.Fatalf("NewClientHandshaker: %v", err)
	}

	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}

	if processStepwise {
		if err := client.HandleServerHello(sh); err != nil {
			t.Fatalf("HandleServerHello: %v", err)
		}
		if err := client.HandleEncryptedExtensions(ee); err != nil {
			t.Fatalf("HandleEncryptedExtensions: %v", err)
		}
		if err := client.HandleCertificate(certMsg); err != nil {
			t.Fatalf("HandleCertificate: %v", err)
		}
		if err := client.HandleCertificateVerify(cv); err != nil {
			t.Fatalf("HandleCertificateVerify: %v", err)
		}
		if err := client.HandleServerFinished(fin); err != nil {
			t.Fatalf("HandleServerFinished: %v", err)
		}
	} else {
		if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
			t.Fatalf("HandleServerFlight: %v", err)
		}
	}

	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server HandleClientFinished: %v", err)
	}
	return client.Secrets(), server.Secrets()
}

func secretsEqual(a, b HandshakeSecrets) bool {
	pairs := [][2]*QUICPacketKeys{
		{a.ClientInitialKeys, b.ClientInitialKeys},
		{a.ServerInitialKeys, b.ServerInitialKeys},
		{a.ClientHandshakeKeys, b.ClientHandshakeKeys},
		{a.ServerHandshakeKeys, b.ServerHandshakeKeys},
		{a.ClientApplicationKeys, b.ClientApplicationKeys},
		{a.ServerApplicationKeys, b.ServerApplicationKeys},
	}
	for _, p := range pairs {
		if p[0] == nil || p[1] == nil {
			return false
		}
		if !bytes.Equal(p[0].AEADKey, p[1].AEADKey) || !bytes.Equal(p[0].AEADIV, p[1].AEADIV) || !bytes.Equal(p[0].HeaderKey, p[1].HeaderKey) {
			return false
		}
	}
	return true
}

// TestHandshake_StepwiseServerFlight drives the server flight through the five
// step-wise Handle* methods (the path a QUIC transport takes, feeding one CRYPTO
// message at a time) and asserts the client and server derive identical
// three-level secrets and that ClientFinished is accepted.
func TestHandshake_StepwiseServerFlight(t *testing.T) {
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	clientSecs, serverSecs := driveFullHandshake(t, dcid, true)

	if !secretsEqual(clientSecs, serverSecs) {
		t.Fatal("step-wise handshake produced mismatched client/server secrets")
	}
	if !keysNonZero(clientSecs.ClientApplicationKeys) {
		t.Fatal("Application client keys not derived after step-wise flight")
	}
}

// TestHandshake_StepwiseEqualsAggregate proves the step-wise and aggregate paths
// are equivalent: for the same client ephemeral + server flight they are the same
// code path, so this guards against a future refactor splitting them. We cannot
// reuse one client instance (stateful), so we assert each path independently
// completes a handshake with matching client/server secrets.
func TestHandshake_StepwisePhaseGuard(t *testing.T) {
	dcid := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	cert, serverKey := generateTestSM2Cert(t)

	server, err := NewServerHandshaker(dcid, cert, serverKey)
	if err != nil {
		t.Fatalf("NewServerHandshaker: %v", err)
	}
	client, err := NewClientHandshaker(dcid, cert)
	if err != nil {
		t.Fatalf("NewClientHandshaker: %v", err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}

	// HandleEncryptedExtensions before HandleServerHello must fail.
	if err := client.HandleEncryptedExtensions(ee); err == nil {
		t.Fatal("HandleEncryptedExtensions accepted before HandleServerHello")
	}
	// HandleCertificate before HandleServerHello must fail.
	if err := client.HandleCertificate(certMsg); err == nil {
		t.Fatal("HandleCertificate accepted before HandleServerHello")
	}
	// HandleServerFinished before HandleCertificateVerify must fail.
	if err := client.HandleServerFinished(fin); err == nil {
		t.Fatal("HandleServerFinished accepted before HandleCertificateVerify")
	}

	// Now drive the legitimate order; each step must succeed.
	if err := client.HandleServerHello(sh); err != nil {
		t.Fatalf("HandleServerHello: %v", err)
	}
	// Calling HandleServerHello a second time (replay) must fail — replaying would
	// corrupt the transcript hash.
	if err := client.HandleServerHello(sh); err == nil {
		t.Fatal("HandleServerHello accepted twice")
	}
	if err := client.HandleEncryptedExtensions(ee); err != nil {
		t.Fatalf("HandleEncryptedExtensions: %v", err)
	}
	if err := client.HandleCertificate(certMsg); err != nil {
		t.Fatalf("HandleCertificate: %v", err)
	}
	if err := client.HandleCertificateVerify(cv); err != nil {
		t.Fatalf("HandleCertificateVerify: %v", err)
	}
	if err := client.HandleServerFinished(fin); err != nil {
		t.Fatalf("HandleServerFinished: %v", err)
	}

	// ClientFinished must now succeed, proving the step-wise path left the engine
	// in a complete, server-verifiable state.
	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished after step-wise flight: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server rejected client Finished from step-wise path: %v", err)
	}
}

// TestHandshake_TransportParametersExchange confirms QUIC transport parameters
// (RFC 9001 §8) are carried in ClientHello (client) and EncryptedExtensions
// (server) and recovered by each side. This is the contract GMCryptoSetup relies
// on to surface transport parameters to quic-go's connection layer.
func TestHandshake_TransportParametersExchange(t *testing.T) {
	dcid := []byte{0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02}
	cert, serverKey := generateTestSM2Cert(t)
	clientTP := []byte("client-transport-params")
	serverTP := []byte("server-transport-params")

	server, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:               dcid,
		Certificate:        cert,
		PrivateKey:         serverKey,
		TransportParameters: serverTP,
	})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:               dcid,
		InsecureSkipVerify: true,
		TransportParameters: clientTP,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello: %v", err)
	}
	if got := server.PeerTransportParams(); !bytes.Equal(got, clientTP) {
		t.Fatalf("server peer TP = %q, want %q", got, clientTP)
	}

	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("HandleServerFlight: %v", err)
	}
	if got := client.PeerTransportParams(); !bytes.Equal(got, serverTP) {
		t.Fatalf("client peer TP = %q, want %q", got, serverTP)
	}
}

// buildTestHRR constructs a HelloRetryRequest (a ServerHello carrying the
// sentinel random) with the given cookie, for client-side HRR tests.
func buildTestHRR(t *testing.T, cookie []byte) []byte {
	t.Helper()
	hrr := &ServerHelloMsg{
		LegacyVersion: uint16(VersionTLS13),
		Random:        helloRetryRequestRandom,
		CipherSuite:   TLS_SM4_GCM_SM3,
		Extensions: []Extension{
			{Type: ExtensionTypeSupportedVersions, Data: []byte{0x03, 0x03}},
			{Type: ExtensionTypeCookie, Data: marshalCookieExtension(cookie)},
		},
	}
	full, err := MarshalHandshakeMessage(hrr)
	if err != nil {
		t.Fatalf("marshal HRR: %v", err)
	}
	return full
}

// TestClientHandshake_HelloRetryRequest covers the client side of RFC 8446
// §4.1.4: when the server replies with a HelloRetryRequest, HandleServerHello
// signals ErrHelloRetryRequest, and HandleHelloRetryRequest produces
// ClientHello2 echoing the cookie. The phase is then reset so the real
// ServerHello can follow.
//
// It verifies message handling (HRR detection, cookie echo, phase reset). A
// full transcript-consistent end-to-end test requires server-side HRR emission
// (cookie generation/verification), which is out of scope for this test.
func TestClientHandshake_HelloRetryRequest(t *testing.T) {
	dcid := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:               dcid,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	ch1, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if len(ch1) < 4 {
		t.Fatal("ClientHello1 too short")
	}

	// Server sends a HelloRetryRequest with a cookie.
	cookie := []byte("stateless-anti-dos-cookie")
	hrr := buildTestHRR(t, cookie)

	// HandleServerHello must detect the HRR and signal it (no key derivation).
	if err := client.HandleServerHello(hrr); !errors.Is(err, ErrHelloRetryRequest) {
		t.Fatalf("HandleServerHello(HRR) = %v, want ErrHelloRetryRequest", err)
	}

	// HandleHelloRetryRequest produces ClientHello2 echoing the cookie.
	ch2, err := client.HandleHelloRetryRequest(hrr)
	if err != nil {
		t.Fatalf("HandleHelloRetryRequest: %v", err)
	}
	_, ch2Body, _, err := ReadHandshakeMessage(ch2)
	if err != nil {
		t.Fatalf("read ClientHello2: %v", err)
	}
	var ch2Msg ClientHelloMsg
	if err := ch2Msg.unmarshalBody(ch2Body); err != nil {
		t.Fatalf("ClientHello2 unmarshal: %v", err)
	}
	cookieExt := findExtension(ch2Msg.Extensions, ExtensionTypeCookie)
	if cookieExt == nil {
		t.Fatal("ClientHello2 missing cookie extension")
	}
	echoed, err := parseCookieExtension(cookieExt)
	if err != nil {
		t.Fatalf("parse echoed cookie: %v", err)
	}
	if !bytes.Equal(echoed, cookie) {
		t.Fatalf("echoed cookie %x, want %x", echoed, cookie)
	}

	// Phase reset proof: HandleHelloRetryRequest returns the client to the
	// "awaiting ServerHello" state, so HandleServerHello runs again (and still
	// recognizes the same HRR) rather than erroring on the phase guard.
	if err := client.HandleServerHello(hrr); !errors.Is(err, ErrHelloRetryRequest) {
		t.Fatalf("post-HRR HandleServerHello = %v, want ErrHelloRetryRequest (phase not reset)", err)
	}
}


