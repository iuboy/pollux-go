package tls13gm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
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

// TestClientHello_PreSharedKey verifies the client emits a PSK-resumption
// ClientHello: pre_shared_key (last extension, identity = PSK, binder) and
// psk_key_exchange_modes (psk_dhe_ke). The binder is recomputed independently
// over the reconstructed truncated ClientHello and must match.
func TestClientHello_PreSharedKey(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	psk := bytes.Repeat([]byte{0xEE}, sm3.Size)
	const obfAge uint32 = 0x12345678

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: obfAge,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	_, body, _, err := ReadHandshakeMessage(ch)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	var chMsg ClientHelloMsg
	if err := chMsg.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// pre_shared_key must be the last extension.
	if got := chMsg.Extensions[len(chMsg.Extensions)-1].Type; got != ExtensionTypePreSharedKey {
		t.Fatalf("last extension type %d, want pre_shared_key (%d)", got, ExtensionTypePreSharedKey)
	}
	pskExt := findExtension(chMsg.Extensions, ExtensionTypePreSharedKey)
	identities, binders, err := parsePreSharedKeyExtension(pskExt)
	if err != nil {
		t.Fatalf("parse pre_shared_key: %v", err)
	}
	if len(identities) != 1 || !bytes.Equal(identities[0].Identity, psk) || identities[0].ObfuscatedTicketAge != obfAge {
		t.Fatalf("identity mismatch: %+v", identities)
	}
	if len(binders) != 1 || len(binders[0]) != sm3.Size {
		t.Fatalf("binder count/len mismatch: %d binders, first len %d", len(binders), len(binders))
	}

	// psk_key_exchange_modes must advertise psk_dhe_ke.
	kemExt := findExtension(chMsg.Extensions, ExtensionTypePSKKeyExchangeModes)
	if kemExt == nil || len(kemExt) != 2 || kemExt[0] != 1 || kemExt[1] != PSKKeyExchangeModeDHEKE {
		t.Fatalf("psk_key_exchange_modes = %x, want [01 01]", kemExt)
	}

	// Reconstruct the truncated ClientHello (pre_shared_key binders list empty)
	// and verify the binder matches an independent computation.
	truncExts := make([]Extension, len(chMsg.Extensions))
	copy(truncExts, chMsg.Extensions)
	for i, e := range truncExts {
		if e.Type == ExtensionTypePreSharedKey {
			trunc, err := marshalPreSharedKeyExtension(identities, nil)
			if err != nil {
				t.Fatalf("marshal truncated: %v", err)
			}
			truncExts[i] = Extension{Type: ExtensionTypePreSharedKey, Data: trunc}
		}
	}
	truncChMsg := chMsg
	truncChMsg.Extensions = truncExts
	truncFull, err := MarshalHandshakeMessage(&truncChMsg)
	if err != nil {
		t.Fatalf("marshal truncated CH: %v", err)
	}
	expected, err := computeResumptionBinder(psk, truncFull)
	if err != nil {
		t.Fatalf("recompute binder: %v", err)
	}
	if !bytes.Equal(binders[0], expected) {
		t.Fatalf("binder mismatch:\n client %x\n recomputed %x", binders[0], expected)
	}
}

// TestServerHandshake_VerifyPSKBinder drives the PSK binder end-to-end between a
// client and server: the client builds a PSK ClientHello (with binder), and the
// server's HandleClientHello verifies the binder. A recognized PSK is accepted;
// an unrecognized one is rejected.
func TestServerHandshake_VerifyPSKBinder(t *testing.T) {
	dcid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	cert, serverKey := generateTestSM2Cert(t)
	psk := bytes.Repeat([]byte{0xEE}, sm3.Size)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: 1,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}

	// Server recognizing the PSK must accept the binder.
	server, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:           dcid,
		Certificate:    cert,
		PrivateKey:     serverKey,
		ResumptionPSKs: [][]byte{psk},
	})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello with recognized PSK: %v", err)
	}

	// Server without the PSK must reject.
	server2, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:           dcid,
		Certificate:    cert,
		PrivateKey:     serverKey,
		ResumptionPSKs: [][]byte{bytes.Repeat([]byte{0xFF}, sm3.Size)},
	})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	if err := server2.HandleClientHello(ch); err == nil {
		t.Fatal("HandleClientHello accepted an unrecognized PSK")
	}
}

// TestHandshake_PSKResumption is the full P2 round-trip: a normal handshake
// yields a NewSessionTicket; the client then resumes with the ticket's PSK and
// the second handshake completes in PSK mode (no Certificate/CertificateVerify)
// with matching client/server keys.
func TestHandshake_PSKResumption(t *testing.T) {
	dcid1 := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}
	dcid2 := []byte{0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8}
	cert, serverKey := generateTestSM2Cert(t)

	// 1. Initial (full) handshake to obtain a resumption ticket.
	server1, err := NewServerHandshakerWithConfig(ServerConfig{DCID: dcid1, Certificate: cert, PrivateKey: serverKey})
	if err != nil {
		t.Fatalf("server1: %v", err)
	}
	client1, err := NewClientHandshakerWithConfig(ClientConfig{DCID: dcid1, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("client1: %v", err)
	}
	ch1, err := client1.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello1: %v", err)
	}
	if err := server1.HandleClientHello(ch1); err != nil {
		t.Fatalf("server1 HandleClientHello: %v", err)
	}
	sh1, ee1, cert1, cv1, fin1, err := server1.ServerFlight()
	if err != nil {
		t.Fatalf("server1 ServerFlight: %v", err)
	}
	if err := client1.HandleServerFlight(sh1, ee1, cert1, cv1, fin1); err != nil {
		t.Fatalf("client1 HandleServerFlight: %v", err)
	}
	cf1, err := client1.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished1: %v", err)
	}
	if err := server1.HandleClientFinished(cf1); err != nil {
		t.Fatalf("server1 HandleClientFinished: %v", err)
	}
	ticketMsg, err := server1.NewSessionTicket(7200, 0x12345678)
	if err != nil {
		t.Fatalf("NewSessionTicket: %v", err)
	}
	_, ticketBody, _, err := ReadHandshakeMessage(ticketMsg)
	if err != nil {
		t.Fatalf("read ticket: %v", err)
	}
	var nst NewSessionTicketMsg
	if err := nst.unmarshalBody(ticketBody); err != nil {
		t.Fatalf("unmarshal ticket: %v", err)
	}
	psk := nst.Ticket

	// 2. PSK resumption handshake.
	server2, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:           dcid2,
		Certificate:    cert,
		PrivateKey:     serverKey,
		ResumptionPSKs: [][]byte{psk},
	})
	if err != nil {
		t.Fatalf("server2: %v", err)
	}
	client2, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid2,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: 1,
	})
	if err != nil {
		t.Fatalf("client2: %v", err)
	}
	ch2, err := client2.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello2: %v", err)
	}
	if err := server2.HandleClientHello(ch2); err != nil {
		t.Fatalf("server2 HandleClientHello (PSK): %v", err)
	}
	sh2, ee2, cert2, cv2, fin2, err := server2.ServerFlight()
	if err != nil {
		t.Fatalf("server2 ServerFlight (PSK): %v", err)
	}
	// PSK mode: server omits Certificate/CertificateVerify.
	if cert2 != nil || cv2 != nil {
		t.Fatal("PSK-mode ServerFlight emitted Certificate/CertificateVerify")
	}
	if err := client2.HandleServerFlight(sh2, ee2, nil, nil, fin2); err != nil {
		t.Fatalf("client2 HandleServerFlight (PSK): %v", err)
	}
	cf2, err := client2.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished2: %v", err)
	}
	if err := server2.HandleClientFinished(cf2); err != nil {
		t.Fatalf("server2 HandleClientFinished: %v", err)
	}

	// Both sides must agree on the Handshake and Application keys.
	cs := client2.Secrets()
	ss := server2.Secrets()
	for _, p := range [][2]*QUICPacketKeys{
		{cs.ClientHandshakeKeys, ss.ClientHandshakeKeys},
		{cs.ServerHandshakeKeys, ss.ServerHandshakeKeys},
		{cs.ClientApplicationKeys, ss.ClientApplicationKeys},
		{cs.ServerApplicationKeys, ss.ServerApplicationKeys},
	} {
		if !bytes.Equal(p[0].AEADKey, p[1].AEADKey) || !bytes.Equal(p[0].AEADIV, p[1].AEADIV) {
			t.Fatalf("PSK resumption keys mismatch: client %x/%x server %x/%x", p[0].AEADKey, p[0].AEADIV, p[1].AEADKey, p[1].AEADIV)
		}
	}
}

// TestHandshake_EarlyTrafficKeys verifies the 0-RTT key agreement between a PSK
// client and server: after the client's ClientHello (which carries early_data)
// and the server's HandleClientHello, both sides have identical ClientEarlyKeys
// usable to encrypt/decrypt 0-RTT data before the handshake completes.
func TestHandshake_EarlyTrafficKeys(t *testing.T) {
	dcid := []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8}
	cert, serverKey := generateTestSM2Cert(t)
	psk := bytes.Repeat([]byte{0xEE}, sm3.Size)

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: 1,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:           dcid,
		Certificate:    cert,
		PrivateKey:     serverKey,
		ResumptionPSKs: [][]byte{psk},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	// The ClientHello must carry the early_data extension.
	_, chBody, _, _ := ReadHandshakeMessage(ch)
	var chMsg ClientHelloMsg
	if err := chMsg.unmarshalBody(chBody); err != nil {
		t.Fatalf("unmarshal CH: %v", err)
	}
	if !hasExtension(chMsg.Extensions, ExtensionTypeEarlyData) {
		t.Fatal("PSK ClientHello missing early_data extension")
	}
	// Client derives 0-RTT keys right after the ClientHello.
	if client.Secrets().ClientEarlyKeys == nil {
		t.Fatal("client ClientEarlyKeys nil after ClientHello")
	}

	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("server HandleClientHello: %v", err)
	}
	if server.Secrets().ClientEarlyKeys == nil {
		t.Fatal("server ClientEarlyKeys nil after HandleClientHello")
	}

	// Both sides must agree on the 0-RTT keys.
	ck := client.Secrets().ClientEarlyKeys
	sk := server.Secrets().ClientEarlyKeys
	if !bytes.Equal(ck.AEADKey, sk.AEADKey) || !bytes.Equal(ck.AEADIV, sk.AEADIV) || !bytes.Equal(ck.HeaderKey, sk.HeaderKey) {
		t.Fatalf("0-RTT keys mismatch:\n client %x/%x/%x\n server %x/%x/%x",
			ck.AEADKey, ck.AEADIV, ck.HeaderKey, sk.AEADKey, sk.AEADIV, sk.HeaderKey)
	}
}


