package tls13gm

import (
	"bytes"
	"testing"
)

// TestClientHandshakerZero verifies that ClientHandshaker.Zero clears every
// secret-bearing []byte field after a completed handshake. The fields are
// expected to be non-empty post-handshake (the handshake populates them as
// derivation intermediates), and must be all-zero after Zero.
func TestClientHandshakerZero(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
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
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("HandleServerFlight: %v", err)
	}
	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server HandleClientFinished: %v", err)
	}

	// Sanity: pre-Zero, the key-derivation intermediates must be populated.
	if len(client.handshakeSecret) == 0 || len(client.masterSecret) == 0 ||
		len(client.clientHSTraffic) == 0 || len(client.serverHSTraffic) == 0 {
		t.Fatalf("precondition failed: client handshaker secrets not populated post-handshake")
	}

	client.Zero()

	zero := bytes.Repeat([]byte{0}, 32)
	for name, got := range map[string][]byte{
		"handshakeSecret":        client.handshakeSecret,
		"masterSecret":           client.masterSecret,
		"resumptionMasterSecret": client.resumptionMasterSecret,
		"clientHSTraffic":        client.clientHSTraffic,
		"serverHSTraffic":        client.serverHSTraffic,
	} {
		if len(got) == 0 {
			continue // field legitimately unset (e.g. resumption not offered)
		}
		if !bytes.Equal(got, zero[:len(got)]) {
			t.Errorf("ClientHandshaker.Zero did not clear %s: got %x", name, got)
		}
	}
}

// TestServerHandshakerZero is the server-side counterpart.
func TestServerHandshakerZero(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
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
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("HandleServerFlight: %v", err)
	}
	cf, err := client.ClientFinished()
	if err != nil {
		t.Fatalf("ClientFinished: %v", err)
	}
	if err := server.HandleClientFinished(cf); err != nil {
		t.Fatalf("server HandleClientFinished: %v", err)
	}

	// HandleClientFinished derives the server resumption master secret, so all
	// common intermediates are now populated.
	if len(server.handshakeSecret) == 0 || len(server.masterSecret) == 0 ||
		len(server.clientHSTraffic) == 0 || len(server.serverHSTraffic) == 0 {
		t.Fatalf("precondition failed: server handshaker secrets not populated post-handshake")
	}

	server.Zero()

	zero := bytes.Repeat([]byte{0}, 32)
	for name, got := range map[string][]byte{
		"handshakeSecret":        server.handshakeSecret,
		"masterSecret":           server.masterSecret,
		"resumptionMasterSecret": server.resumptionMasterSecret,
		"clientHSTraffic":        server.clientHSTraffic,
		"serverHSTraffic":        server.serverHSTraffic,
	} {
		if len(got) == 0 {
			continue
		}
		if !bytes.Equal(got, zero[:len(got)]) {
			t.Errorf("ServerHandshaker.Zero did not clear %s: got %x", name, got)
		}
	}
}

// TestHandshakerZeroNilSafe ensures Zero on a nil handshaker does not panic
// (defensive: GMCryptoSetup.Close calls it unconditionally).
func TestHandshakerZeroNilSafe(t *testing.T) {
	var nilClient *ClientHandshaker
	var nilServer *ServerHandshaker
	nilClient.Zero() // must not panic
	nilServer.Zero() // must not panic
}
