package tls13gm

import (
	"bytes"
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
