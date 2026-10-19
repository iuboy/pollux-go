package tls13gm

// ALPN (RFC 7301 / RFC 9001 §8.1) fail-closed negative tests, plus the
// positive path (covered end-to-end by every handshake test that sets
// NextProtos on both sides).

import (
	"strings"
	"testing"
)

func alpnHandshakePair(t *testing.T, clientProtos, serverProtos []string) (*ClientHandshaker, *ServerHandshaker) {
	t.Helper()
	dcid := []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}
	cert, serverKey := generateTestSM2Cert(t)
	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:               dcid,
		InsecureSkipVerify: true,
		NextProtos:         clientProtos,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:        dcid,
		Certificate: cert,
		PrivateKey:  serverKey,
		NextProtos:  serverProtos,
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return client, server
}

func TestALPN_Negotiation(t *testing.T) {
	client, server := alpnHandshakePair(t,
		[]string{"h2", "gm/1.0"}, []string{"gm/1.0", "h3", "h2"})
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello: %v", err)
	}
	// crypto/tls preference policy: the FIRST client-offered protocol the
	// server also supports wins — "h2" (client's first), not the server's
	// own first entry "gm/1.0".
	if got := server.NegotiatedProtocol(); got != "h2" {
		t.Fatalf("server negotiated %q, want h2 (client preference order)", got)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	if err := client.HandleServerFlight(sh, ee, certMsg, cv, fin); err != nil {
		t.Fatalf("HandleServerFlight: %v", err)
	}
	if got := client.NegotiatedProtocol(); got != "h2" {
		t.Fatalf("client negotiated %q, want h2", got)
	}
}

func TestALPN_NoOverlapAbortsServer(t *testing.T) {
	client, server := alpnHandshakePair(t, []string{"h2"}, []string{"h3"})
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	err = server.HandleClientHello(ch)
	if err == nil || !strings.Contains(err.Error(), "no overlapping ALPN protocol") {
		t.Fatalf("want no-overlap abort (no_application_protocol), got %v", err)
	}
}

func TestALPN_ServerSilenceFailsClient(t *testing.T) {
	// The server has NO protocols configured, so it never echoes ALPN — the
	// client, which offered a list, must fail closed at EE instead of
	// continuing without a negotiated protocol (RFC 9001 §8.1).
	client, server := alpnHandshakePair(t, []string{"h2"}, nil)
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello: %v", err)
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight: %v", err)
	}
	err = client.HandleServerFlight(sh, ee, certMsg, cv, fin)
	if err == nil || !strings.Contains(err.Error(), "did not negotiate an ALPN protocol") {
		t.Fatalf("want client ALPN failure, got %v", err)
	}
}
