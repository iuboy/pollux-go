package handshake

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

func gmTestServerCert(t *testing.T) (*x509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2 GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gm quic test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := smx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("smx509 CreateCertificate: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("smx509 ParseCertificate: %v", err)
	}
	return cert, priv
}

// drainGMEvents pops every queued event from a GMCryptoSetup.
func drainGMEvents(g *GMCryptoSetup) []Event {
	var out []Event
	for {
		ev := g.NextEvent()
		if ev.Kind == EventNoEvent {
			return out
		}
		out = append(out, ev)
	}
}

func eventKindSeq(evs []Event) []EventKind {
	seq := make([]EventKind, len(evs))
	for i, e := range evs {
		seq[i] = e.Kind
	}
	return seq
}

// TestGMCryptoSetup_FullHandshake drives a client and server GMCryptoSetup
// through a complete RFC 8998 GM handshake the way quic-go's connection layer
// would (StartHandshake → HandleMessage per CRYPTO reassembly → NextEvent),
// without involving UDP. It asserts the event sequence, transport-parameter
// exchange, and that the client's 1-RTT sealer output is decryptable by the
// server's 1-RTT opener.
func TestGMCryptoSetup_FullHandshake(t *testing.T) {
	connID := protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	cert, serverKey := gmTestServerCert(t)

	clientTP := &wire.TransportParameters{MaxIdleTimeout: 10 * time.Second, ActiveConnectionIDLimit: 2}
	serverTP := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2}

	server, err := NewGMCryptoSetupServer(connID, &tls13gm.ServerConfig{
		Certificate: cert,
		PrivateKey:  serverKey,
	}, serverTP, utils.DefaultLogger, protocol.Version1)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	client, err := NewGMCryptoSetupClient(connID, &tls13gm.ClientConfig{
		InsecureSkipVerify: true,
	}, clientTP, utils.DefaultLogger, protocol.Version1, nil)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupClient: %v", err)
	}

	// 1. Client starts → emits ClientHello on the Initial stream.
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("client StartHandshake: %v", err)
	}
	clientEvs := drainGMEvents(client)
	if got := eventKindSeq(clientEvs); len(got) != 1 || got[0] != EventWriteInitialData {
		t.Fatalf("client initial events = %v, want [EventWriteInitialData]", got)
	}
	clientHello := clientEvs[0].Data

	// 2. Server consumes the ClientHello and emits its flight.
	if err := server.HandleMessage(clientHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	serverEvs := drainGMEvents(server)
	var serverHello, serverHandshake []byte
	sawClientTP := false
	for _, e := range serverEvs {
		switch e.Kind {
		case EventReceivedTransportParameters:
			sawClientTP = true
			if e.TransportParameters.MaxIdleTimeout != clientTP.MaxIdleTimeout {
				t.Fatalf("server saw client TP MaxIdleTimeout = %v, want %v", e.TransportParameters.MaxIdleTimeout, clientTP.MaxIdleTimeout)
			}
		case EventWriteInitialData:
			serverHello = e.Data
		case EventWriteHandshakeData:
			serverHandshake = e.Data
		}
	}
	if serverHello == nil || serverHandshake == nil {
		t.Fatalf("server flight incomplete: events = %v", eventKindSeq(serverEvs))
	}
	if !sawClientTP {
		t.Fatal("server did not surface client transport parameters")
	}

	// 3. Client consumes ServerHello (Initial level) → handshake keys ready.
	if err := client.HandleMessage(serverHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("client HandleMessage(ServerHello): %v", err)
	}
	drainGMEvents(client) // EventReceivedReadKeys

	// 4. Client consumes EE+Cert+CertVerify+Finished (Handshake level).
	if err := client.HandleMessage(serverHandshake, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("client HandleMessage(server flight): %v", err)
	}
	clientEvs2 := drainGMEvents(client)
	var clientFin []byte
	sawServerTP, clientComplete := false, false
	for _, e := range clientEvs2 {
		switch e.Kind {
		case EventReceivedTransportParameters:
			sawServerTP = true
			if e.TransportParameters.MaxIdleTimeout != serverTP.MaxIdleTimeout {
				t.Fatalf("client saw server TP MaxIdleTimeout = %v, want %v", e.TransportParameters.MaxIdleTimeout, serverTP.MaxIdleTimeout)
			}
		case EventWriteHandshakeData:
			clientFin = e.Data
		case EventHandshakeComplete:
			clientComplete = true
		}
	}
	if clientFin == nil {
		t.Fatalf("client did not emit Finished: events = %v", eventKindSeq(clientEvs2))
	}
	if !sawServerTP {
		t.Fatal("client did not surface server transport parameters")
	}
	if !clientComplete {
		t.Fatal("client did not complete the handshake")
	}

	// 5. Server consumes the client Finished → handshake complete.
	if err := server.HandleMessage(clientFin, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("server HandleMessage(client Finished): %v", err)
	}
	serverComplete := false
	for _, e := range drainGMEvents(server) {
		if e.Kind == EventHandshakeComplete {
			serverComplete = true
		}
	}
	if !serverComplete {
		t.Fatal("server did not complete the handshake")
	}

	// 6. 1-RTT: the client's sealer output must be decryptable by the server's
	// opener (and vice versa), proving both sides derived matching keys.
	clientSealer, err := client.Get1RTTSealer()
	if err != nil {
		t.Fatalf("client Get1RTTSealer: %v", err)
	}
	serverOpener, err := server.Get1RTTOpener()
	if err != nil {
		t.Fatalf("server Get1RTTOpener: %v", err)
	}
	serverSealer, err := server.Get1RTTSealer()
	if err != nil {
		t.Fatalf("server Get1RTTSealer: %v", err)
	}
	clientOpener, err := client.Get1RTTOpener()
	if err != nil {
		t.Fatalf("client Get1RTTOpener: %v", err)
	}

	header := []byte{0x40, 0x01, 0x02, 0x03}
	payload := []byte("pollux-go gm quic 1-rtt")

	c2s := clientSealer.Seal(nil, payload, 1, header)
	pt, err := serverOpener.Open(nil, c2s, monotime.Now(), 1, protocol.KeyPhaseZero, header)
	if err != nil {
		t.Fatalf("c→s 1-RTT open failed: %v", err)
	}
	if string(pt) != string(payload) {
		t.Fatalf("c→s plaintext mismatch: %q", pt)
	}

	s2c := serverSealer.Seal(nil, payload, 1, header)
	pt2, err := clientOpener.Open(nil, s2c, monotime.Now(), 1, protocol.KeyPhaseZero, header)
	if err != nil {
		t.Fatalf("s→c 1-RTT open failed: %v", err)
	}
	if string(pt2) != string(payload) {
		t.Fatalf("s→c plaintext mismatch: %q", pt2)
	}

	// 0-RTT is unsupported in P0.
	if _, err := client.Get0RTTSealer(); err == nil {
		t.Fatal("Get0RTTSealer should fail in P0")
	}
}
