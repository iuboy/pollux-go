package handshake

// gm_0rtt_gates_test.go locks the third security review's P1 fixes:
//   - M13: the server's 1-RTT opener stays ErrKeysNotYetAvailable until the
//     client's Finished is verified (packets are buffered, not delivered);
//   - M9:  the quic.Config-level Allow0RTT switch gates GM 0-RTT admission;
//   - M10: a client whose 0-RTT was rejected sees EventDiscard0RTTKeys (the
//     0-RTT level drops) instead of a silent 1-RTT retransmission.

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm3"
	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// gmGatePair drives a client/server GMCryptoSetup pair through step 2 of the
// handshake (client ClientHello consumed by the server, server flight
// produced) and returns the raw flight for further driving.
func gmGatePair(t *testing.T, serverCfg *tls13gm.ServerConfig, clientCfg *tls13gm.ClientConfig) (client, server *GMCryptoSetup, clientHello, serverHello, serverFlight []byte) {
	t.Helper()
	connID := protocol.ParseConnectionID([]byte{0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8})
	clientTP := &wire.TransportParameters{MaxIdleTimeout: 10 * time.Second, ActiveConnectionIDLimit: 2}
	serverTP := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2}

	server, err := NewGMCryptoSetupServer(connID, serverCfg, serverTP, utils.DefaultLogger, protocol.Version1, true)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	client, err = NewGMCryptoSetupClient(connID, clientCfg, clientTP, utils.DefaultLogger, protocol.Version1, nil)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupClient: %v", err)
	}
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("client StartHandshake: %v", err)
	}
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteInitialData {
			clientHello = ev.Data
		}
	}
	if clientHello == nil {
		t.Fatal("client did not emit ClientHello")
	}
	if err := server.HandleMessage(clientHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	for _, ev := range drainGMEvents(server) {
		switch ev.Kind {
		case EventWriteInitialData:
			serverHello = ev.Data
		case EventWriteHandshakeData:
			serverFlight = ev.Data
		}
	}
	if serverHello == nil || serverFlight == nil {
		t.Fatal("server flight incomplete")
	}
	return client, server, clientHello, serverHello, serverFlight
}

// TestGMCryptoSetup_Server1RTTOpenerGatedUntilFinished locks M13: the server
// installs its 1-RTT AEAD while processing the ClientHello, but Get1RTTOpener
// must refuse (buffering early 1-RTT packets) until the client's Finished is
// verified.
func TestGMCryptoSetup_Server1RTTOpenerGatedUntilFinished(t *testing.T) {
	cert, serverKey := gmTestServerCert(t)
	client, server, _, serverHello, serverFlight := gmGatePair(t,
		&tls13gm.ServerConfig{Certificate: cert, PrivateKey: serverKey},
		&tls13gm.ClientConfig{InsecureSkipVerify: true},
	)

	if _, err := server.Get1RTTOpener(); err != ErrKeysNotYetAvailable {
		t.Fatalf("server Get1RTTOpener before client Finished = %v, want ErrKeysNotYetAvailable", err)
	}
	// Drive the flight to the client and the client Finished back to the server.
	if err := client.HandleMessage(serverHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("client HandleMessage(ServerHello): %v", err)
	}
	drainGMEvents(client)
	if err := client.HandleMessage(serverFlight, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("client HandleMessage(server flight): %v", err)
	}
	var clientFin []byte
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteHandshakeData {
			clientFin = ev.Data
		}
	}
	if clientFin == nil {
		t.Fatal("client did not emit Finished")
	}
	// Still gated before the Finished reaches the server.
	if _, err := server.Get1RTTOpener(); err != ErrKeysNotYetAvailable {
		t.Fatalf("server Get1RTTOpener before consuming Finished = %v, want ErrKeysNotYetAvailable", err)
	}
	if err := server.HandleMessage(clientFin, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("server HandleMessage(client Finished): %v", err)
	}
	drainGMEvents(server)
	if _, err := server.Get1RTTOpener(); err != nil {
		t.Fatalf("server Get1RTTOpener after Finished = %v, want nil", err)
	}
}

// TestGMCryptoSetup_Allow0RTTConfigGate locks M9: a server configured for
// 0-RTT at the tls13gm level (AllowEarlyData + accept-all acceptor + the right
// ticket key) must still refuse 0-RTT when the quic.Config-level Allow0RTT
// switch is false — no EventReceived0RTTReadKeys, no decryptable 0-RTT data,
// and no early_data echo in EncryptedExtensions.
func TestGMCryptoSetup_Allow0RTTConfigGate(t *testing.T) {
	cert, serverKey := gmTestServerCert(t)
	psk := make([]byte, sm3.Size)
	for i := range psk {
		psk[i] = byte(i)
	}
	tek := make([]byte, tls13gm.SessionTicketKeyLen)
	for i := range tek {
		tek[i] = byte(0x70 + i)
	}
	identity, err := tls13gm.EncryptSessionTicket(tek, psk, 0)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}

	serverCfg := &tls13gm.ServerConfig{
		Certificate:       cert,
		PrivateKey:        serverKey,
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: func([]byte, time.Duration) bool { return true },
	}
	connID := protocol.ParseConnectionID([]byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8})
	serverTP := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2}
	// quic-level switch OFF while the tls13gm-level config says ON.
	server, err := NewGMCryptoSetupServer(connID, serverCfg, serverTP, utils.DefaultLogger, protocol.Version1, false)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	clientTP := &wire.TransportParameters{MaxIdleTimeout: 10 * time.Second, ActiveConnectionIDLimit: 2}
	client, err := NewGMCryptoSetupClient(connID, &tls13gm.ClientConfig{
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
		// Saved server params keep the client's own 0-RTT alive (M11 drops
		// the early keys without them); the SERVER-side gate under test is
		// unaffected by what the client saved.
		ResumptionAppData: serverTP.Marshal(protocol.PerspectiveServer),
		EarlyData:         true,
	}, clientTP, utils.DefaultLogger, protocol.Version1, nil)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupClient: %v", err)
	}
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("client StartHandshake: %v", err)
	}
	var clientHello []byte
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteInitialData {
			clientHello = ev.Data
		}
	}
	// The client CAN seal 0-RTT before knowing the verdict.
	if _, err := client.Get0RTTSealer(); err != nil {
		t.Fatalf("client Get0RTTSealer before verdict: %v", err)
	}

	if err := server.HandleMessage(clientHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	for _, ev := range drainGMEvents(server) {
		if ev.Kind == EventReceived0RTTReadKeys {
			t.Fatal("server emitted EventReceived0RTTReadKeys despite quic-level Allow0RTT=false")
		}
	}
	if _, err := server.Get0RTTOpener(); err == nil {
		t.Fatal("server Get0RTTOpener must be unavailable when Allow0RTT=false")
	}
}

// TestGMCryptoSetup_Client0RTTRejectionDiscards locks M10: a client that
// offered 0-RTT (PSK + early_data) but faces a server that declines the PSK
// (no shared ticket key → full handshake, no early_data in EE) must see
// EventDiscard0RTTKeys — the 0-RTT level drops and the 0-RTT sealer becomes
// unavailable, instead of the 0-RTT stream data being silently retransmitted
// at 1-RTT.
func TestGMCryptoSetup_Client0RTTRejectionDiscards(t *testing.T) {
	cert, serverKey := gmTestServerCert(t)
	psk := make([]byte, sm3.Size)
	for i := range psk {
		psk[i] = byte(0x90 + i)
	}
	rightTek := make([]byte, tls13gm.SessionTicketKeyLen)
	for i := range rightTek {
		rightTek[i] = byte(0xA0 + i)
	}
	wrongTek := make([]byte, tls13gm.SessionTicketKeyLen)
	for i := range wrongTek {
		wrongTek[i] = byte(0xB0 + i)
	}
	identity, err := tls13gm.EncryptSessionTicket(rightTek, psk, 0)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}

	// Server holds the WRONG ticket key: the PSK is declined (full handshake,
	// EE carries no early_data).
	client, _, _, serverHello, serverFlight := gmGatePair(t,
		&tls13gm.ServerConfig{
			Certificate:       cert,
			PrivateKey:        serverKey,
			SessionTicketKeys: func() [][]byte { return [][]byte{wrongTek} },
		},
		&tls13gm.ClientConfig{
			InsecureSkipVerify:            true,
			ResumptionPSK:                 psk,
			ResumptionIdentity:            identity,
			ResumptionObfuscatedTicketAge: 1,
			EarlyData:                     true,
		},
	)

	if err := client.HandleMessage(serverHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("client HandleMessage(ServerHello): %v", err)
	}
	drainGMEvents(client)
	if err := client.HandleMessage(serverFlight, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("client HandleMessage(server flight): %v", err)
	}
	sawDiscard, sawComplete, discardBeforeComplete := false, false, false
	for _, ev := range drainGMEvents(client) {
		switch ev.Kind {
		case EventDiscard0RTTKeys:
			sawDiscard = true
			discardBeforeComplete = !sawComplete
		case EventHandshakeComplete:
			sawComplete = true
		}
	}
	if !sawDiscard {
		t.Fatal("client did not emit EventDiscard0RTTKeys after 0-RTT rejection")
	}
	if !discardBeforeComplete {
		t.Fatal("EventDiscard0RTTKeys must precede EventHandshakeComplete")
	}
	if !sawComplete {
		t.Fatal("handshake did not complete after 0-RTT rejection")
	}
	if _, err := client.Get0RTTSealer(); err == nil {
		t.Fatal("client 0-RTT sealer must be unavailable after rejection")
	}
}
