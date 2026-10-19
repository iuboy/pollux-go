package handshake

// gm_0rtt_restore_test.go locks the M11/M12 fixes (third security review):
//   - M11: a 0-RTT client holding saved server parameters emits
//     EventRestoredTransportParameters (releasing DialEarly's early
//     connection); without saved parameters 0-RTT is declined;
//   - M12: the server rejects 0-RTT when the transport parameters saved in
//     the ticket no longer satisfy ValidFor0RTT under the current ones (or
//     the ticket carries none).

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

func gmRestoreClient(t *testing.T, tp *wire.TransportParameters, resumption *tls13gm.ClientConfig) *GMCryptoSetup {
	t.Helper()
	connID := protocol.ParseConnectionID([]byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58})
	cfg := tls13gm.ClientConfig{InsecureSkipVerify: true, NextProtos: []string{"echo"}}
	if resumption != nil {
		cfg.ResumptionPSK = resumption.ResumptionPSK
		cfg.ResumptionIdentity = resumption.ResumptionIdentity
		cfg.ResumptionObfuscatedTicketAge = resumption.ResumptionObfuscatedTicketAge
		cfg.ResumptionAppData = resumption.ResumptionAppData
		cfg.EarlyData = true
	}
	client, err := NewGMCryptoSetupClient(connID, &cfg, tp, utils.DefaultLogger, protocol.Version1, nil)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupClient: %v", err)
	}
	return client
}

func gmRestoreServerParams(t *testing.T) *wire.TransportParameters {
	t.Helper()
	return &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2, InitialMaxData: 1 << 20}
}

// TestGMCryptoSetup_Client0RTTRestoresParams locks M11: with 0-RTT keys AND
// saved server parameters, StartHandshake emits EventRestoredTransportParameters
// carrying them.
func TestGMCryptoSetup_Client0RTTRestoresParams(t *testing.T) {
	saved := gmRestoreServerParams(t)
	savedRaw := saved.Marshal(protocol.PerspectiveServer)
	cfg := &tls13gm.ClientConfig{
		ResumptionPSK:                 bytes32(0xC1),
		ResumptionIdentity:            []byte("identity"),
		ResumptionObfuscatedTicketAge: 1,
		ResumptionAppData:             savedRaw,
	}
	client := gmRestoreClient(t, gmRestoreServerParams(t), cfg)
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}
	restored := false
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventRestoredTransportParameters {
			restored = true
			if ev.TransportParameters == nil || ev.TransportParameters.MaxIdleTimeout != saved.MaxIdleTimeout {
				t.Fatalf("restored params mismatch: %+v", ev.TransportParameters)
			}
		}
	}
	if !restored {
		t.Fatal("0-RTT client with saved params did not emit EventRestoredTransportParameters")
	}
}

// TestGMCryptoSetup_Client0RTTWithoutSavedParamsDeclined locks M11: 0-RTT keys
// without saved server parameters are dropped (upstream "Not doing 0-RTT") —
// no restore event, and the 0-RTT sealer is unavailable.
func TestGMCryptoSetup_Client0RTTWithoutSavedParamsDeclined(t *testing.T) {
	cfg := &tls13gm.ClientConfig{
		ResumptionPSK:                 bytes32(0xC2),
		ResumptionIdentity:            []byte("identity"),
		ResumptionObfuscatedTicketAge: 1,
		// ResumptionAppData deliberately empty.
	}
	client := gmRestoreClient(t, gmRestoreServerParams(t), cfg)
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventRestoredTransportParameters {
			t.Fatal("restore event emitted without saved params")
		}
	}
	if _, err := client.Get0RTTSealer(); err == nil {
		t.Fatal("0-RTT sealer must be unavailable when 0-RTT was declined for missing params")
	}
}

// TestGMCryptoSetup_Server0RTTRejectedOnParamsChange locks M12: the server
// declines 0-RTT (no EventReceived0RTTReadKeys, no early keys) when the
// ticket's saved parameters fail ValidFor0RTT — here because the server
// LOWERED InitialMaxData since the ticket was issued.
func TestGMCryptoSetup_Server0RTTRejectedOnParamsChange(t *testing.T) {
	cert, serverKey := gmTestServerCert(t)
	tek := bytes16(0xD0)
	psk := bytes32(0xC3)

	// Ticket saved when the server advertised 1 MiB of connection flow
	// control; the server now runs 64 KiB — a resuming 0-RTT client would
	// exceed the new limit.
	oldParams := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2, InitialMaxData: 1 << 20}
	newParams := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2, InitialMaxData: 64 << 10}
	if newParams.ValidFor0RTT(oldParams) {
		t.Fatal("test setup: lowered InitialMaxData must fail ValidFor0RTT")
	}
	identity, err := tls13gm.EncryptSessionTicketWithData(tek, psk, 0, oldParams.Marshal(protocol.PerspectiveServer))
	if err != nil {
		t.Fatalf("EncryptSessionTicketWithData: %v", err)
	}

	// Client offers 0-RTT with the OLD params saved.
	clientCfg := &tls13gm.ClientConfig{
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
		ResumptionAppData:             oldParams.Marshal(protocol.PerspectiveServer),
	}
	client := gmRestoreClient(t, newParams, clientCfg)
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("client StartHandshake: %v", err)
	}
	var ch []byte
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteInitialData {
			ch = ev.Data
		}
	}

	connID := protocol.ParseConnectionID([]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68})
	server, err := NewGMCryptoSetupServer(connID, &tls13gm.ServerConfig{
		Certificate:       cert,
		PrivateKey:        serverKey,
		NextProtos:        []string{"echo"},
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: func([]byte, time.Duration) bool { return true },
	}, newParams, utils.DefaultLogger, protocol.Version1, true)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	if err := server.HandleMessage(ch, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	for _, ev := range drainGMEvents(server) {
		if ev.Kind == EventReceived0RTTReadKeys {
			t.Fatal("server accepted 0-RTT despite changed transport parameters")
		}
	}
	if _, err := server.Get0RTTOpener(); err == nil {
		t.Fatal("server 0-RTT opener must be unavailable after the ValidFor0RTT rejection")
	}
	// Control: the SAME ticket against a server whose params still satisfy
	// ValidFor0RTT keeps the 0-RTT (the acceptor said yes, the params match).
	sameServer, err := NewGMCryptoSetupServer(connID, &tls13gm.ServerConfig{
		Certificate:       cert,
		PrivateKey:        serverKey,
		NextProtos:        []string{"echo"},
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: func([]byte, time.Duration) bool { return true },
	}, oldParams, utils.DefaultLogger, protocol.Version1, true)
	if err != nil {
		t.Fatalf("control NewGMCryptoSetupServer: %v", err)
	}
	if err := sameServer.HandleMessage(ch, protocol.EncryptionInitial); err != nil {
		t.Fatalf("control HandleMessage: %v", err)
	}
	saw0RTT := false
	for _, ev := range drainGMEvents(sameServer) {
		if ev.Kind == EventReceived0RTTReadKeys {
			saw0RTT = true
		}
	}
	if !saw0RTT {
		t.Fatal("control: unchanged params must keep the 0-RTT")
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, sm3.Size)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytes16(b byte) []byte {
	out := make([]byte, tls13gm.SessionTicketKeyLen)
	for i := range out {
		out[i] = b + byte(i)
	}
	return out
}
