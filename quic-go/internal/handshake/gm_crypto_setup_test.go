package handshake

import (
	"bytes"
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
	}, serverTP, utils.DefaultLogger, protocol.Version1, true)
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
	drainGMEvents(client) // EventReceivedHandshakeReadKeys

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

// gmHandshakePair 驱动一对 GMCryptoSetup 完成完整握手（FullHandshake 测试的
// 同款流程），供会话票据相关测试复用。cb 为客户端的 GMOnClientSessionTicket
// 回调（可为 nil）。
func gmHandshakePair(t *testing.T, cb func(identity, psk []byte, ticketAgeAdd uint32, serverParams []byte)) (client, server *GMCryptoSetup) {
	t.Helper()
	cert, serverKey := gmTestServerCert(t)
	connID := protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09})
	clientTP := &wire.TransportParameters{MaxIdleTimeout: 10 * time.Second, ActiveConnectionIDLimit: 2}
	serverTP := &wire.TransportParameters{MaxIdleTimeout: 20 * time.Second, ActiveConnectionIDLimit: 2}

	var err error
	tek := make([]byte, tls13gm.SessionTicketKeyLen)
	server, err = NewGMCryptoSetupServer(connID, &tls13gm.ServerConfig{
		Certificate:       cert,
		PrivateKey:        serverKey,
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
	}, serverTP, utils.DefaultLogger, protocol.Version1, true)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	client, err = NewGMCryptoSetupClient(connID, &tls13gm.ClientConfig{
		InsecureSkipVerify: true,
	}, clientTP, utils.DefaultLogger, protocol.Version1, cb)
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
	if clientHello == nil {
		t.Fatal("client emitted no ClientHello")
	}
	if err := server.HandleMessage(clientHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	var serverHello, serverFlight []byte
	for _, ev := range drainGMEvents(server) {
		switch ev.Kind {
		case EventWriteInitialData:
			serverHello = ev.Data
		case EventWriteHandshakeData:
			serverFlight = ev.Data
		}
	}
	if err := client.HandleMessage(serverHello, protocol.EncryptionInitial); err != nil {
		t.Fatalf("client HandleMessage(ServerHello): %v", err)
	}
	drainGMEvents(client)
	if err := client.HandleMessage(serverFlight, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("client HandleMessage(server flight): %v", err)
	}
	var clientFinished []byte
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteHandshakeData {
			clientFinished = ev.Data
		}
	}
	if err := server.HandleMessage(clientFinished, protocol.EncryptionHandshake); err != nil {
		t.Fatalf("server HandleMessage(client Finished): %v", err)
	}
	return client, server
}

// gmDeliverSessionTicket 由 server 签发一张 NewSessionTicket 并投递给 client
// 的 1-RTT HandleMessage。
func gmDeliverSessionTicket(t *testing.T, client, server *GMCryptoSetup) {
	t.Helper()
	ticket, err := server.GetSessionTicket()
	if err != nil {
		t.Fatalf("GetSessionTicket: %v", err)
	}
	if len(ticket) == 0 {
		t.Fatal("server issued no session ticket")
	}
	if err := client.HandleMessage(ticket, protocol.Encryption1RTT); err != nil {
		t.Fatalf("client HandleMessage(NewSessionTicket): %v", err)
	}
}

// TestClientSessionTicket_DefensiveCopy 锁定第四轮审计 #3:ClientSessionTicket
// 返回与 GMOnClientSessionTicket 入参均为防御性拷贝——
//  1. 改写返回的 identity/psk 不影响内部状态;
//  2. 回调改写入参不影响内部状态;
//  3. Close() 对内部 PSK 的 Zero() 不会把调用方/回调持有的副本一并清零。
func TestClientSessionTicket_DefensiveCopy(t *testing.T) {
	var cbIdentity, cbPSK []byte
	cb := func(identity, psk []byte, _ uint32, _ []byte) {
		cbIdentity = append([]byte(nil), identity...)
		cbPSK = append([]byte(nil), psk...)
		// 回调改写入参:若入参是内部切片的别名,后续断言会暴露。
		for i := range identity {
			identity[i] ^= 0xAA
		}
		for i := range psk {
			psk[i] ^= 0xAA
		}
	}
	client, server := gmHandshakePair(t, cb)
	gmDeliverSessionTicket(t, client, server)

	if len(cbIdentity) == 0 || len(cbPSK) == 0 {
		t.Fatal("callback received empty identity/psk")
	}
	pristineID, pristinePSK, _ := client.ClientSessionTicket()
	if !bytes.Equal(pristineID, cbIdentity) || !bytes.Equal(pristinePSK, cbPSK) {
		t.Fatal("callback mutation of its arguments must not affect internal state")
	}

	// 改写 ClientSessionTicket 返回的切片,再次读取必须得到原值。
	mutatedID, mutatedPSK, _ := client.ClientSessionTicket()
	mutatedID[0] ^= 0xFF
	mutatedPSK[0] ^= 0xFF
	againID, againPSK, _ := client.ClientSessionTicket()
	if !bytes.Equal(againID, pristineID) {
		t.Fatal("mutating the returned identity leaked into internal state")
	}
	if !bytes.Equal(againPSK, pristinePSK) {
		t.Fatal("mutating the returned psk leaked into internal state")
	}

	// Close() Zero 内部 PSK:调用方与回调先前持有的副本必须原样存活。
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	afterCloseID, afterClosePSK, _ := client.ClientSessionTicket()
	if len(afterCloseID) != 0 || len(afterClosePSK) != 0 {
		t.Fatal("Close must clear the cached ticket fields")
	}
	var zero32 [32]byte
	if bytes.Equal(cbPSK, zero32[:]) {
		t.Fatal("the callback's copy was zeroed by Close — it must be a defensive copy")
	}
	if !bytes.Equal(cbPSK, pristinePSK) {
		t.Fatal("the callback's copy diverged from the issued PSK")
	}
}

// TestGMOnClientSessionTicket_InvokedOutsideStateMutex 锁定第四轮审计 #4:
// 回调在 stateMutex 之外执行——回调内部调用本 CryptoSetup 的加锁方法
// (ConnectionState/ClientSessionTicket)不得自死锁。修复前回调在
// HandleMessage 持锁期间被调用,此处必然卡死。
func TestGMOnClientSessionTicket_InvokedOutsideStateMutex(t *testing.T) {
	type captured struct {
		identity, psk, serverParams []byte
		ticketAgeAdd                uint32
	}
	capturedCh := make(chan captured, 1)
	var client, server *GMCryptoSetup
	cb := func(identity, psk []byte, ticketAgeAdd uint32, serverParams []byte) {
		// 若回调仍持 stateMutex,下面两个调用会自死锁,HandleMessage 永不返回。
		_ = client.ConnectionState()
		_, _, _ = client.ClientSessionTicket()
		capturedCh <- captured{
			identity:     append([]byte(nil), identity...),
			psk:          append([]byte(nil), psk...),
			ticketAgeAdd: ticketAgeAdd,
			serverParams: append([]byte(nil), serverParams...),
		}
	}
	client, server = gmHandshakePair(t, cb)

	errCh := make(chan error, 1)
	go func() {
		ticket, err := server.GetSessionTicket()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- client.HandleMessage(ticket, protocol.Encryption1RTT)
	}()

	msgTimeout := time.After(2 * time.Second)
	var msgErr error
	gotResult := false
	for !gotResult {
		select {
		case err := <-errCh:
			msgErr, gotResult = err, true
		case <-msgTimeout:
			t.Fatal("HandleMessage deadlocked — the ticket callback ran inside stateMutex")
		}
	}
	if msgErr != nil {
		t.Fatalf("HandleMessage(NewSessionTicket): %v", msgErr)
	}

	select {
	case cap := <-capturedCh:
		if len(cap.identity) == 0 || len(cap.psk) == 0 {
			t.Fatal("callback received empty identity/psk")
		}
		if len(cap.serverParams) == 0 {
			t.Fatal("callback received no server transport parameters")
		}
		id, psk, ageAdd := client.ClientSessionTicket()
		if !bytes.Equal(id, cap.identity) || !bytes.Equal(psk, cap.psk) || ageAdd != cap.ticketAgeAdd {
			t.Fatal("callback data diverges from ClientSessionTicket state")
		}
	case <-time.After(time.Second):
		t.Fatal("callback never invoked")
	}
}
