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

	server, err := NewServerHandshakerWithConfig(ServerConfig{DCID: dcid, Certificate: cert, PrivateKey: serverKey})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	client, err := NewClientHandshakerWithConfig(ClientConfig{DCID: dcid, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
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

	server, err := NewServerHandshakerWithConfig(ServerConfig{DCID: dcid, Certificate: cert, PrivateKey: serverKey})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	client, err := NewClientHandshakerWithConfig(ClientConfig{DCID: dcid, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
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

// TestClientHandshaker_DoesNotAliasConfigPSK 是第四轮审计 P2 的回归守卫:
// NewClientHandshakerWithConfig 曾对 ResumptionPSK/ResumptionIdentity 直接
// 别名调用方 Config 的切片,Zero() 擦除 handshaker 副本时会把调用方 Config
// 里仍需复用的凭据一并清零。修复后构造必须真实拷贝:
//  1. 修改/清零 handshaker 侧副本不影响原 Config 切片(bytes 断言);
//  2. Zero() 之后原 Config 内容完好。
func TestClientHandshaker_DoesNotAliasConfigPSK(t *testing.T) {
	cfgPSK := []byte("resumption-psk-0123456789abcdef") // 32 bytes
	cfgIdentity := []byte("opaque-ticket-identity-blob")
	cfg := ClientConfig{
		DCID:               []byte{1, 2, 3, 4, 5, 6, 7, 8},
		InsecureSkipVerify: true,
		ResumptionPSK:      cfgPSK,
		ResumptionIdentity: cfgIdentity,
	}
	pskCopy := append([]byte(nil), cfgPSK...)
	idCopy := append([]byte(nil), cfgIdentity...)

	client, err := NewClientHandshakerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}

	// 真实拷贝断言:handshaker 副本与 Config 不共享底层数组。改写 handshaker
	// 侧副本,Config 切片必须纹丝不动。
	if &client.resumptionPSK[0] == &cfg.ResumptionPSK[0] {
		t.Fatal("resumptionPSK aliases the caller's Config backing array")
	}
	if &client.resumptionIdentity[0] == &cfg.ResumptionIdentity[0] {
		t.Fatal("resumptionIdentity aliases the caller's Config backing array")
	}
	for i := range client.resumptionPSK {
		client.resumptionPSK[i] = 0xAA
	}
	for i := range client.resumptionIdentity {
		client.resumptionIdentity[i] = 0xBB
	}
	if !bytes.Equal(cfg.ResumptionPSK, pskCopy) {
		t.Errorf("mutating the handshaker copy altered Config.ResumptionPSK: got %x", cfg.ResumptionPSK)
	}
	if !bytes.Equal(cfg.ResumptionIdentity, idCopy) {
		t.Errorf("mutating the handshaker copy altered Config.ResumptionIdentity: got %x", cfg.ResumptionIdentity)
	}

	// Zero 行为不变,且擦除只落在 handshaker 自己的副本上:Zero 后 Config
	// 内容完好。
	client.Zero()
	if !bytes.Equal(cfg.ResumptionPSK, pskCopy) {
		t.Errorf("Zero() wiped the caller's Config.ResumptionPSK: got %x", cfg.ResumptionPSK)
	}
	if !bytes.Equal(cfg.ResumptionIdentity, idCopy) {
		t.Errorf("Zero() wiped the caller's Config.ResumptionIdentity: got %x", cfg.ResumptionIdentity)
	}
}
