package tls13gm

// 第三轮安全审查 H1/H2 回归测试。

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm3"
	"github.com/iuboy/pollux-go/smx509"
)

// TestServerHandshake_DeclinedPSKNoEarlyKeys locks the H1 fix: a ClientHello
// carrying early_data whose PSK identity the server cannot decrypt is DECLINED
// to a full handshake, and the server must NOT derive 0-RTT keys. Before the
// fix, the early-data acceptance block ran with the nil (declined) PSK, feeding
// DeriveEarlySecret's zero-IKM fallback — producing "0-RTT keys" that are a
// function of public data only, letting any attacker inject data the server
// would decrypt and deliver.
func TestServerHandshake_DeclinedPSKNoEarlyKeys(t *testing.T) {
	dcid := []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8}
	cert, serverKey := generateTestSM2Cert(t)
	psk := bytes.Repeat([]byte{0x3C}, sm3.Size)
	rightTek := bytes.Repeat([]byte{0x9B}, SessionTicketKeyLen)
	wrongTek := bytes.Repeat([]byte{0x44}, SessionTicketKeyLen)
	identity, err := EncryptSessionTicket(rightTek, psk, 0)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}
	acceptAll := func([]byte, time.Duration) bool { return true }

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
		EarlyData:                     true,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}

	// Control: with the ticket decryptable and an accept-all acceptor, the
	// server derives 0-RTT keys.
	serverOK, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:              dcid,
		Certificate:       cert,
		PrivateKey:        serverKey,
		SessionTicketKeys: func() [][]byte { return [][]byte{rightTek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	if err := serverOK.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello (recognized PSK): %v", err)
	}
	if serverOK.Secrets().ClientEarlyKeys == nil {
		t.Fatal("control: recognized PSK + accept-all acceptor must derive ClientEarlyKeys")
	}

	// Regression: the same ClientHello against a server holding the WRONG TEK
	// declines the PSK. Even with AllowEarlyData and an accept-all acceptor,
	// deriving early keys from the nil PSK must not happen.
	serverDecline, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:              dcid,
		Certificate:       cert,
		PrivateKey:        serverKey,
		SessionTicketKeys: func() [][]byte { return [][]byte{wrongTek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: acceptAll,
	})
	if err != nil {
		t.Fatalf("NewServerHandshakerWithConfig: %v", err)
	}
	if err := serverDecline.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello (declined PSK) must not abort: %v", err)
	}
	if got := serverDecline.Secrets().ClientEarlyKeys; got != nil {
		t.Fatalf("0-RTT keys derived from a DECLINED (nil) PSK — the zero-IKM early secret is publicly computable (keys %x)", got.AEADKey)
	}
}

// TestNewClientHandshaker_RequiresServerNameWithRoots locks the H2 fix: with
// Roots configured, an empty ServerName makes hostname verification a no-op
// (smx509 skips matching on an empty DNSName), silently degrading to
// chain-only validation. The constructor must reject that combination.
func TestNewClientHandshaker_RequiresServerNameWithRoots(t *testing.T) {
	_, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:  []byte{0x01, 0x02, 0x03, 0x04},
		Roots: smx509.NewCertPool(),
	})
	if err == nil {
		t.Fatal("empty ServerName with Roots configured must be rejected")
	}
	if !strings.Contains(err.Error(), "ServerName") {
		t.Fatalf("error should name ServerName, got: %v", err)
	}
	// InsecureSkipVerify is an explicit opt-out and must still construct.
	if _, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:               []byte{0x01, 0x02, 0x03, 0x04},
		Roots:              smx509.NewCertPool(),
		InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("InsecureSkipVerify opt-out must construct: %v", err)
	}
}

// TestHandleHelloRetryRequest_WithdrawsEarlyData locks the M3 fixes (third
// security review): after a HelloRetryRequest the client (a) drops the
// CH1-derived 0-RTT keys, (b) withdraws the early-data offer so ClientHello2
// carries no early_data extension (RFC 8446 §4.2.10), and (c) computes the
// CH2 binder over message_hash(CH1) || HRR || Truncate(CH2) as RFC 8446
// §4.2.11.2 requires — without the prefix the binder mismatches any
// spec-compliant server (Tongsuo/OpenSSL) after an HRR.
func TestHandleHelloRetryRequest_WithdrawsEarlyData(t *testing.T) {
	dcid := []byte{0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8}
	psk := bytes.Repeat([]byte{0x5A}, sm3.Size)
	tek := bytes.Repeat([]byte{0x6B}, SessionTicketKeyLen)
	identity, err := EncryptSessionTicket(tek, psk, 0)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
		EarlyData:                     true,
	})
	if err != nil {
		t.Fatalf("NewClientHandshakerWithConfig: %v", err)
	}
	ch1, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if client.Secrets().ClientEarlyKeys == nil {
		t.Fatal("CH1 with PSK + early_data must derive early keys")
	}
	_, body1, _, err := ReadHandshakeMessage(ch1)
	if err != nil {
		t.Fatalf("read CH1: %v", err)
	}
	var ch1Msg ClientHelloMsg
	if err := ch1Msg.unmarshalBody(body1); err != nil {
		t.Fatalf("CH1 unmarshal: %v", err)
	}
	if !hasExtension(ch1Msg.Extensions, ExtensionTypeEarlyData) {
		t.Fatal("CH1 must carry early_data")
	}

	hrr := buildTestHRR(t, []byte("retry-cookie"))
	ch2, err := client.HandleHelloRetryRequest(hrr)
	if err != nil {
		t.Fatalf("HandleHelloRetryRequest: %v", err)
	}
	if client.Secrets().ClientEarlyKeys != nil {
		t.Fatal("CH1-derived early keys must be dropped after an HRR")
	}
	if client.EarlyDataOffered() {
		t.Fatal("early-data offer must be withdrawn after an HRR")
	}

	_, body2, _, err := ReadHandshakeMessage(ch2)
	if err != nil {
		t.Fatalf("read CH2: %v", err)
	}
	var ch2Msg ClientHelloMsg
	if err := ch2Msg.unmarshalBody(body2); err != nil {
		t.Fatalf("CH2 unmarshal: %v", err)
	}
	if hasExtension(ch2Msg.Extensions, ExtensionTypeEarlyData) {
		t.Fatal("CH2 must NOT carry early_data (RFC 8446 §4.2.10)")
	}
	// PSK resumption itself survives the HRR: pre_shared_key stays the last
	// extension, but its binder must now cover the HRR transcript prefix.
	pskExt := ch2Msg.Extensions[len(ch2Msg.Extensions)-1]
	if pskExt.Type != ExtensionTypePreSharedKey {
		t.Fatalf("CH2 last extension = %d, want pre_shared_key", pskExt.Type)
	}
	identities, binders, err := parsePreSharedKeyExtension(pskExt.Data)
	if err != nil || len(binders) != 1 {
		t.Fatalf("parse CH2 pre_shared_key: %v, binders %d", err, len(binders))
	}
	// Independently reconstruct the RFC §4.2.11.2 binder transcript:
	// the message_hash(CH1) synthetic message, then the HRR, then Truncate(CH2).
	hash1 := sm3.Sum(ch1)
	var mh [4]byte
	mh[0] = HandshakeTypeMessageHash
	mh[1] = byte(len(hash1) >> 16)
	mh[2] = byte(len(hash1) >> 8)
	mh[3] = byte(len(hash1))
	prefix := append(append([]byte{}, mh[:]...), hash1[:]...)
	prefix = append(prefix, hrr...)
	trunc, err := pskBinderTranscript(&ch2Msg, identities)
	if err != nil {
		t.Fatalf("CH2 binder transcript: %v", err)
	}
	want, err := computeResumptionBinder(psk, append(prefix, trunc...))
	if err != nil {
		t.Fatalf("recompute binder: %v", err)
	}
	if !bytes.Equal(binders[0], want) {
		t.Fatalf("CH2 binder must cover message_hash(CH1)||HRR||Truncate(CH2):\n got %x\n want %x", binders[0], want)
	}
}
