package tls13gm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

func quicTestSecret() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func TestDeriveQUICPacketKeys(t *testing.T) {
	keys, err := DeriveQUICPacketKeys(quicTestSecret())
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	defer keys.Zero()
	if len(keys.AEADKey) != 16 {
		t.Errorf("AEADKey: got %d, want 16", len(keys.AEADKey))
	}
	if len(keys.AEADIV) != 12 {
		t.Errorf("AEADIV: got %d, want 12", len(keys.AEADIV))
	}
	if len(keys.HeaderKey) != 16 {
		t.Errorf("HeaderKey: got %d, want 16", len(keys.HeaderKey))
	}
}

func TestDeriveQUICPacketKeys_Deterministic(t *testing.T) {
	k1, _ := DeriveQUICPacketKeys(quicTestSecret())
	defer k1.Zero()
	k2, _ := DeriveQUICPacketKeys(quicTestSecret())
	defer k2.Zero()
	if !bytes.Equal(k1.AEADKey, k2.AEADKey) || !bytes.Equal(k1.HeaderKey, k2.HeaderKey) {
		t.Error("same secret should derive identical keys")
	}
}

func TestDeriveQUICPacketKeys_EmptySecret(t *testing.T) {
	if _, err := DeriveQUICPacketKeys(nil); err == nil {
		t.Error("empty secret should fail")
	}
}

// TestDeriveQUICPacketKeys_DistinctFromTLS verifies that the "quic key" label
// produces a different key than the TLS 1.3 "key" label for the same secret.
func TestDeriveQUICPacketKeys_DistinctFromTLS(t *testing.T) {
	qk, _ := DeriveQUICPacketKeys(quicTestSecret())
	defer qk.Zero()
	tk, _ := DeriveTrafficKeys(quicTestSecret(), 16, 12)
	if bytes.Equal(qk.AEADKey, tk.Key) {
		t.Error("QUIC AEAD key must differ from TLS traffic key (different labels)")
	}
}

func TestQUICKeyUpdate(t *testing.T) {
	secret := quicTestSecret()
	next, err := QUICKeyUpdate(secret)
	if err != nil {
		t.Fatalf("QUICKeyUpdate: %v", err)
	}
	if len(next) != len(secret) {
		t.Errorf("updated secret length: got %d, want %d", len(next), len(secret))
	}
	if bytes.Equal(next, secret) {
		t.Error("key update should produce a different secret")
	}
}

func TestQUICKeyUpdate_EmptySecret(t *testing.T) {
	if _, err := QUICKeyUpdate(nil); err == nil {
		t.Error("empty secret should fail")
	}
}

func TestHeaderProtectionMask(t *testing.T) {
	hpKey := bytes.Repeat([]byte{0x01}, 16)
	sample := bytes.Repeat([]byte{0x02}, 16)
	m1, err := HeaderProtectionMask(hpKey, sample)
	if err != nil {
		t.Fatalf("HeaderProtectionMask: %v", err)
	}
	if len(m1) != 16 {
		t.Errorf("mask length: got %d, want 16", len(m1))
	}
	m2, _ := HeaderProtectionMask(hpKey, sample)
	if !bytes.Equal(m1, m2) {
		t.Error("mask should be deterministic")
	}
}

func TestHeaderProtectionMask_InvalidArgs(t *testing.T) {
	sample := bytes.Repeat([]byte{0x02}, 16)
	if _, err := HeaderProtectionMask(bytes.Repeat([]byte{0x01}, 15), sample); err == nil {
		t.Error("15-byte key should fail")
	}
	hpKey := bytes.Repeat([]byte{0x01}, 16)
	if _, err := HeaderProtectionMask(hpKey, bytes.Repeat([]byte{0x02}, 15)); err == nil {
		t.Error("15-byte sample should fail")
	}
}

func TestDeriveQUICInitialSecret(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	secret, err := DeriveQUICInitialSecret(dcid)
	if err != nil {
		t.Fatalf("DeriveQUICInitialSecret: %v", err)
	}
	if len(secret) != sm3.Size {
		t.Errorf("initial secret length: got %d, want %d", len(secret), sm3.Size)
	}
	secret2, _ := DeriveQUICInitialSecret(dcid)
	if !bytes.Equal(secret, secret2) {
		t.Error("initial secret should be deterministic")
	}
}

func TestDeriveQUICInitialSecret_EmptyDCID(t *testing.T) {
	if _, err := DeriveQUICInitialSecret(nil); err == nil {
		t.Error("empty dcid should fail")
	}
}

func TestDeriveQUICInitialSecrets(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	clientIn, serverIn, err := DeriveQUICInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("DeriveQUICInitialSecrets: %v", err)
	}
	if len(clientIn) != sm3.Size || len(serverIn) != sm3.Size {
		t.Errorf("secret lengths: client=%d server=%d, want %d", len(clientIn), len(serverIn), sm3.Size)
	}
	if bytes.Equal(clientIn, serverIn) {
		t.Error("client and server initial secrets must differ")
	}
	c2, s2, _ := DeriveQUICInitialSecrets(dcid)
	if !bytes.Equal(clientIn, c2) || !bytes.Equal(serverIn, s2) {
		t.Error("initial secrets should be deterministic")
	}
}

func TestDeriveQUICInitialSecrets_DifferentDCID(t *testing.T) {
	c1, _, _ := DeriveQUICInitialSecrets([]byte{0x01})
	c2, _, _ := DeriveQUICInitialSecrets([]byte{0x02})
	if bytes.Equal(c1, c2) {
		t.Error("different dcids should derive different secrets")
	}
}

// TestDeriveQUICPacketKeys_FromInitialSecret exercises the full Initial-key
// chain: dcid -> initial secret -> client in -> packet keys.
func TestDeriveQUICPacketKeys_FromInitialSecret(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	clientIn, _, err := DeriveQUICInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("DeriveQUICInitialSecrets: %v", err)
	}
	keys, err := DeriveQUICPacketKeys(clientIn)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys from initial secret: %v", err)
	}
	defer keys.Zero()
	if len(keys.AEADKey) != 16 || len(keys.AEADIV) != 12 || len(keys.HeaderKey) != 16 {
		t.Error("initial packet keys have wrong lengths")
	}
}

// --- Benchmarks ---

func BenchmarkHeaderProtectionMask(b *testing.B) {
	hpKey := bytes.Repeat([]byte{0x01}, 16)
	sample := bytes.Repeat([]byte{0x02}, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HeaderProtectionMask(hpKey, sample)
	}
}

func BenchmarkDeriveQUICPacketKeys(b *testing.B) {
	secret := quicTestSecret()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys, _ := DeriveQUICPacketKeys(secret)
		keys.Zero()
	}
}

func BenchmarkDeriveQUICInitialSecrets(b *testing.B) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DeriveQUICInitialSecrets(dcid)
	}
}
