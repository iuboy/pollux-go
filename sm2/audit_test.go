package sm2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestS2_H1_KeyExchange_Typography tests the upstream gmsm typo in KeyExchange
// Audit finding: S2-H1 (sm2 RepondKeyExchange 拼写错误)
func TestS2_H1_KeyExchange_Typography(t *testing.T) {
	// The upstream gmsm library has a typo "Repond" instead of "Respond" in RepondKeyExchange.
	// The wrapper in key_exchange.go handles this with a //nolint:misspell annotation.
	// This test verifies the full key exchange flow still works correctly.

	priv1, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Alice (initiator) and Bob (responder)
	alice, err := NewKeyExchangePerformer(priv1, &priv2.PublicKey, []byte("alice"), []byte("bob"), 32)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer Alice: %v", err)
	}
	bob, err := NewKeyExchangePerformer(priv2, &priv1.PublicKey, []byte("bob"), []byte("alice"), 32)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer Bob: %v", err)
	}

	// Both generate ephemeral keys
	aliceEph, err := alice.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("Alice GenerateEphemeralKey: %v", err)
	}
	bobEph, err := bob.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("Bob GenerateEphemeralKey: %v", err)
	}

	// Bob (responder) computes shared key + signature using RepondKeyExchange (upstream typo)
	bobShared, bobSig, err := bob.ComputeSharedSecretAsResponder(rand.Reader, aliceEph)
	if err != nil {
		t.Fatalf("Bob ComputeSharedSecretAsResponder: %v", err)
	}
	if len(bobShared) != 32 {
		t.Errorf("Bob shared key length: got %d, want 32", len(bobShared))
	}

	// Alice (initiator) computes shared key using Bob's ephemeral key and signature
	aliceShared, err := alice.ComputeSharedSecretAsInitiator(bobEph, bobSig)
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecretAsInitiator: %v", err)
	}
	if len(aliceShared) != 32 {
		t.Errorf("Alice shared key length: got %d, want 32", len(aliceShared))
	}

	// Both shared keys must match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Errorf("shared key mismatch:\nAlice=%x\nBob  =%x", aliceShared, bobShared)
	}
}
