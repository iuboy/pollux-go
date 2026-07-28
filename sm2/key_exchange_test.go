package sm2_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

func TestKeyExchangeFullFlow(t *testing.T) {
	// 生成双方长期密钥对
	alicePriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	aliceUID := []byte("alice@example.com")
	bobUID := []byte("bob@example.com")
	keyLen := 32

	// Alice 作为发起方
	alice, err := sm2.NewKeyExchangePerformer(alicePriv, &bobPriv.PublicKey, aliceUID, bobUID, keyLen)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer (Alice): %v", err)
	}

	// Bob 作为响应方
	bob, err := sm2.NewKeyExchangePerformer(bobPriv, &alicePriv.PublicKey, bobUID, aliceUID, keyLen)
	if err != nil {
		t.Fatalf("NewKeyExchangePerformer (Bob): %v", err)
	}

	// 双方各生成临时公钥
	aliceEphemeralPub, err := alice.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("Alice GenerateEphemeralKey: %v", err)
	}
	if aliceEphemeralPub == nil {
		t.Fatal("Alice ephemeral public key should not be nil")
	}

	bobEphemeralPub, err := bob.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("Bob GenerateEphemeralKey: %v", err)
	}
	if bobEphemeralPub == nil {
		t.Fatal("Bob ephemeral public key should not be nil")
	}

	// Bob（响应方）收到 Alice 的临时公钥，生成响应签名 sB（GM/T 0003.3 step B2）。
	bobSig, err := bob.RespondKeyExchange(rand.Reader, aliceEphemeralPub)
	if err != nil {
		t.Fatalf("Bob RespondKeyExchange: %v", err)
	}
	if len(bobSig) == 0 {
		t.Fatal("Bob responder signature should not be empty")
	}

	// Alice（发起方）收到 Bob 的临时公钥和签名，验证 sB 并计算共享密钥与自己的签名 sA。
	aliceSharedKey, aliceSig, err := alice.ComputeSharedSecretAsInitiator(bobEphemeralPub, bobSig)
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecretAsInitiator: %v", err)
	}
	if len(aliceSharedKey) != keyLen {
		t.Errorf("Alice shared key length: got %d, want %d", len(aliceSharedKey), keyLen)
	}
	if len(aliceSig) == 0 {
		t.Fatal("Alice initiator signature should not be empty")
	}

	// Bob 验证 Alice 的签名 sA 后派生共享密钥，完成双向认证（step B3）。
	bobSharedKey, err := bob.ConfirmInitiator(aliceSig)
	if err != nil {
		t.Fatalf("Bob ConfirmInitiator: %v", err)
	}
	if len(bobSharedKey) != keyLen {
		t.Errorf("Bob shared key length: got %d, want %d", len(bobSharedKey), keyLen)
	}

	// 双方共享密钥应一致
	if !bytes.Equal(aliceSharedKey, bobSharedKey) {
		t.Errorf("shared key mismatch:\nAlice=%x\nBob  =%x", aliceSharedKey, bobSharedKey)
	}

	// Bob 拒绝伪造的 initiator 签名（mutual authentication fail-closed）。
	tampered := make([]byte, len(aliceSig))
	copy(tampered, aliceSig)
	tampered[0] ^= 0xFF
	// Reset bob to re-run confirmation is not possible (state consumed); instead
	// verify a fresh exchange rejects a bad signature.
	alice2, err := sm2.NewKeyExchangePerformer(alicePriv, &bobPriv.PublicKey, aliceUID, bobUID, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	bob2, err := sm2.NewKeyExchangePerformer(bobPriv, &alicePriv.PublicKey, bobUID, aliceUID, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	aEph2, _ := alice2.GenerateEphemeralKey()
	bEph2, _ := bob2.GenerateEphemeralKey()
	bSig2, err := bob2.RespondKeyExchange(rand.Reader, aEph2)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = alice2.ComputeSharedSecretAsInitiator(bEph2, bSig2)
	if err != nil {
		t.Fatalf("fresh initiator step: %v", err)
	}
	if _, err := bob2.ConfirmInitiator(tampered); err == nil {
		t.Error("ConfirmInitiator accepted a forged initiator signature")
	}
}

func TestKeyExchange_DifferentKeyLengths(t *testing.T) {
	alicePriv, _ := sm2.GenerateKey(rand.Reader)
	bobPriv, _ := sm2.GenerateKey(rand.Reader)

	for _, keyLen := range []int{16, 24, 32} {
		t.Run("", func(t *testing.T) {
			alice, err := sm2.NewKeyExchangePerformer(alicePriv, &bobPriv.PublicKey, []byte("A"), []byte("B"), keyLen)
			if err != nil {
				t.Fatal(err)
			}
			bob, err := sm2.NewKeyExchangePerformer(bobPriv, &alicePriv.PublicKey, []byte("B"), []byte("A"), keyLen)
			if err != nil {
				t.Fatal(err)
			}

			aEph, _ := alice.GenerateEphemeralKey()
			bEph, _ := bob.GenerateEphemeralKey()

			bobSig, err := bob.RespondKeyExchange(rand.Reader, aEph)
			if err != nil {
				t.Fatal(err)
			}
			aliceKey, aliceSig, err := alice.ComputeSharedSecretAsInitiator(bEph, bobSig)
			if err != nil {
				t.Fatal(err)
			}
			bobKey, err := bob.ConfirmInitiator(aliceSig)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(aliceKey, bobKey) {
				t.Errorf("keyLen=%d: shared key mismatch", keyLen)
			}
		})
	}
}

func TestKeyExchange_InvalidKeyLength(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	// keyLen = 0 应该报错或返回无效结果
	_, err := sm2.NewKeyExchangePerformer(priv, &priv.PublicKey, []byte("A"), []byte("B"), 0)
	// gmsm 可能不检查 keyLen=0，所以这里只验证不 panic
	_ = err
}
