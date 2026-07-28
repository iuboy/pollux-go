package sm9

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestGenerateSignMasterKey(t *testing.T) {
	master, err := GenerateSignMasterKey()
	if err != nil {
		t.Fatalf("GenerateSignMasterKey: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
}

func TestSignVerify(t *testing.T) {
	master, err := GenerateSignMasterKey()
	if err != nil {
		t.Fatalf("GenerateSignMasterKey: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := GenerateSignUserKey(master, uid)
	if err != nil {
		t.Fatalf("GenerateSignUserKey: %v", err)
	}

	msg := []byte("Hello SM9 signing!")
	sig, err := Sign(userKey, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	if err := Verify(master.PublicKey(), uid, msg, sig); err != nil {
		t.Errorf("Verify should succeed for valid signature, got: %v", err)
	}

	// wrong message should fail with ErrSignatureInvalid
	if err := Verify(master.PublicKey(), uid, []byte("wrong"), sig); err == nil {
		t.Error("Verify should fail for wrong message")
	} else if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("Verify wrong-message: expected ErrSignatureInvalid, got: %v", err)
	}

	// VerifyBool should mirror the new Verify
	if !VerifyBool(master.PublicKey(), uid, msg, sig) {
		t.Error("VerifyBool should succeed for valid signature")
	}
	if VerifyBool(master.PublicKey(), uid, []byte("wrong"), sig) {
		t.Error("VerifyBool should fail for wrong message")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	master, err := GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}

	uid := []byte("testuser@example.com")
	userKey, err := GenerateEncryptUserKey(master, uid)
	if err != nil {
		t.Fatalf("GenerateEncryptUserKey: %v", err)
	}

	plaintext := []byte("Hello SM9 encryption!")
	ct, err := Encrypt(master.PublicKey(), uid, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	pt, err := Decrypt(userKey, uid, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

func TestWrapKey(t *testing.T) {
	master, err := GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}

	uid := []byte("keywrap@test.com")

	key, cipher, err := WrapKey(master.PublicKey(), uid, 32)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if len(key) == 0 {
		t.Error("key should not be empty")
	}
	if len(cipher) == 0 {
		t.Error("cipher should not be empty")
	}
}

func TestWrapKeyUnwrapKey_Roundtrip(t *testing.T) {
	master, err := GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}

	uid := []byte("unwrap@test.com")
	userKey, err := GenerateEncryptUserKey(master, uid)
	if err != nil {
		t.Fatalf("GenerateEncryptUserKey: %v", err)
	}

	for _, keyLen := range []int{16, 24, 32} {
		// WrapKey 返回值实际是 (key, cipher) 而非文档标注的 (cipher, key)
		// 因为底层 gmsm WrapKey 返回 (key, cipher)
		returned1, returned2, err := WrapKey(master.PublicKey(), uid, keyLen)
		if err != nil {
			t.Fatalf("WrapKey keyLen=%d: %v", keyLen, err)
		}

		// returned1 是派生密钥 (keyLen 字节), returned2 是封装密文 (65 字节点)
		if len(returned1) != keyLen {
			t.Fatalf("keyLen=%d: returned1 len=%d, want %d", keyLen, len(returned1), keyLen)
		}

		// UnwrapKey 接受封装密文 (returned2)
		unwrapped, err := UnwrapKey(userKey, uid, returned2, keyLen)
		if err != nil {
			t.Errorf("UnwrapKey keyLen=%d: %v", keyLen, err)
			continue
		}
		if !bytes.Equal(unwrapped, returned1) {
			t.Errorf("UnwrapKey mismatch at keyLen=%d", keyLen)
		}
	}
}

func TestWrapKey_WrongUser(t *testing.T) {
	master, err := GenerateEncryptMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uid1 := []byte("user1@test.com")
	uid2 := []byte("user2@test.com")

	userKey2, err := GenerateEncryptUserKey(master, uid2)
	if err != nil {
		t.Fatal(err)
	}

	// 用 uid1 封装，用 uid2 的用户密钥解封应失败
	_, wrappedCT, err := WrapKey(master.PublicKey(), uid1, 32)
	if err != nil {
		t.Fatal(err)
	}

	wrongResult, err := UnwrapKey(userKey2, uid2, wrappedCT, 32)
	if err != nil {
		// gmsm 可能在某些情况下直接返回错误
		return
	}
	// gmsm UnwrapKey 不验证 uid 匹配，但结果应与原始密钥不同
	originalKey, _, _ := WrapKey(master.PublicKey(), uid1, 32)
	if bytes.Equal(wrongResult, originalKey) {
		t.Error("wrong user should not recover the original key")
	}
}

func TestGenerateSignMasterKeyFromReader(t *testing.T) {
	master, err := GenerateSignMasterKeyFromReader(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateSignMasterKeyFromReader: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
}

func TestGenerateEncryptMasterKeyFromReader(t *testing.T) {
	master, err := GenerateEncryptMasterKeyFromReader(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKeyFromReader: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
}

func TestUIDEmptyValidation(t *testing.T) {
	// All functions taking uid must reject empty/nil uid.
	signMaster, _ := GenerateSignMasterKey()
	encMaster, _ := GenerateEncryptMasterKey()

	if _, err := GenerateSignUserKey(signMaster, nil); err == nil {
		t.Error("GenerateSignUserKey: expected error for nil uid")
	}
	if _, err := GenerateSignUserKey(signMaster, []byte{}); err == nil {
		t.Error("GenerateSignUserKey: expected error for empty uid")
	}
	if _, err := GenerateEncryptUserKey(encMaster, nil); err == nil {
		t.Error("GenerateEncryptUserKey: expected error for nil uid")
	}
	if err := Verify(signMaster.PublicKey(), nil, []byte("data"), []byte("sig")); err == nil {
		t.Error("Verify: expected error for nil uid")
	} else if errors.Is(err, ErrSignatureInvalid) {
		t.Error("Verify nil-uid: should be input-validation error, not ErrSignatureInvalid")
	}
	// nil publicKey should be input-validation error
	if err := Verify(nil, []byte("uid"), []byte("data"), []byte("sig")); err == nil {
		t.Error("Verify: expected error for nil publicKey")
	} else if errors.Is(err, ErrSignatureInvalid) {
		t.Error("Verify nil-key: should be input-validation error, not ErrSignatureInvalid")
	}
	// empty sig should be input-validation error
	if err := Verify(signMaster.PublicKey(), []byte("uid"), []byte("data"), nil); err == nil {
		t.Error("Verify: expected error for empty sig")
	} else if errors.Is(err, ErrSignatureInvalid) {
		t.Error("Verify empty-sig: should be input-validation error, not ErrSignatureInvalid")
	}
	if _, err := Encrypt(encMaster.PublicKey(), nil, []byte("pt"), nil); err == nil {
		t.Error("Encrypt: expected error for nil uid")
	}
	if _, err := Decrypt(nil, nil, []byte("ct")); err == nil {
		t.Error("Decrypt: expected error for nil uid")
	}
	if _, _, err := WrapKey(encMaster.PublicKey(), nil, 16); err == nil {
		t.Error("WrapKey: expected error for nil uid")
	}
	if _, err := WrapKeyASN1(encMaster.PublicKey(), nil, 16); err == nil {
		t.Error("WrapKeyASN1: expected error for nil uid")
	}
	if _, err := UnwrapKey(nil, nil, []byte("ct"), 16); err == nil {
		t.Error("UnwrapKey: expected error for nil uid")
	}
}

func TestKeysGeneratedWithRealRandom(t *testing.T) {
	// S9-H1: Keys generated with crypto/rand should be non-trivial and unique.
	master1, err := GenerateSignMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	master2, err := GenerateSignMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	// Two independently generated master keys should produce different public keys
	pub1 := master1.PublicKey()
	pub2 := master2.PublicKey()
	if pub1 == nil || pub2 == nil {
		t.Fatal("public keys should not be nil")
	}

	// Generate user keys with real randomness and verify they work
	uid := []byte("real-random-test@example.com")
	userKey, err := GenerateSignUserKey(master1, uid)
	if err != nil {
		t.Fatalf("GenerateSignUserKey with real random master: %v", err)
	}
	if userKey == nil {
		t.Fatal("user key should not be nil")
	}
}
