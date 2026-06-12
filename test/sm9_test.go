package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM9 "github.com/iuboy/pollux-go/sm9"
)

// ========== 签名主密钥 ==========

func TestBlackBox_SM9_GenerateSignMasterKey(t *testing.T) {
	master, err := polluxSM9.GenerateSignMasterKey()
	if err != nil {
		t.Fatalf("GenerateSignMasterKey: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
	if master.PublicKey() == nil {
		t.Fatal("public key should not be nil")
	}
}

func TestBlackBox_SM9_SignVerify(t *testing.T) {
	master, _ := polluxSM9.GenerateSignMasterKey()
	uid := []byte("alice@test.com")
	userKey, err := polluxSM9.GenerateSignUserKey(master, uid)
	if err != nil {
		t.Fatalf("GenerateSignUserKey: %v", err)
	}

	hash := []byte("SM9 sign/verify black-box test")
	sig, err := polluxSM9.Sign(userKey, hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	if !polluxSM9.Verify(master.PublicKey(), uid, hash, sig) {
		t.Error("Verify should accept valid signature")
	}
}

func TestBlackBox_SM9_SignVerify_WrongUID(t *testing.T) {
	master, _ := polluxSM9.GenerateSignMasterKey()
	uid := []byte("alice@test.com")
	userKey, _ := polluxSM9.GenerateSignUserKey(master, uid)

	sig, _ := polluxSM9.Sign(userKey, []byte("test"))

	wrongUID := []byte("bob@test.com")
	if polluxSM9.Verify(master.PublicKey(), wrongUID, []byte("test"), sig) {
		t.Error("Verify should reject wrong UID")
	}
}

func TestBlackBox_SM9_SignVerify_WrongHash(t *testing.T) {
	master, _ := polluxSM9.GenerateSignMasterKey()
	uid := []byte("alice@test.com")
	userKey, _ := polluxSM9.GenerateSignUserKey(master, uid)

	sig, _ := polluxSM9.Sign(userKey, []byte("hash1"))
	if polluxSM9.Verify(master.PublicKey(), uid, []byte("hash2"), sig) {
		t.Error("Verify should reject wrong hash")
	}
}

func TestBlackBox_SM9_SignVerify_TamperedSig(t *testing.T) {
	master, _ := polluxSM9.GenerateSignMasterKey()
	uid := []byte("alice@test.com")
	userKey, _ := polluxSM9.GenerateSignUserKey(master, uid)

	sig, _ := polluxSM9.Sign(userKey, []byte("test"))
	sig[0] ^= 0xff
	if polluxSM9.Verify(master.PublicKey(), uid, []byte("test"), sig) {
		t.Error("Verify should reject tampered signature")
	}
}

// ========== 加密主密钥 ==========

func TestBlackBox_SM9_GenerateEncryptMasterKey(t *testing.T) {
	master, err := polluxSM9.GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
	if master.PublicKey() == nil {
		t.Fatal("public key should not be nil")
	}
}

func TestBlackBox_SM9_EncryptDecrypt(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("bob@test.com")
	userKey, err := polluxSM9.GenerateEncryptUserKey(master, uid)
	if err != nil {
		t.Fatalf("GenerateEncryptUserKey: %v", err)
	}

	plaintext := []byte("SM9 encrypt/decrypt black-box test")
	ct, err := polluxSM9.Encrypt(master.PublicKey(), uid, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	decrypted, err := polluxSM9.Decrypt(userKey, uid, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestBlackBox_SM9_EncryptDecrypt_Empty(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("empty@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)

	ct, _ := polluxSM9.Encrypt(master.PublicKey(), uid, []byte{}, nil)
	decrypted, _ := polluxSM9.Decrypt(userKey, uid, ct)
	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %q", decrypted)
	}
}

func TestBlackBox_SM9_EncryptDecrypt_WrongUID(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("bob@test.com")
	wrongUID := []byte("eve@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)

	ct, _ := polluxSM9.Encrypt(master.PublicKey(), uid, []byte("secret"), nil)
	_, err := polluxSM9.Decrypt(userKey, wrongUID, ct)
	if err == nil {
		t.Error("should reject wrong UID")
	}
}

func TestBlackBox_SM9_EncryptDecrypt_Tampered(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("tamper@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)

	ct, _ := polluxSM9.Encrypt(master.PublicKey(), uid, []byte("tamper test"), nil)
	ct[0] ^= 0xff
	_, err := polluxSM9.Decrypt(userKey, uid, ct)
	if err == nil {
		t.Error("should reject tampered ciphertext")
	}
}

func TestBlackBox_SM9_EncryptDecrypt_Large(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("large@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)
	plaintext := make([]byte, 4096)
	_, _ = rand.Read(plaintext)

	ct, _ := polluxSM9.Encrypt(master.PublicKey(), uid, plaintext, nil)
	decrypted, err := polluxSM9.Decrypt(userKey, uid, ct)
	if err != nil {
		t.Fatalf("Decrypt large: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large payload roundtrip mismatch")
	}
}

// ========== WrapKey / UnwrapKey ==========

func TestBlackBox_SM9_WrapUnwrapKey(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("wrap@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)
	keyLen := 32

	key, wrapped, err := polluxSM9.WrapKey(master.PublicKey(), uid, keyLen)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if len(key) != keyLen {
		t.Errorf("key length: got %d, want %d", len(key), keyLen)
	}

	unwrapped, err := polluxSM9.UnwrapKey(userKey, uid, wrapped, keyLen)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(unwrapped, key) {
		t.Error("unwrapped key mismatch")
	}
}

func TestBlackBox_SM9_WrapKeyASN1(t *testing.T) {
	master, err := polluxSM9.GenerateEncryptMasterKey()
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKey: %v", err)
	}
	uid := []byte("asn1wrap@test.com")
	keyLen := 16

	wrapped, err := polluxSM9.WrapKeyASN1(master.PublicKey(), uid, keyLen)
	if err != nil {
		t.Fatalf("WrapKeyASN1: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped key should not be empty")
	}

	// WrapKeyASN1 返回 ASN.1 DER 编码，验证以 SEQUENCE tag 开头
	if wrapped[0] != 0x30 {
		t.Errorf("ASN.1 output should start with SEQUENCE tag (0x30), got 0x%02x", wrapped[0])
	}
}

func TestBlackBox_SM9_WrapKey_DifferentKeyLengths(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("klen@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)

	for _, klen := range []int{16, 24, 32} {
		key, wrapped, err := polluxSM9.WrapKey(master.PublicKey(), uid, klen)
		if err != nil {
			t.Fatalf("WrapKey klen=%d: %v", klen, err)
		}
		unwrapped, err := polluxSM9.UnwrapKey(userKey, uid, wrapped, klen)
		if err != nil {
			t.Fatalf("UnwrapKey klen=%d: %v", klen, err)
		}
		if !bytes.Equal(unwrapped, key) {
			t.Errorf("klen=%d: unwrap mismatch", klen)
		}
	}
}

func TestBlackBox_SM9_WrapKey_WrongUID(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("real@test.com")
	wrongUID := []byte("fake@test.com")

	key, wrapped, _ := polluxSM9.WrapKey(master.PublicKey(), uid, 16)

	// 用正确 userKey + 正确 UID 解封装
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)
	correctUnwrap, _ := polluxSM9.UnwrapKey(userKey, uid, wrapped, 16)
	if !bytes.Equal(correctUnwrap, key) {
		t.Error("correct UID unwrap should match original key")
	}

	// 用正确 userKey 但传 wrongUID 解封装——SM9 算法不会报错，但会得到不匹配的 key
	wrongUnwrap, err := polluxSM9.UnwrapKey(userKey, wrongUID, wrapped, 16)
	if err != nil {
		// 如果底层库实际拒绝了，那也是好的
		return
	}
	if bytes.Equal(wrongUnwrap, key) {
		t.Error("wrong UID unwrap should produce different key than original")
	}
}

func TestBlackBox_SM9_WrapKey_TamperedCipher(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	uid := []byte("tamper@test.com")
	userKey, _ := polluxSM9.GenerateEncryptUserKey(master, uid)

	_, wrapped, _ := polluxSM9.WrapKey(master.PublicKey(), uid, 16)
	wrapped[0] ^= 0xff

	_, err := polluxSM9.UnwrapKey(userKey, uid, wrapped, 16)
	if err == nil {
		t.Error("UnwrapKey with tampered cipher should fail")
	}
}

func TestBlackBox_SM9_WrapKey_EmptyUID(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	_, _, err := polluxSM9.WrapKey(master.PublicKey(), []byte{}, 16)
	if err == nil {
		t.Error("WrapKey with empty UID should fail")
	}
}

func TestBlackBox_SM9_WrapKeyASN1_EmptyUID(t *testing.T) {
	master, _ := polluxSM9.GenerateEncryptMasterKey()
	_, err := polluxSM9.WrapKeyASN1(master.PublicKey(), []byte{}, 16)
	if err == nil {
		t.Error("WrapKeyASN1 with empty UID should fail")
	}
}

// ========== FromReader ==========

func TestBlackBox_SM9_GenerateSignMasterKeyFromReader(t *testing.T) {
	master, err := polluxSM9.GenerateSignMasterKeyFromReader(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateSignMasterKeyFromReader: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
}

func TestBlackBox_SM9_GenerateEncryptMasterKeyFromReader(t *testing.T) {
	master, err := polluxSM9.GenerateEncryptMasterKeyFromReader(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEncryptMasterKeyFromReader: %v", err)
	}
	if master == nil {
		t.Fatal("master key should not be nil")
	}
}

// ========== 默认 HID ==========

func TestBlackBox_SM9_DefaultHID(t *testing.T) {
	if polluxSM9.DefaultSignHID != 0x01 {
		t.Errorf("DefaultSignHID: got %d, want 1", polluxSM9.DefaultSignHID)
	}
	if polluxSM9.DefaultEncryptHID != 0x03 {
		t.Errorf("DefaultEncryptHID: got %d, want 3", polluxSM9.DefaultEncryptHID)
	}
}
