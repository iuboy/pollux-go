package sm2_test

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

func TestPrivateKeyImplementsCryptoSigner(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var _ crypto.Signer = key
}

func TestSignVerifyASN1(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := []byte("test message digest")
	sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !sm2.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Error("VerifyASN1 failed for valid signature")
	}

	// Wrong digest should fail
	if sm2.VerifyASN1(&key.PublicKey, []byte("wrong"), sig) {
		t.Error("VerifyASN1 should fail for wrong digest")
	}
}

func TestSignVerifyWithSM2(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	uid := []byte("1234567812345678")
	data := []byte("GM/T 0009-2012 test data")

	sig, err := sm2.SignWithSM2(rand.Reader, key, uid, data)
	if err != nil {
		t.Fatal(err)
	}

	if !sm2.VerifyWithSM2(&key.PublicKey, uid, data, sig) {
		t.Error("VerifyWithSM2 failed for valid signature")
	}
}

func TestCryptoSignerInterface(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := []byte("crypto.Signer test")
	sig, err := key.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !sm2.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Error("Sign via crypto.Signer interface failed verification")
	}
}

func TestEncryptDecryptASN1(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("SM2 encryption test")
	ciphertext, err := sm2.EncryptASN1(rand.Reader, &key.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := sm2.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != string(msg) {
		t.Errorf("decrypted mismatch: got %q, want %q", plaintext, msg)
	}
}

func TestP256(t *testing.T) {
	curve := sm2.P256()
	if curve == nil {
		t.Error("P256() returned nil")
	}
	if curve.Params().BitSize != 256 {
		t.Errorf("P256 bit size = %d, want 256", curve.Params().BitSize)
	}
}

func TestNewPrivateKeyDER(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// NewPrivateKey 期望原始 32 字节标量（不是 DER）
	// 使用 PrivateKeyToBytesSecure 而非弃用的 PrivateKeyToBytes，
	// SecureKeyBytes 在使用后必须 Destroy 以清零敏感内存。
	skb, err := sm2.PrivateKeyToBytesSecure(key)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	keyBytes := skb.Data()

	parsed, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Error("parsed private key mismatch")
	}
}

func TestNewPrivateKey_InvalidDER(t *testing.T) {
	_, err := sm2.NewPrivateKey([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("should reject invalid DER")
	}
}

func TestNewPublicKeyDER(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 序列化公钥为未压缩格式再解析
	pubBytes := sm2.MarshalUncompressed(&key.PublicKey)
	pubKey2, err := sm2.UnmarshalUncompressed(pubBytes)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}
	if !sm2.Equal(pubKey2, &key.PublicKey) {
		t.Error("public key round-trip mismatch")
	}
}

func TestNewPublicKey_InvalidDER(t *testing.T) {
	_, err := sm2.NewPublicKey([]byte{0x00})
	if err == nil {
		t.Error("should reject invalid DER")
	}
}

func TestNewSM2SignerOption(t *testing.T) {
	uid := []byte("1234567812345678")
	opts := sm2.NewSM2SignerOption(true, uid)
	if opts == nil {
		t.Fatal("NewSM2SignerOption returned nil")
	}

	// 使用该选项签名并验证
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("test with NewSM2SignerOption")
	sig, err := sm2.SignASN1(rand.Reader, key, data, opts)
	if err != nil {
		t.Fatalf("SignASN1 with NewSM2SignerOption: %v", err)
	}
	if !sm2.VerifyWithSM2(&key.PublicKey, uid, data, sig) {
		t.Error("VerifyWithSM2 failed for signature made with NewSM2SignerOption")
	}
}
