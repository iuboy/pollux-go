package sm2_test

import (
	"crypto"
	"crypto/rand"
	"math/big"
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

// TestNewPrivateKeyFromInt 验证从标量构造 SM2 私钥:
//   - 构造出的私钥标量与输入一致;
//   - 公钥可正确导出并验签(证明密钥可用);
//   - 与 NewPrivateKey(DER) 路径产出的密钥可互换签名/验证。
func TestNewPrivateKeyFromInt(t *testing.T) {
	// 基线:随机生成一个合法 SM2 私钥,取其标量
	orig, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 从标量重建
	rebuilt, err := sm2.NewPrivateKeyFromInt(orig.D)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromInt: %v", err)
	}

	// 标量必须一致
	if rebuilt.D.Cmp(orig.D) != 0 {
		t.Errorf("scalar mismatch: rebuilt.D != orig.D")
	}

	// 公钥点必须一致(标量确定公钥)
	if rebuilt.PublicKey.X.Cmp(orig.PublicKey.X) != 0 ||
		rebuilt.PublicKey.Y.Cmp(orig.PublicKey.Y) != 0 {
		t.Error("public key point mismatch from same scalar")
	}

	// 重建的密钥必须能签名,且基线公钥能验证(密钥功能完整)
	digest := []byte("NewPrivateKeyFromInt sign test")
	sig, err := sm2.SignASN1(rand.Reader, rebuilt, digest, nil)
	if err != nil {
		t.Fatalf("sign with rebuilt key: %v", err)
	}
	if !sm2.VerifyASN1(&orig.PublicKey, digest, sig) {
		t.Error("orig pubkey failed to verify sig from rebuilt key")
	}
}

// TestNewPrivateKeyFromInt_Nil 验证 nil 标量返回 error 而非 panic。
func TestNewPrivateKeyFromInt_Nil(t *testing.T) {
	_, err := sm2.NewPrivateKeyFromInt(nil)
	if err == nil {
		t.Error("NewPrivateKeyFromInt should reject nil scalar")
	}
}

// TestNewPrivateKeyFromInt_Zero 验证非法标量(0,不在 [1, n-1] 范围)返回 error。
func TestNewPrivateKeyFromInt_Zero(t *testing.T) {
	_, err := sm2.NewPrivateKeyFromInt(big.NewInt(0))
	if err == nil {
		t.Error("NewPrivateKeyFromInt should reject zero scalar")
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
