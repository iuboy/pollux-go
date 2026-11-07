package sm4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/iuboy/pollux-go/sm4"
)

// Standard SM4 test key and plaintext from GM/T 0002-2012 Section 4 Example 1.
// The single-block encryption of this plaintext under this key is the canonical
// SM4 vector 681edf34d206965e86b3e94f536e4246 (asserted in sm4_vectors_test.go).
var (
	modesKey     = func() []byte { b, _ := hex.DecodeString("0123456789abcdeffedcba9876543210"); return b }()
	modesPlain16 = func() []byte { b, _ := hex.DecodeString("0123456789abcdeffedcba9876543210"); return b }()
	modesIV      = func() []byte { b, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f"); return b }()
)

// ---------------------------------------------------------------------------
// CBC — thin wrapper over crypto/cipher.NewCBCEncrypter/Decrypter.
// ---------------------------------------------------------------------------

func TestCBCRoundTrip(t *testing.T) {
	for _, plainLen := range []int{0, 1, 15, 16, 17, 100} {
		plain := bytes.Repeat([]byte{0xCD}, plainLen)
		ct, err := sm4.Encrypt(modesKey, plain, sm4.ModeCBC, modesIV)
		if err != nil {
			t.Fatalf("CBC Encrypt len=%d: %v", plainLen, err)
		}
		pt, err := sm4.Decrypt(modesKey, ct, sm4.ModeCBC, modesIV)
		if err != nil {
			t.Fatalf("CBC Decrypt len=%d: %v", plainLen, err)
		}
		if !bytes.Equal(pt, plain) {
			t.Errorf("CBC len=%d round-trip mismatch", plainLen)
		}
	}
}

func TestCBCRejectsWrongIVLength(t *testing.T) {
	badIV := make([]byte, sm4.BlockSize-1)
	_, err := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeCBC, badIV)
	if err == nil {
		t.Error("CBC Encrypt should reject short IV")
	}
	_, err = sm4.Decrypt(modesKey, modesPlain16, sm4.ModeCBC, badIV)
	if err == nil {
		t.Error("CBC Decrypt should reject short IV")
	}
}

func TestCBCDecryptRejectsUnalignedCiphertext(t *testing.T) {
	short := make([]byte, sm4.BlockSize-1)
	_, err := sm4.Decrypt(modesKey, short, sm4.ModeCBC, modesIV)
	if err == nil {
		t.Error("CBC Decrypt should reject unaligned ciphertext")
	}
}

func TestNewCBCEncrypterConstructors(t *testing.T) {
	// Direct constructor coverage + IV-length guard.
	enc, err := sm4.NewCBCEncrypter(modesKey, modesIV)
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	if enc == nil {
		t.Fatal("NewCBCEncrypter returned nil")
	}
	if _, err := sm4.NewCBCEncrypter(modesKey, make([]byte, sm4.BlockSize-1)); err == nil {
		t.Error("NewCBCEncrypter should reject short IV")
	}
	if _, err := sm4.NewCBCEncrypter(make([]byte, 15), modesIV); err == nil {
		t.Error("NewCBCEncrypter should reject short key")
	}

	dec, err := sm4.NewCBCDecrypter(modesKey, modesIV)
	if err != nil {
		t.Fatalf("NewCBCDecrypter: %v", err)
	}
	if dec == nil {
		t.Fatal("NewCBCDecrypter returned nil")
	}
	if _, err := sm4.NewCBCDecrypter(modesKey, make([]byte, sm4.BlockSize-1)); err == nil {
		t.Error("NewCBCDecrypter should reject short IV")
	}
}

// ---------------------------------------------------------------------------
// CTR — stream cipher; encrypt and decrypt are the same operation.
// ---------------------------------------------------------------------------

func TestCTRRoundTrip(t *testing.T) {
	for _, plainLen := range []int{0, 1, 15, 16, 17, 100} {
		plain := bytes.Repeat([]byte{0xCD}, plainLen)
		ct, err := sm4.Encrypt(modesKey, plain, sm4.ModeCTR, modesIV)
		if err != nil {
			t.Fatalf("CTR Encrypt len=%d: %v", plainLen, err)
		}
		// CTR is a stream cipher: ciphertext length == plaintext length.
		if len(ct) != plainLen {
			t.Errorf("CTR len=%d: ciphertext len %d != plaintext len", plainLen, len(ct))
		}
		pt, err := sm4.Decrypt(modesKey, ct, sm4.ModeCTR, modesIV)
		if err != nil {
			t.Fatalf("CTR Decrypt len=%d: %v", plainLen, err)
		}
		if !bytes.Equal(pt, plain) {
			t.Errorf("CTR len=%d round-trip mismatch", plainLen)
		}
	}
}

func TestCTRRejectsWrongIVLength(t *testing.T) {
	badIV := make([]byte, sm4.BlockSize-1)
	_, err := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeCTR, badIV)
	if err == nil {
		t.Error("CTR Encrypt should reject short IV")
	}
}

func TestNewCTRConstructor(t *testing.T) {
	stream, err := sm4.NewCTR(modesKey, modesIV)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}
	if stream == nil {
		t.Fatal("NewCTR returned nil")
	}
	if _, err := sm4.NewCTR(modesKey, make([]byte, sm4.BlockSize-1)); err == nil {
		t.Error("NewCTR should reject short IV")
	}
}

// ---------------------------------------------------------------------------
// GCM via the Encrypt/Decrypt dispatcher — covers the auto-nonce and
// explicit-nonce paths.
// ---------------------------------------------------------------------------

func TestGCMViaDispatcherAutoNonce(t *testing.T) {
	// nil IV → auto-generated nonce prepended to ciphertext.
	ct, err := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeGCM, nil)
	if err != nil {
		t.Fatalf("GCM Encrypt auto-nonce: %v", err)
	}
	// SM4-GCM: 12B nonce + 16B plaintext + 16B tag = 44B.
	if len(ct) != 12+len(modesPlain16)+16 {
		t.Errorf("GCM auto-nonce ciphertext len = %d, want %d", len(ct), 12+len(modesPlain16)+16)
	}
	// nil IV on decrypt → expects nonce prepended.
	pt, err := sm4.Decrypt(modesKey, ct, sm4.ModeGCM, nil)
	if err != nil {
		t.Fatalf("GCM Decrypt auto-nonce: %v", err)
	}
	if !bytes.Equal(pt, modesPlain16) {
		t.Errorf("GCM auto-nonce round-trip mismatch")
	}
}

func TestGCMViaDispatcherExplicitNonce(t *testing.T) {
	nonce := make([]byte, 12) // all-zero nonce, test only
	ct, err := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeGCM, nonce)
	if err != nil {
		t.Fatalf("GCM Encrypt explicit nonce: %v", err)
	}
	// Explicit nonce: ciphertext = 16B plaintext + 16B tag = 32B (nonce NOT prepended).
	if len(ct) != len(modesPlain16)+16 {
		t.Errorf("GCM explicit-nonce ciphertext len = %d, want %d", len(ct), len(modesPlain16)+16)
	}
	pt, err := sm4.Decrypt(modesKey, ct, sm4.ModeGCM, nonce)
	if err != nil {
		t.Fatalf("GCM Decrypt explicit nonce: %v", err)
	}
	if !bytes.Equal(pt, modesPlain16) {
		t.Errorf("GCM explicit-nonce round-trip mismatch")
	}
}

func TestGCMRejectsWrongNonceLength(t *testing.T) {
	badNonce := make([]byte, 8) // GCM nonce must be 12
	if _, err := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeGCM, badNonce); err == nil {
		t.Error("GCM Encrypt should reject non-12-byte nonce")
	}
	if _, err := sm4.Decrypt(modesKey, modesPlain16, sm4.ModeGCM, badNonce); err == nil {
		t.Error("GCM Decrypt should reject non-12-byte nonce")
	}
}

func TestGCMDecryptRejectsTruncatedCiphertext(t *testing.T) {
	// Auto-nonce path: ciphertext too short to contain a nonce → errNonceMissing.
	short := make([]byte, 10) // < 12 (nonce) + 16 (tag)
	_, err := sm4.Decrypt(modesKey, short, sm4.ModeGCM, nil)
	if err == nil {
		t.Error("GCM Decrypt should reject truncated ciphertext")
	}
}

func TestGCMDecryptDetectsTamper(t *testing.T) {
	// Flip a bit in the ciphertext → authentication must fail.
	ct, _ := sm4.Encrypt(modesKey, modesPlain16, sm4.ModeGCM, nil)
	ct[len(ct)-1] ^= 0x01
	_, err := sm4.Decrypt(modesKey, ct, sm4.ModeGCM, nil)
	if err == nil {
		t.Error("GCM Decrypt should detect tampered ciphertext")
	}
}

// ---------------------------------------------------------------------------
// Encrypt/Decrypt dispatcher — default branch (unknown mode) errors.
// ---------------------------------------------------------------------------

func TestEncryptDecryptUnknownMode(t *testing.T) {
	_, err := sm4.Encrypt(modesKey, modesPlain16, sm4.Mode("NOPE"), nil)
	if err == nil {
		t.Error("Encrypt should reject unknown mode")
	}
	_, err = sm4.Decrypt(modesKey, modesPlain16, sm4.Mode("NOPE"), nil)
	if err == nil {
		t.Error("Decrypt should reject unknown mode")
	}
}

// ---------------------------------------------------------------------------
// GenerateIV
// ---------------------------------------------------------------------------

func TestGenerateIV(t *testing.T) {
	iv, err := sm4.GenerateIV()
	if err != nil {
		t.Fatalf("GenerateIV: %v", err)
	}
	if len(iv) != sm4.BlockSize {
		t.Errorf("GenerateIV len = %d, want %d", len(iv), sm4.BlockSize)
	}
	// Two IVs must differ (random).
	iv2, _ := sm4.GenerateIV()
	if bytes.Equal(iv, iv2) {
		t.Error("GenerateIV produced identical IVs — randomness failure")
	}
}

// ---------------------------------------------------------------------------
// PKCS7Pad / PKCS7Unpad — boundary and adversarial cases.
// ---------------------------------------------------------------------------

func TestPKCS7PadUnpadRoundTrip(t *testing.T) {
	for _, dataLen := range []int{0, 1, 7, 15, 16, 17, 32} {
		data := bytes.Repeat([]byte{0x42}, dataLen)
		padded, err := sm4.PKCS7Pad(data, sm4.BlockSize)
		if err != nil {
			t.Fatalf("PKCS7Pad len=%d: %v", dataLen, err)
		}
		if len(padded)%sm4.BlockSize != 0 {
			t.Errorf("PKCS7Pad len=%d: result not block-aligned", dataLen)
		}
		unpadded, err := sm4.PKCS7Unpad(padded, sm4.BlockSize)
		if err != nil {
			t.Fatalf("PKCS7Unpad len=%d: %v", dataLen, err)
		}
		if !bytes.Equal(unpadded, data) {
			t.Errorf("PKCS7 len=%d round-trip mismatch", dataLen)
		}
	}
}

func TestPKCS7PadAddsFullBlockOnBoundary(t *testing.T) {
	// Exactly one block of data → PKCS7 adds a full second block of 0x10.
	data := make([]byte, sm4.BlockSize)
	padded, _ := sm4.PKCS7Pad(data, sm4.BlockSize)
	if len(padded) != 2*sm4.BlockSize {
		t.Errorf("PKCS7Pad on boundary: len %d, want %d", len(padded), 2*sm4.BlockSize)
	}
	// The padding block must be all 0x10.
	for _, b := range padded[sm4.BlockSize:] {
		if b != 0x10 {
			t.Errorf("PKCS7Pad padding byte = 0x%02x, want 0x10", b)
		}
	}
}

func TestPKCS7RejectsInvalidBlockSize(t *testing.T) {
	if _, err := sm4.PKCS7Pad([]byte{1}, 0); err == nil {
		t.Error("PKCS7Pad should reject blockSize 0")
	}
	if _, err := sm4.PKCS7Pad([]byte{1}, -1); err == nil {
		t.Error("PKCS7Pad should reject negative blockSize")
	}
	if _, err := sm4.PKCS7Unpad([]byte{1}, 0); err == nil {
		t.Error("PKCS7Unpad should reject blockSize 0")
	}
}

func TestPKCS7UnpadRejectsMalformed(t *testing.T) {
	// Empty input.
	if _, err := sm4.PKCS7Unpad(nil, sm4.BlockSize); err == nil {
		t.Error("PKCS7Unpad should reject empty input")
	}
	// Non-block-aligned input.
	if _, err := sm4.PKCS7Unpad(make([]byte, sm4.BlockSize-1), sm4.BlockSize); err == nil {
		t.Error("PKCS7Unpad should reject unaligned input")
	}
	// Padding byte 0x00 (invalid — PKCS7 padding is 1..blockSize).
	zeroPad := make([]byte, sm4.BlockSize)
	zeroPad[sm4.BlockSize-1] = 0x00
	if _, err := sm4.PKCS7Unpad(zeroPad, sm4.BlockSize); err == nil {
		t.Error("PKCS7Unpad should reject 0x00 padding byte")
	}
	// Padding byte > blockSize.
	bigPad := make([]byte, sm4.BlockSize)
	bigPad[sm4.BlockSize-1] = byte(sm4.BlockSize + 1)
	if _, err := sm4.PKCS7Unpad(bigPad, sm4.BlockSize); err == nil {
		t.Error("PKCS7Unpad should reject padding byte > blockSize")
	}
	// Inconsistent padding: claims 3 bytes of 0x03 but only last is correct.
	badPad := make([]byte, sm4.BlockSize)
	badPad[sm4.BlockSize-1] = 0x03
	badPad[sm4.BlockSize-2] = 0x02 // should be 0x03
	badPad[sm4.BlockSize-3] = 0x03
	if _, err := sm4.PKCS7Unpad(badPad, sm4.BlockSize); err == nil {
		t.Error("PKCS7Unpad should reject inconsistent padding")
	}
}

// TestPKCS7Unpad_ConstantTimeBehaviorEquivalent 是第四轮审计 P3 的回归守卫:
// PKCS7Unpad 常数时间化(恒定扫描末块、范围检查并入掩码、统一返回)后,
// 正确/错误 padding 的判定行为必须与旧实现完全一致——所有合法 padding 值
// (1..blockSize)都正确去填充,所有非法家族(pad=0、pad>blockSize、声明值与
// 实际字节不一致)都仍被拒绝。审计关注点是把实现从"数据相关早退/数据相关
// 循环"改为常数时间,而不是改变语义。
func TestPKCS7Unpad_ConstantTimeBehaviorEquivalent(t *testing.T) {
	// 每个 padding 值(含边界:pad=1、pad=blockSize 整块填充)round-trip 不变。
	for pad := 1; pad <= sm4.BlockSize; pad++ {
		block := make([]byte, sm4.BlockSize)
		for i := sm4.BlockSize - pad; i < sm4.BlockSize; i++ {
			block[i] = byte(pad)
		}
		if pad < sm4.BlockSize {
			// padding 区之外的字节取任意值不参与校验;pad=blockSize 时整块皆
			// 为 padding,索引 0 必须保持 pad 值。
			block[0] = 0xA5
		}
		got, err := sm4.PKCS7Unpad(block, sm4.BlockSize)
		if err != nil {
			t.Fatalf("pad=%d: valid padding rejected: %v", pad, err)
		}
		if len(got) != sm4.BlockSize-pad {
			t.Fatalf("pad=%d: unpadded length = %d, want %d", pad, len(got), sm4.BlockSize-pad)
		}
	}
	// 多块输入:只有末块参与 padding 判定,前块内容不受影响。
	tail := make([]byte, sm4.BlockSize)
	for i := sm4.BlockSize - 5; i < sm4.BlockSize; i++ {
		tail[i] = 5
	}
	two := append(bytes.Repeat([]byte{0x5A}, sm4.BlockSize), tail...)
	got, err := sm4.PKCS7Unpad(two, sm4.BlockSize)
	if err != nil || len(got) != 2*sm4.BlockSize-5 {
		t.Fatalf("two-block unpad: len=%d err=%v", len(got), err)
	}
	// 非法家族逐一仍被拒(常数时间扫描不改变判定结果)。
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{"pad 0", make([]byte, sm4.BlockSize)},
		{"pad > blockSize", func() []byte {
			b := make([]byte, sm4.BlockSize)
			b[sm4.BlockSize-1] = byte(sm4.BlockSize + 1)
			return b
		}()},
		{"claim 2 but tail garbage", func() []byte {
			b := make([]byte, sm4.BlockSize)
			b[sm4.BlockSize-1] = 2
			b[sm4.BlockSize-2] = 0xFF // padding 声明 2 字节,倒数第二字节必须为 2
			return b
		}()},
		{"claim 16 not all 16", func() []byte {
			b := bytes.Repeat([]byte{0x10}, sm4.BlockSize)
			b[0] = 0x0F
			return b
		}()},
	} {
		if _, err := sm4.PKCS7Unpad(tc.block, sm4.BlockSize); err == nil {
			t.Errorf("%s: invalid padding accepted", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// NewGCM direct constructor (modes.go line 19, distinct from gcm.go helpers).
// ---------------------------------------------------------------------------

func TestNewGCMModesConstructor(t *testing.T) {
	aead, err := sm4.NewGCM(modesKey)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	if aead == nil {
		t.Fatal("NewGCM returned nil")
	}
	if aead.NonceSize() != 12 {
		t.Errorf("GCM NonceSize = %d, want 12", aead.NonceSize())
	}
	if _, err := sm4.NewGCM(make([]byte, 15)); err == nil {
		t.Error("NewGCM should reject short key")
	}
}
