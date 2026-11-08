package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

var (
	errInvalidIVLen = errors.New("sm4: invalid IV length")
	errNonceMissing = errors.New("sm4: nonce required (none provided and ciphertext too short to contain a prepended one)")
)

// NewGCM creates an SM4-GCM authenticated encryptor.
// The returned cipher.AEAD can be used directly for Seal/Open.
func NewGCM(key []byte) (cipher.AEAD, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewCBCEncrypter creates an SM4-CBC encryptor.
func NewCBCEncrypter(key, iv []byte) (cipher.BlockMode, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCEncrypter(block, iv), nil
}

// NewCBCDecrypter creates an SM4-CBC decryptor.
func NewCBCDecrypter(key, iv []byte) (cipher.BlockMode, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCDecrypter(block, iv), nil
}

// NewCTR creates an SM4-CTR stream cipher.
func NewCTR(key, iv []byte) (cipher.Stream, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// GenerateIV generates a random IV of the same size as the block.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("sm4: failed to generate IV: %w", err)
	}
	return iv, nil
}

// Mode represents an SM4 encryption mode.
type Mode string

const (
	// ModeCBC is Cipher Block Chaining mode. The caller must supply a unique IV.
	ModeCBC Mode = "CBC"
	// ModeCTR is Counter mode. The caller must supply a unique nonce/counter.
	ModeCTR Mode = "CTR"
	// ModeGCM is Galois/Counter Mode (recommended): authenticated encryption.
	ModeGCM Mode = "GCM"
)

// PKCS7Pad pads data to a multiple of blockSize using PKCS#7.
func PKCS7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("sm4: invalid block size")
	}
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded, nil
}

// PKCS7Unpad removes PKCS#7 padding in constant time.
//
// 第四轮审计 P3:旧实现先按末字节做范围早退、再按 padding 值决定循环次数,
// 执行时间与明文末块的数据取值相关——在 CBC 等无认证模式下构成经典
// padding oracle 的时序半边。现改为:恒定扫描末块全部 blockSize 字节,
// 范围检查(1 ≤ pad ≤ blockSize)与逐字节等值检查统一累积进 valid 掩码,
// 循环次数与分支走向均与 pad 的实际取值无关,末尾一次性判定、统一返回。
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("sm4: invalid block size")
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("sm4: invalid padded data length")
	}
	pad := data[len(data)-1]
	p := int(pad)
	// 范围检查并入掩码:lowerOK = 1 ⇔ pad ≥ 1;upperOK = 1 ⇔ pad ≤ blockSize。
	// 两者都以无符号移位提取符号位,不引入数据相关分支。
	lowerOK := 1 - int(uint64(int64(p)-1)>>63)
	upperOK := 1 - int(uint64(int64(blockSize)-int64(p))>>63)
	valid := lowerOK & upperOK
	// 恒定扫描末块全部字节:last[i] 落在 padding 区(i ≥ blockSize-pad)时,
	// 其值必须等于 pad;padding 区之外的字节恒视为通过。
	last := data[len(data)-blockSize:]
	for i := range blockSize {
		// inPad = 1 ⇔ i ≥ blockSize-pad ⇔ blockSize-pad-i-1 < 0(符号位)。
		inPad := int(uint64(int64(blockSize)-int64(p)-int64(i)-1) >> 63)
		eq := subtle.ConstantTimeByteEq(last[i], pad)
		valid &= 1 - inPad&(eq^1)
	}
	if valid == 0 {
		return nil, errors.New("sm4: invalid PKCS7 padding")
	}
	return data[:len(data)-p], nil
}

// Encrypt encrypts plaintext using the specified SM4 mode.
// Supported modes: ModeGCM (recommended), ModeCBC, ModeCTR.
//
//   - GCM: if iv is nil or empty, a random 12-byte nonce is generated and
//     prepended to the ciphertext; if iv is provided it is used directly and
//     NOT prepended (and must be exactly GCMNonceSize bytes).
//   - CBC/CTR: iv is the IV and MUST be BlockSize (16) bytes; an empty or
//     wrong-length iv returns errInvalidIVLen (no auto-generation).
//
// GCM includes authentication; the others do not.
// WARNING: for GCM mode, never reuse a nonce with the same key.
func Encrypt(key, plaintext []byte, mode Mode, iv []byte) ([]byte, error) {
	switch mode {
	case ModeCBC:
		return encryptCBC(key, plaintext, iv)
	case ModeCTR:
		return encryptCTR(key, plaintext, iv)
	case ModeGCM:
		return encryptGCM(key, plaintext, iv)
	default:
		return nil, errors.New("sm4: unsupported mode")
	}
}

// Decrypt decrypts ciphertext using the specified SM4 mode.
func Decrypt(key, ciphertext []byte, mode Mode, iv []byte) ([]byte, error) {
	switch mode {
	case ModeCBC:
		return decryptCBC(key, ciphertext, iv)
	case ModeCTR:
		return decryptCTR(key, ciphertext, iv)
	case ModeGCM:
		return decryptGCM(key, ciphertext, iv)
	default:
		return nil, errors.New("sm4: unsupported mode")
	}
}

func encryptCBC(key, plaintext, iv []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	padded, err := PKCS7Pad(plaintext, BlockSize)
	if err != nil {
		return nil, err
	}
	mode, err := NewCBCEncrypter(key, iv)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func decryptCBC(key, ciphertext, iv []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("sm4: ciphertext not aligned to block size")
	}
	mode, err := NewCBCDecrypter(key, iv)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return PKCS7Unpad(plaintext, BlockSize)
}

func encryptCTR(key, plaintext, iv []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	stream, err := NewCTR(key, iv)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func decryptCTR(key, ciphertext, iv []byte) ([]byte, error) {
	return encryptCTR(key, ciphertext, iv)
}

func encryptGCM(key, plaintext, nonce []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	noncePrepended := false
	if len(nonce) == 0 {
		nonce = make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		noncePrepended = true
	} else if len(nonce) != aead.NonceSize() {
		// cipher.NewGCM's Seal/Open panic (not return error) on a wrong-length
		// nonce; guard explicitly so a malformed caller nonce becomes a
		// returned error instead of a process-wide panic.
		return nil, errInvalidIVLen
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	if noncePrepended {
		result := make([]byte, len(nonce)+len(sealed))
		copy(result, nonce)
		copy(result[len(nonce):], sealed)
		return result, nil
	}
	return sealed, nil
}

func decryptGCM(key, ciphertext, nonce []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) == 0 {
		// No explicit nonce: it must be prepended to the ciphertext. Reject
		// short inputs explicitly instead of silently degrading to an
		// all-zero nonce, which would mask caller misuse (e.g. a truncated
		// ciphertext or a forgotten nonce) as a generic decryption failure.
		if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
			return nil, errNonceMissing
		}
		nonce = ciphertext[:aead.NonceSize()]
		ciphertext = ciphertext[aead.NonceSize():]
	} else if len(nonce) != aead.NonceSize() {
		// See encryptGCM: guard against cipher.AEAD.Open panicking on a
		// wrong-length nonce.
		return nil, errInvalidIVLen
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
