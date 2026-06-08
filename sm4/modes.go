package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
)

var errInvalidIVLen = errors.New("sm4: invalid IV length")

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

// NewCFBEncrypter creates an SM4-CFB encryptor.
//
// Deprecated: CFB mode does not provide authentication; use NewGCM instead.
func NewCFBEncrypter(key, iv []byte) (cipher.Stream, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil //nolint:staticcheck
}

// NewCFBDecrypter creates an SM4-CFB decryptor.
//
// Deprecated: CFB mode does not provide authentication; use NewGCM instead.
func NewCFBDecrypter(key, iv []byte) (cipher.Stream, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil //nolint:staticcheck
}

// GenerateIV generates a random IV of the same size as the block.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("sm4: failed to generate IV")
	}
	return iv, nil
}

// Mode represents an SM4 encryption mode.
type Mode string

const (
	ModeECB Mode = "ECB" // Deprecated: ECB does not provide semantic security; use GCM for new protocols
	ModeCBC Mode = "CBC"
	ModeCTR Mode = "CTR"
	ModeGCM Mode = "GCM"
	ModeCFB Mode = "CFB"
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

// PKCS7Unpad removes PKCS#7 padding using constant-time comparison.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("sm4: invalid block size")
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("sm4: invalid padded data length")
	}
	pad := data[len(data)-1]
	padding := int(pad)
	if padding == 0 || padding > blockSize {
		return nil, errors.New("sm4: invalid PKCS7 padding")
	}
	// Constant-time validation of all padding bytes.
	var valid int = 1
	for i := len(data) - padding; i < len(data); i++ {
		valid &= subtle.ConstantTimeByteEq(data[i], pad)
	}
	if valid == 0 {
		return nil, errors.New("sm4: invalid PKCS7 padding")
	}
	return data[:len(data)-padding], nil
}

// Encrypt encrypts plaintext using the specified SM4 mode.
// Supported modes: ModeGCM (recommended), ModeCBC, ModeCTR, ModeCFB, ModeECB (deprecated).
//
//   - If iv is nil or empty, a random 12-byte nonce is generated and prepended to the ciphertext.
//   - If iv is provided, it is used directly and NOT prepended to the ciphertext.
//
// For CBC/CTR/CFB, iv is the IV. ECB ignores iv. GCM includes authentication.
// WARNING: for GCM mode, never reuse a nonce with the same key.
func Encrypt(key, plaintext []byte, mode Mode, iv []byte) ([]byte, error) {
	switch mode {
	case ModeECB:
		return encryptECB(key, plaintext)
	case ModeCBC:
		return encryptCBC(key, plaintext, iv)
	case ModeCTR:
		return encryptCTR(key, plaintext, iv)
	case ModeGCM:
		return encryptGCM(key, plaintext, iv)
	case ModeCFB:
		return encryptCFB(key, plaintext, iv)
	default:
		return nil, errors.New("sm4: unsupported mode")
	}
}

// Decrypt decrypts ciphertext using the specified SM4 mode.
func Decrypt(key, ciphertext []byte, mode Mode, iv []byte) ([]byte, error) {
	switch mode {
	case ModeECB:
		return decryptECB(key, ciphertext)
	case ModeCBC:
		return decryptCBC(key, ciphertext, iv)
	case ModeCTR:
		return decryptCTR(key, ciphertext, iv)
	case ModeGCM:
		return decryptGCM(key, ciphertext, iv)
	case ModeCFB:
		return decryptCFB(key, ciphertext, iv)
	default:
		return nil, errors.New("sm4: unsupported mode")
	}
}

func encryptECB(key, plaintext []byte) ([]byte, error) {
	padded, err := PKCS7Pad(plaintext, BlockSize)
	if err != nil {
		return nil, err
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += BlockSize {
		block.Encrypt(ciphertext[i:i+BlockSize], padded[i:i+BlockSize])
	}
	return ciphertext, nil
}

func decryptECB(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("sm4: ciphertext not aligned to block size")
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += BlockSize {
		block.Decrypt(plaintext[i:i+BlockSize], ciphertext[i:i+BlockSize])
	}
	return PKCS7Unpad(plaintext, BlockSize)
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
	if len(nonce) == 0 && len(ciphertext) >= aead.NonceSize()+aead.Overhead() {
		nonce = ciphertext[:aead.NonceSize()]
		ciphertext = ciphertext[aead.NonceSize():]
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func encryptCFB(key, plaintext, iv []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	stream, err := NewCFBEncrypter(key, iv)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func decryptCFB(key, ciphertext, iv []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, errInvalidIVLen
	}
	stream, err := NewCFBDecrypter(key, iv)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
