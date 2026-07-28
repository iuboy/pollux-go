// Package sm4 implements the SM4 block cipher (GM/T 0002-2012).
//
// SM4 is a block cipher with a fixed block size of 128 bits and a key size
// of 128 bits, standardized by the Chinese National Cryptography Administration.
//
// The API follows crypto/aes conventions:
//
//	block, err := sm4.NewCipher(key)
//
//	// Use with standard library modes:
//	aead, err := cipher.NewGCM(block)
//	cbc := cipher.NewCBCEncrypter(block, iv)
//	ctr := cipher.NewCTR(block, iv)
//
// # Security: nonce and IV reuse
//
// Reusing a nonce (GCM) or IV (CBC, CTR, CFB) with the same key is catastrophic:
//
//   - GCM: nonce reuse allows key recovery and message forgery.
//   - CTR: reuse produces a two-time pad, leaking plaintext via XOR.
//   - CBC: reuse enables block-wise correlation attacks.
//
// For GCM encryption, generate a cryptographically random 12-byte nonce for
// each encryption. The package provides SealRandomNonce (which binds nonce
// generation to the encrypt call) and GenerateNonce for callers that reuse a
// cipher.AEAD across many messages. See gcm.go.
//
// ECB mode (NewECBEncrypter/NewECBDecrypter) is provided for compatibility only
// and should not be used in new protocols — it does not provide semantic security.
//
// Status: wrapper around gmsm/sm4
package sm4
