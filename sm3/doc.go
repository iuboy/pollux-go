// Package sm3 implements the SM3 cryptographic hash function (GM/T 0004-2012).
//
// SM3 is a cryptographic hash algorithm published by the Chinese National
// Cryptography Administration. It produces a 256-bit (32-byte) digest.
//
// The API follows crypto/sha256 conventions:
//
//	h := sm3.New()
//	h.Write(data)
//	digest := h.Sum(nil)
//
//	// Or use the one-shot function:
//	digest := sm3.Sum(data)
//
// Status: wrapper around gmsm/sm3
package sm3
