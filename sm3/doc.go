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
// This package delegates to github.com/emmansun/gmsm/sm3 for the core
// implementation. The wrapper provides a Go-idiomatic API (New, Sum, KDF,
// HKDF, HMAC) symmetric with the sha package for SHA-256.
package sm3
