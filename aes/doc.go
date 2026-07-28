// Package aes provides convenience wrappers around the standard library
// crypto/aes, symmetric in API surface to [github.com/iuboy/pollux-go/sm4].
//
// pollux-go positions itself as an integration toolkit that exposes GM
// (Chinese national cryptography) primitives alongside their international
// counterparts under a uniform, Go-idiomatic API. This package exists so that
// callers can treat AES-256-GCM and SM4-GCM as interchangeable: both packages
// expose NewCipher / GenerateKey / NewGCM / SealRandomNonce / Sealed / Encrypt
// / Decrypt with matching signatures, differing only in key size (AES-256 =
// 32 bytes, SM4 = 16 bytes).
//
// # Why AES-256 only
//
// AES-128 and AES-192 are intentionally omitted. The package targets
// at-rest encryption of object content and field-level secrets, where the
// 256-bit key strength matches the security posture of SM4 (which has a fixed
// 128-bit key but is the GM-mandated equivalent). Exposing only AES-256 keeps
// the surface minimal and avoids the "which AES variant?" decision.
//
// # Security: nonce reuse
//
// Reusing a nonce (GCM) or IV (CBC, CTR, CFB) with the same key is
// catastrophic:
//   - GCM: nonce reuse allows key recovery and message forgery.
//   - CTR: reuse produces a two-time pad, leaking plaintext via XOR.
//   - CBC/CFB: reuse reveals whether two plaintexts share a prefix.
//
// Prefer [SealRandomNonce], which binds nonce generation to the encrypt path
// and eliminates the reuse risk for one-shot callers.
package aes
