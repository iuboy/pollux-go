// Package sha provides convenience wrappers around the standard library
// crypto/sha256 and crypto/sha512, symmetric in API surface to
// [github.com/iuboy/pollux-go/sm3].
//
// pollux-go positions itself as an integration toolkit that exposes GM
// (Chinese national cryptography) primitives alongside their international
// counterparts under a uniform, Go-idiomatic API. This package mirrors the
// sm3 package (New / Sum / NewHMAC / HKDF) so that callers can treat SHA-256
// and SM3 as interchangeable hash backends.
//
// # Scope: SHA-256 only
//
// SHA-224, SHA-384, and SHA-512 are intentionally omitted. SHA-256 is the
// hash backend that matches SM3 in both output size (32 bytes) and security
// level, which is what every cross-algorithm use case in pollux-go consumers
// (content addressing, JWT, PBKDF2, audit chains) requires. Exposing only
// SHA-256 keeps the surface symmetric with sm3 and avoids the "which SHA-2
// variant?" decision. Callers needing SHA-512 should use crypto/sha512
// directly.
//
// # HMAC and HKDF
//
// HMAC-SHA-256 and HKDF-SHA-256 (RFC 5869) are provided as convenience
// wrappers, mirroring sm3.NewHMAC and sm3.HKDF.
package sha
