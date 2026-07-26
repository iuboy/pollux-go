// Package gmstd provides helper functions per GM/T national cryptography standards.
//
// This package implements auxiliary functions from:
//   - GM/T 0009-2012: SM2 cryptographic algorithm usage specification
//     (DefaultSM2UserID, ComputeSM2UserID)
//   - GM/T 0003-2012: SM3 cryptographic hash algorithm
//     (SM3Hash, SM3HashHex, SM2KDF, SM3HashForPublicKey)
//   - GB/T 32907 / GM/T 0002: SM4 block cipher
//     (GenerateSM4Key)
//
// It also exposes a generic GenerateNonce helper for cryptographically random
// bytes of a caller-chosen length (used by AES-GCM/SM4-GCM nonce generation).
package gmstd
