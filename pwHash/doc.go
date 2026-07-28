// Package pwHash provides PHC-format-encoded password hashing with a uniform
// [PasswordHasher] interface across the international (argon2id) and GM
// (pbkdf2-sm3) regimes.
//
// The package exists so that a consuming application (e.g. cloudfile
// cryptosuite) can switch password-hashing backends by configuration while
// keeping a single call site:
//
//	h := pwhash.NewArgon2id(pwhash.DefaultArgon2idParams())
//	encoded, _ := h.Hash("user-password")
//	if h.Verify("user-password", encoded) { ... }
//	if h.NeedsRehash(encoded) { /* lazily upgrade */ }
//
// # Encoded formats (PHC-style, self-describing)
//
// Each implementation produces a string that starts with a scheme identifier,
// so a single Verify dispatcher can be built later if a project wants to
// migrate hashes lazily.
//
//	argon2id:  $argon2id$v=19$m=<KiB>,t=<iter>,p=<par>$<b64-salt>$<b64-hash>
//	pbkdf2-sm3: $pbkdf2-sm3$i=<iter>$<b64-salt>$<b64-hash>
//
// These encodings round-trip with [PasswordHasher.Verify]: the hash itself
// embeds the algorithm and parameters, so no out-of-band state is required.
//
// # Algorithm selection rationale
//
//   - argon2id (PHC winner, RFC 9106): the international default. Memory-hard,
//     resistant to GPU/ASIC attacks. OWASP recommends it as the primary
//     password hash.
//   - pbkdf2-sm3: the GM-mandated equivalent. PBKDF2 is NIST-blessed and the
//     GM regime requires SM3 as the PRF. Iteration count compensates for the
//     lack of memory hardness.
//
// The package intentionally exposes no global default — callers must pick a
// hasher explicitly via NewArgon2id or NewPBKDF2SM3 so the choice is visible
// at the construction site.
package pwhash
