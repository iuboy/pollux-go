// Package kdf provides hash-agnostic key- and password-derivation functions.
//
// Unlike the algorithm-specific packages (sm3, sha), which only expose
// HKDF/HMAC for a fixed hash, this package hosts the cross-algorithm
// primitives that take a hash.Hash factory as input so the same code path
// can serve both the GM (SM3) and international (SHA-256) modes.
//
// Currently the package implements PBKDF2 (RFC 2898 / PKCS#5 v2.0). The
// password-hashing package [github.com/iuboy/pollux-go/pwHash] builds the
// PHC-encoded pbkdf2-sm3 variant on top of [PBKDF2].
//
// # Why hash-agnostic?
//
// GM compliance regimes require PBKDF2-HMAC-SM3, while the OWASP baseline
// uses PBKDF2-HMAC-SHA-256. Both are the same algorithm with different PRFs;
// a single PBKDF2( password, salt, iter, keyLen, h func() hash.Hash )
// implementation serves both. The caller supplies h:
//
//	// GM
//	dk, err := kdf.PBKDF2(pwd, salt, 200_000, 32, sm3.New)
//	if err != nil { /* handle invalid params: iter<=0, keyLen<=0, iter>10M, ... */ }
//	// international
//	dk, err = kdf.PBKDF2(pwd, salt, 600_000, 32, sha256.New)
//	if err != nil { /* ... */ }
//
// Always check the returned error: PBKDF2 rejects invalid parameters
// (iter<=0, keyLen<=0, iter>10M, keyLen>1MiB, nil hash) with a descriptive
// error rather than silently producing a degenerate key.
package kdf
