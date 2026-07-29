package sha

import (
	"crypto/hmac"
	"hash"
)

// NewHMAC returns an HMAC instance using SHA-256.
// HMAC-SHA-256 satisfies FIPS 198-1 / RFC 2104.
//
// NIST SP 800-107 recommends HMAC key length ≥ HashLen (32 bytes for
// SHA-256) to reach the full security strength. Shorter keys are accepted
// (HMAC does not reject them) but reduce the effective security level.
// For security-sensitive use, prefer ≥32-byte keys via sha.NewHMAC.
//
// WARNING: a nil key is silently treated as an empty key ([]byte{}) by
// crypto/hmac, producing an HMAC under a zero-length key — i.e. NO real
// authentication. This is a foot-gun: callers that pass nil (e.g. by reading a
// missing config field) get a valid-looking hash.Hash with zero security. Always
// supply a non-empty, high-entropy key.
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(New, key)
}
