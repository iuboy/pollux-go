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
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(New, key)
}
