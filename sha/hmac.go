package sha

import (
	"crypto/hmac"
	"hash"
)

// NewHMAC returns an HMAC instance using SHA-256.
// HMAC-SHA-256 satisfies FIPS 198-1 / RFC 2104.
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(New, key)
}
