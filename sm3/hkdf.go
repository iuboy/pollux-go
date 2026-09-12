package sm3

import (
	"crypto/hkdf"
	"errors"
)

// HKDF-Extract and HKDF-Expand per RFC 5869, using SM3 as the underlying hash.
//
// Since Go 1.25 the standard library ships crypto/hkdf; the construction is
// delegated to it (golang.org/x/crypto/hkdf is its frozen ancestor) so the KDF
// sits on the stdlib-vetted, FIPS-aware implementation. These wrappers
// preserve the package's historical (salt, ikm) / (prk, info, length)
// signatures so callers — notably the tls13gm key schedule — keep their
// argument order.
//
// Parameter-order note: crypto/hkdf.Extract is Extract(h, secret, salt), i.e.
// secret and salt are in the OPPOSITE order from this package's historical
// (salt, ikm) signature. The swap happens here at the boundary so callers are
// unaffected by the underlying switch.
//
// FIPS note: under GODEBUG=fips140=only the stdlib rejects non-approved
// hashes, so these wrappers fail closed rather than silently deriving SM3
// keys inside a process that explicitly opted into FIPS-only crypto. That is
// the honest behavior for a GM (国密) library in such a process.

// hkdfExtract implements HKDF-Extract (RFC 5869 Section 2.2) using SM3.
// A nil/empty salt is replaced with HashLen zero bytes by the underlying
// implementation (RFC 5869 §2.2), matching the previous hand-rolled behavior.
func hkdfExtract(salt, ikm []byte) ([]byte, error) {
	return hkdf.Extract(New, ikm, salt)
}

// hkdfExpand implements HKDF-Expand (RFC 5869 Section 2.3) using SM3.
// T(i) = HMAC(PRK, T(i-1) || info || i), where T(0) = empty string.
//
// Requests exceeding 255*HashLen are rejected by the underlying
// implementation with "hkdf: requested key length too large".
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	// stdlib Expand takes info as string to discourage retaining attacker
	// data; the conversion here never outlives the call.
	return hkdf.Expand(New, prk, string(info), length)
}

// HKDF implements the full HKDF (Extract+Expand) per RFC 5869 using SM3.
func HKDF(salt, ikm, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("sm3/hkdf: length must be positive")
	}
	prk, err := hkdfExtract(salt, ikm)
	if err != nil {
		return nil, err
	}
	return hkdfExpand(prk, info, length)
}

// HKDFExtract returns the PRK from HKDF-Extract.
func HKDFExtract(salt, ikm []byte) ([]byte, error) {
	return hkdfExtract(salt, ikm)
}

// HKDFExpand derives output keying material from a PRK.
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("sm3/hkdf: length must be positive")
	}
	return hkdfExpand(prk, info, length)
}
