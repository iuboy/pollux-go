package sm3

import (
	"errors"
	"io"

	xhkdf "golang.org/x/crypto/hkdf"
)

// HKDF-Extract and HKDF-Expand per RFC 5869, using SM3 as the underlying hash.
//
// The HKDF construction itself is delegated to golang.org/x/crypto/hkdf (a
// vetted implementation) to avoid maintaining a hand-rolled KDF on the
// cryptographic critical path. These wrappers preserve the package's existing
// (salt, ikm) / (prk, info, length) signatures so callers — notably the
// tls13gm key schedule — are unaffected by the underlying switch.
//
// Parameter-order note: golang.org/x/crypto/hkdf.Extract is
// Extract(hash, secret, salt), i.e. secret and salt are in the OPPOSITE order
// from this package's historical (salt, ikm) signature. The swap happens here
// at the boundary so callers keep their existing argument order.

// hkdfExtract implements HKDF-Extract (RFC 5869 Section 2.2) using SM3.
// A nil/empty salt is replaced with HashLen zero bytes by the underlying
// implementation (RFC 5869 §2.2), matching the previous hand-rolled behavior.
func hkdfExtract(salt, ikm []byte) []byte {
	return xhkdf.Extract(New, ikm, salt)
}

// hkdfExpand implements HKDF-Expand (RFC 5869 Section 2.3) using SM3.
// T(i) = HMAC(PRK, T(i-1) || info || i), where T(0) = empty string.
//
// golang.org/x/crypto/hkdf.Expand returns an io.Reader; we drain it with
// io.ReadFull. Requests exceeding 255*HashLen surface as the underlying
// "hkdf: entropy limit reached" error from Read.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*Size {
		return nil, errors.New("sm3/hkdf: length too large")
	}

	out := make([]byte, length)
	r := xhkdf.Expand(New, prk, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// HKDF implements the full HKDF (Extract+Expand) per RFC 5869 using SM3.
func HKDF(salt, ikm, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("sm3/hkdf: length must be positive")
	}
	prk := hkdfExtract(salt, ikm)
	return hkdfExpand(prk, info, length)
}

// HKDFExtract returns the PRK from HKDF-Extract.
func HKDFExtract(salt, ikm []byte) []byte {
	return hkdfExtract(salt, ikm)
}

// HKDFExpand derives output keying material from a PRK.
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("sm3/hkdf: length must be positive")
	}
	return hkdfExpand(prk, info, length)
}
