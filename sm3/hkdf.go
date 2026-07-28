package sm3

import (
	"errors"
)

// HKDF-Extract and HKDF-Expand per RFC 5869, using SM3 as the underlying hash.

// hkdfExtract implements HKDF-Extract (RFC 5869 Section 2.2) using SM3.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, Size)
	}
	h := NewHMAC(salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand implements HKDF-Expand (RFC 5869 Section 2.3) using SM3.
// T(i) = HMAC(PRK, T(i-1) || info || i), where T(0) = empty string.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*Size {
		return nil, errors.New("sm3/hkdf: length too large")
	}

	n := (length + Size - 1) / Size

	result := make([]byte, 0, length)
	var prev []byte

	for i := 1; i <= n; i++ {
		h := NewHMAC(prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		result = append(result, prev...)
	}

	return result[:length], nil
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
