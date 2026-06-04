package tls13gm

import (
	"fmt"

	"github.com/ycq/pollux/sm3"
)

// HKDFExpandLabel implements TLS 1.3 HKDF-Expand-Label with SM3.
func HKDFExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255 {
		return nil, fmt.Errorf("tls13gm: HKDFExpandLabel length must be 1..255, got %d", length)
	}
	hkdfLabel := buildHKDFLabel(label, context, length)
	return sm3.HKDFExpand(secret, hkdfLabel, length)
}

func buildHKDFLabel(label string, context []byte, length int) []byte {
	// RFC 8446 Section 7.1: HkdfLabel
	// length (2 bytes) + label length (1 byte) + "tls13 " + label + context length (1 byte) + context
	prefix := "tls13 "
	fullLabel := prefix + label
	result := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	result = append(result, byte(length>>8), byte(length))
	result = append(result, byte(len(fullLabel)))
	result = append(result, fullLabel...)
	result = append(result, byte(len(context)))
	result = append(result, context...)
	return result
}

// DeriveSecret implements TLS 1.3 Derive-Secret with SM3.
func DeriveSecret(secret []byte, label string, transcript []byte) ([]byte, error) {
	hash := sm3.Sum(transcript)
	return HKDFExpandLabel(secret, label, hash[:], 32)
}
