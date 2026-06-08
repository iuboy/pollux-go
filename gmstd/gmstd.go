// Package gmstd provides helper functions per GM/T national cryptography standards.
//
// This package implements auxiliary functions from:
//   - GM/T 0009-2012: SM2 cryptographic algorithm usage specification
//   - GM/T 0003-2012: SM3 cryptographic hash algorithm
package gmstd

import (
	"crypto"
	"encoding/hex"

	"github.com/emmansun/gmsm/sm3"
	smx509 "github.com/emmansun/gmsm/smx509"
)

// DefaultSM2UserID is the default user identifier per GM/T 0009-2012.
const DefaultSM2UserID = "1234567812345678"

// SM3UserIDLength is the recommended SM2 user ID length in bytes.
const SM3UserIDLength = 16

// SM3Hash computes the SM3 hash of data.
func SM3Hash(data []byte) []byte {
	h := sm3.Sum(data)
	return h[:]
}

// SM3HashHex computes the SM3 hash and returns it as a hex string.
func SM3HashHex(data []byte) string {
	h := sm3.Sum(data)
	return hex.EncodeToString(h[:])
}

// SM3HashForPublicKey computes the SM3 hash of a public key's DER encoding.
func SM3HashForPublicKey(pubKey crypto.PublicKey) ([]byte, error) {
	pubKeyBytes, err := smx509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return SM3Hash(pubKeyBytes), nil
}

// ComputeSM2UserID computes a 16-byte SM2 user identifier from a public key.
// Per GM/T 0009-2012, this is the first 16 bytes of the SM3 hash of the
// public key's DER encoding.
func ComputeSM2UserID(pubKey crypto.PublicKey) ([]byte, error) {
	h, err := SM3HashForPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return h[:SM3UserIDLength], nil
}
