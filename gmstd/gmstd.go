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
//
// WARNING: despite the name, this does NOT return the standard SM2 user ID.
// Note on GM/T 0009-2012: the standard fixes the default SM2 user identifier
// to the ASCII string "1234567812345678" (16 bytes). It does NOT define the
// user ID as a hash of the public key. This helper instead derives a
// public-key-bound identifier as the first 16 bytes of SM3(DER-encoded
// public key), intended for callers that want a key-bound UID distinct from
// the default. For standard SM2 interop, use [DefaultSM2UserID] directly —
// using this key-bound UID where a peer expects the default UID will break
// signature interoperation silently.
func ComputeSM2UserID(pubKey crypto.PublicKey) ([]byte, error) {
	h, err := SM3HashForPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return h[:SM3UserIDLength], nil
}
