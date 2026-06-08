package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/ycq/pollux/internal/memsecure"
)

var (
	errInvalidCompressedKey = errors.New("sm2: invalid compressed public key")
	errNotOnCurve           = errors.New("sm2: point not on SM2 curve")
)

// CompressPublicKey compresses SM2 public key to 33 bytes (02/03 prefix + X coordinate).
func CompressPublicKey(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	curve := P256()
	return elliptic.MarshalCompressed(curve, pub.X, pub.Y)
}

// DecompressPublicKey decompresses compressed SM2 public key (33 bytes) to full public key.
func DecompressPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	curve := P256()
	if len(data) != 33 {
		return nil, errInvalidCompressedKey
	}

	x, y := elliptic.UnmarshalCompressed(curve, data)
	if x == nil || y == nil {
		return nil, errInvalidCompressedKey
	}

	// Verify point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, errNotOnCurve
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// MarshalUncompressed serializes SM2 public key to uncompressed format (65 bytes: 04 + X + Y).
func MarshalUncompressed(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return elliptic.Marshal(P256(), pub.X, pub.Y) //nolint:staticcheck
}

// UnmarshalUncompressed parses SM2 public key from uncompressed format.
func UnmarshalUncompressed(data []byte) (*ecdsa.PublicKey, error) {
	curve := P256()
	x, y := elliptic.Unmarshal(curve, data) //nolint:staticcheck
	if x == nil {
		return nil, errInvalidCompressedKey
	}
	if !curve.IsOnCurve(x, y) {
		return nil, errNotOnCurve
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// PublicKeyToBytes converts SM2 public key to uncompressed byte sequence.
// Deprecated: use MarshalUncompressed instead.
func PublicKeyToBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return elliptic.Marshal(P256(), pub.X, pub.Y) //nolint:staticcheck
}

// BytesToPublicKey parses SM2 public key from byte sequence.
// Deprecated: use UnmarshalUncompressed instead.
func BytesToPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	return UnmarshalUncompressed(data)
}

// Equal reports whether two SM2 public keys are equal.
func Equal(x, y *ecdsa.PublicKey) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.X.Cmp(y.X) == 0 && x.Y.Cmp(y.Y) == 0
}

// SecureKeyBytes holds sensitive private key bytes with an explicit Destroy method.
// This provides a safer alternative to PrivateKeyToBytes by making cleanup part of
// the type contract.
type SecureKeyBytes struct {
	bytes []byte
}

// Data returns the underlying key bytes. Callers must not retain references
// after calling Destroy.
func (s *SecureKeyBytes) Data() []byte {
	return s.bytes
}

// Destroy securely zeroes the key material and releases the reference.
func (s *SecureKeyBytes) Destroy() {
	if s.bytes != nil {
		memsecure.ZeroBytes(s.bytes)
		s.bytes = nil
	}
}

// PrivateKeyToBytesSecure returns the private key scalar as a SecureKeyBytes
// that must be explicitly destroyed after use. This is the recommended way
// to access raw private key bytes.
//
// Example:
//
//	skb, err := sm2.PrivateKeyToBytesSecure(key)
//	if err != nil { ... }
//	defer skb.Destroy()
//	use(skb.Data())
func PrivateKeyToBytesSecure(key *PrivateKey) (*SecureKeyBytes, error) {
	if key == nil {
		return nil, errors.New("sm2: nil private key")
	}
	return &SecureKeyBytes{bytes: key.D.Bytes()}, nil
}

// PrivateKeyToBytes serializes SM2 private key to 32-byte big-endian integer.
//
// Deprecated: use PrivateKeyToBytesSecure instead, which provides explicit
// key material cleanup via SecureKeyBytes.Destroy.
//
// Security: the returned bytes contain sensitive key material.
// Callers MUST zero the returned slice after use via memsecure.ZeroBytes
// or by overwriting with zeros. Do not leave copies in memory.
func PrivateKeyToBytes(key *PrivateKey) []byte {
	return key.D.Bytes()
}

// BytesToPrivateKey recovers SM2 private key from 32-byte big-endian integer.
func BytesToPrivateKey(data []byte) (*PrivateKey, error) {
	curve := sm2ec.P256()
	d := new(big.Int).SetBytes(data)
	n := curve.Params().N
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("sm2: private key scalar out of range")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	sm2Priv := new(gmsmSM2.PrivateKey)
	_, err := sm2Priv.FromECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return sm2Priv, nil
}
