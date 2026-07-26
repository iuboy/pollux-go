package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/iuboy/pollux-go/internal/memsecure"
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

// Equal reports whether two SM2 public keys are equal. Both keys MUST be on
// the SM2 curve (P256); keys on different curves are never equal even if their
// coordinates happen to match, preventing cross-curve confusion attacks.
func Equal(x, y *ecdsa.PublicKey) bool {
	if x == nil || y == nil {
		return x == y
	}
	// Compare curve identity first — coordinate-only comparison would let a
	// P-256 key from a non-SM2 curve match an SM2 key with identical coords.
	if x.Curve != y.Curve {
		// Fall back to curve-parameter comparison in case the two curves are
		// distinct instances with identical parameters (e.g. gmsm vs stdlib).
		xp, yp := x.Curve.Params(), y.Curve.Params()
		if xp == nil || yp == nil || xp.Name != yp.Name || xp.P.Cmp(yp.P) != 0 {
			return false
		}
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

// PrivateKeyToBytesSecure returns the private key scalar as a fixed-length
// 32-byte big-endian SecureKeyBytes that must be explicitly destroyed after
// use. This is the recommended way to access raw private key bytes.
//
// The 32-byte fixed-length encoding matches the contract of NewPrivateKey and
// BytesToPrivateKey, so the output round-trips cleanly through both. (A minimal
// big.Int encoding — key.D.Bytes() — could be shorter when the scalar has
// leading zero bytes, which those parsers reject.)
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
	if key.D == nil {
		return nil, errors.New("sm2: private key scalar D is nil")
	}
	const scalarSize = 32 // SM2 curve order size in bytes
	out := make([]byte, scalarSize)
	key.D.FillBytes(out)
	return &SecureKeyBytes{bytes: out}, nil
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
