package tls13gm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
)

// CurveSM2 is the TLS NamedCurve ID for the SM2 elliptic curve
// as defined in RFC 8998 Section 4.
const CurveSM2 uint16 = 0x0029

// CurveSM2KeySize is the byte length of a curveSM2 key share (uncompressed point).
const CurveSM2KeySize = 65 // 0x04 + 32 + 32

// GenerateCurveSM2KeyPair generates an SM2 key pair for use in TLS 1.3 key_share.
//
// Since the Go 1.26 crypto modernization this function takes no randomness
// source. The standard library now ignores caller-supplied io.Reader
// randomness in crypto/ecdh.Curve.GenerateKey, crypto/rand.Prime and the
// key-generation paths of ecdsa/ed25519/rsa, because a weak, nil, or replayed
// reader silently degrades key material at the most sensitive point of a
// protocol. pollux-go aligns with that semantics: the ephemeral key is always
// drawn from crypto/rand, and a caller cannot opt out.
func GenerateCurveSM2KeyPair() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// CurveSM2ECDHE computes the shared secret using SM2 ECDH.
// privateKey is the local ephemeral SM2 private key.
// peerPublic is the peer's SM2 public key from the key_share extension.
//
// This performs raw ECDH scalar multiplication (x-coordinate only),
// matching the TLS 1.3 key agreement semantics (not GM/T 0003.3 key exchange).
//
// The exchange is delegated to gmsm's ecdh package — the SM2 equivalent of
// crypto/ecdh, built on the constant-time point arithmetic ported from
// crypto/internal/nistec. This replaces the previous hand-rolled
// elliptic.Curve.ScalarMult call (deprecated API) and strengthens validation:
// the conversion path rejects private scalars outside [1, N-1] and off-curve
// peer points, the multiplication is constant-time, and the result is the
// fixed-width 32-byte x-coordinate with the point at infinity rejected — so
// the manual zero-padding of the shared secret is no longer needed.
func CurveSM2ECDHE(privateKey *sm2.PrivateKey, peerPublic *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("tls13gm: privateKey is nil")
	}
	if peerPublic == nil {
		return nil, errors.New("tls13gm: peerPublic is nil")
	}
	// Curve identity check on BOTH keys. The ECDH scalar below is the SM2
	// private scalar, so it MUST only ever be multiplied on the SM2 curve.
	// Performing it on a different (e.g. NIST) curve would be a catastrophic
	// cross-curve error leaking the private scalar. sm2.PublicKey is a type
	// alias for ecdsa.PublicKey, so the type system cannot enforce this — the
	// check must be explicit on BOTH the local private key's curve AND the
	// peer's public key's curve. (The gmsm conversions below enforce it again;
	// these guards keep the error specific.)
	if privateKey.Curve != sm2.P256() {
		return nil, errors.New("tls13gm: local private key is not on the SM2 curve")
	}
	if peerPublic.Curve != sm2.P256() {
		return nil, errors.New("tls13gm: peer public key is not on the SM2 curve")
	}
	// privateKey.D is populated by sm2.GenerateKey, but CurveSM2ECDHE is a public
	// API reachable from keys constructed via other means (unmarshal, zero-value
	// declarations) where D may be nil. A nil D would panic inside gmsm's
	// conversion below (big.Int method on nil receiver).
	if privateKey.D == nil {
		return nil, errors.New("tls13gm: private key scalar D is nil")
	}
	priv, err := privateKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("tls13gm: convert SM2 private key for ECDH: %w", err)
	}
	// PublicKeyToECDH re-validates that the peer point is on the curve (defense
	// in depth against invalid-curve attacks for callers that did not parse
	// the point via sm2.UnmarshalUncompressed).
	peer, err := sm2.PublicKeyToECDH(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: convert SM2 public key for ECDH: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: SM2 ECDH: %w", err)
	}
	return shared, nil
}
