package tls13gm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/iuboy/pollux-go/sm2"
)

// CurveSM2 is the TLS NamedCurve ID for the SM2 elliptic curve
// as defined in RFC 8998 Section 4.
const CurveSM2 uint16 = 0x0029

// CurveSM2KeySize is the byte length of a curveSM2 key share (uncompressed point).
const CurveSM2KeySize = 65 // 0x04 + 32 + 32

// GenerateCurveSM2KeyPair generates an SM2 key pair for use in TLS 1.3 key_share.
func GenerateCurveSM2KeyPair(r io.Reader) (*sm2.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	return sm2.GenerateKey(r)
}

// CurveSM2ECDHE computes the shared secret using SM2 ECDH.
// privateKey is the local ephemeral SM2 private key.
// peerPublic is the peer's SM2 public key from the key_share extension.
//
// This performs raw ECDH scalar multiplication (x-coordinate only),
// matching the TLS 1.3 key agreement semantics (not GM/T 0003.3 key exchange).
func CurveSM2ECDHE(privateKey *sm2.PrivateKey, peerPublic *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("tls13gm: privateKey is nil")
	}
	if peerPublic == nil {
		return nil, fmt.Errorf("tls13gm: peerPublic is nil")
	}
	// Verify the peer's public key is on the curve to prevent invalid-curve attacks.
	// Without this check, a malicious peer could send a point on a different curve
	// to extract information about the private scalar.
	if !peerPublic.Curve.IsOnCurve(peerPublic.X, peerPublic.Y) {
		return nil, fmt.Errorf("tls13gm: peer public key is not on the SM2 curve")
	}
	// sm2.PrivateKey embeds ecdsa.PrivateKey (via PublicKey), so .D and .Curve
	// are directly accessible. Perform raw scalar multiplication on the peer's
	// public point using our private scalar.
	//
	// ScalarMult is deprecated for NIST curves (use crypto/ecdh instead), but
	// SM2 uses a custom curve that crypto/ecdh does not support, so this is
	// the correct approach.
	//
	// Pad private scalar to 32 bytes (SM2 field element size) for constant-time
	// consistency. D.Bytes() returns minimal encoding, which may be shorter
	// than 32 bytes if leading bytes happen to be zero.
	const scalarSize = 32
	dBytes := make([]byte, scalarSize)
	rawD := privateKey.D.Bytes()
	copy(dBytes[scalarSize-len(rawD):], rawD)

	x, _ := peerPublic.Curve.ScalarMult(peerPublic.X, peerPublic.Y, dBytes)
	if x == nil {
		return nil, fmt.Errorf("tls13gm: ECDH scalar multiplication failed")
	}
	shared := x.Bytes()
	// Pad shared secret to 32 bytes.
	if len(shared) < scalarSize {
		padded := make([]byte, scalarSize)
		copy(padded[scalarSize-len(shared):], shared)
		shared = padded
	}
	return shared[:scalarSize], nil
}
