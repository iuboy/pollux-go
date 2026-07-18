package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iuboy/pollux-go/gmstd"
	"github.com/iuboy/pollux-go/sm2"
)

// ErrInvalidSM2Key is returned when Sign/Verify receive a key of the wrong
// type. SM2 signing requires *sm2.PrivateKey; verifying requires
// *ecdsa.PublicKey (which is what sm2.PublicKey aliases).
var ErrInvalidSM2Key = errors.New("jwt/sm2sm3: key must be *sm2.PrivateKey (sign) or *ecdsa.PublicKey (verify)")

// init registers the SM2-SM3 signing method with golang-jwt so its parser
// can dispatch tokens carrying alg="SM2SM3".
func init() {
	jwt.RegisterSigningMethod(string(AlgSM2SM3), func() jwt.SigningMethod {
		return SigningMethodSM2SM3
	})
}

// SigningMethodSM2SM3 implements [jwt.SigningMethod] for SM2 with SM3
// prehash per GM/T 0009-2012. The signing flow:
//
//  1. The JWT library builds signingString = base64(header) + "." + base64(payload).
//  2. Sign invokes sm2.SignWithSM2(rand, priv, uid, signingString), which
//     computes the ZA value from the public key + user ID, hashes
//     ZA || signingString with SM3, and signs the digest with SM2.
//  3. The ASN.1-encoded signature is returned as raw bytes; the JWT library
//     applies base64url encoding when assembling the final token.
//
// Verify reverses the flow via sm2.VerifyWithSM2 with the same user ID.
//
// The default user ID is gmstd.DefaultSM2UserID ("1234567812345678"). Both
// ends MUST agree on the user ID or signatures will not verify.
//
// golang-jwt v5 SigningMethod contract:
//   - Sign(signingString string, key any) ([]byte, error) — returns raw sig
//   - Verify(signingString string, sig []byte, key any) error — receives raw sig
//   - Alg() string
var SigningMethodSM2SM3 jwt.SigningMethod = &signingMethodSM2SM3{
	uid: []byte(gmstd.DefaultSM2UserID),
}

type signingMethodSM2SM3 struct {
	uid []byte // GM/T 0009 user ID; default "1234567812345678"
}

// Alg returns the JWT "alg" header value for this method.
func (m *signingMethodSM2SM3) Alg() string { return string(AlgSM2SM3) }

// Sign signs signingString with an SM2 private key and returns the raw
// ASN.1-encoded signature bytes. key MUST be *sm2.PrivateKey. The JWT library
// handles base64url encoding when assembling the final token.
func (m *signingMethodSM2SM3) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, ErrInvalidSM2Key
	}
	sig, err := sm2.SignWithSM2(rand.Reader, priv, m.uid, []byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("jwt/sm2sm3: SM2 sign failed: %w", err)
	}
	return sig, nil
}

// Verify validates an SM2-SM3 signature. key MUST be *ecdsa.PublicKey
// (which is what sm2.PublicKey aliases). sig is the raw (base64-decoded)
// signature bytes as delivered by the JWT library's parser.
//
// Any verification failure (bad signature, wrong key, tampered payload)
// returns an error. The JWT library further enforces that the token's alg
// header matches this method via the keyFunc the caller passes to
// jwt.ParseWithClaims, defending against alg-confusion attacks.
func (m *signingMethodSM2SM3) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidSM2Key
	}
	if !sm2.VerifyWithSM2(pub, m.uid, []byte(signingString), sig) {
		return jwt.ErrSignatureInvalid
	}
	return nil
}
