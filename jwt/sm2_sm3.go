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
// *ecdsa.PublicKey (which is what sm2.PublicKey aliases). The error wraps the
// actual received type via fmt.Errorf so callers debugging a misconfigured
// signer can see what they passed.
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
// User ID customization: the registered SigningMethodSM2SM3 singleton pins the
// user ID to the GM/T 0009 default. To use a non-default user ID (e.g. for a
// profile that mandates a key-bound UID), call [NewSM2SM3SigningMethod] with the
// desired uid to obtain a distinct [jwt.SigningMethod], then register it with
// jwt.RegisterSigningMethod under a distinct alg name. signingMethodSM2SM3 is
// unexported, so callers cannot construct it directly; NewSM2SM3SigningMethod is
// the only way to obtain a custom-UID variant.
//
// golang-jwt v5 SigningMethod contract:
//   - Sign(signingString string, key any) ([]byte, error) — returns raw sig
//   - Verify(signingString string, sig []byte, key any) error — receives raw sig
//   - Alg() string
var SigningMethodSM2SM3 jwt.SigningMethod = &signingMethodSM2SM3{
	uid: []byte(gmstd.DefaultSM2UserID),
}

// signingMethodSM2SM3 is the SM2+SM3 SigningMethod. The uid field is set at
// construction and treated as read-only thereafter; concurrent reads from
// Sign/Verify are safe. A future SetUID-style mutator would need to guard uid
// with a mutex.
type signingMethodSM2SM3 struct {
	uid []byte // GM/T 0009 user ID; default "1234567812345678"
}

// NewSM2SM3SigningMethod returns an SM2-SM3 [jwt.SigningMethod] that uses uid
// as the GM/T 0009 user ID instead of the default. Use it when a deployment
// mandates a non-default user ID; both signing and verifying ends MUST use the
// same uid.
//
// The returned method is independent of the package-registered
// [SigningMethodSM2SM3] singleton. To make the JWT parser dispatch to it,
// register it under a distinct alg name:
//
//	custom := jwt.NewSM2SM3SigningMethod([]byte("custom-uid"))
//	jwt.RegisterSigningMethod("SM2SM3-Custom", func() jwt.SigningMethod { return custom })
//
// Registering under the default "SM2SM3" name would overwrite the default
// singleton and silently change UID for all default-alg tokens — avoid that
// unless it is the explicit intent.
//
// A nil/empty uid falls back to gmstd.DefaultSM2UserID.
func NewSM2SM3SigningMethod(uid []byte) jwt.SigningMethod {
	if len(uid) == 0 {
		uid = []byte(gmstd.DefaultSM2UserID)
	}
	// Copy uid so later caller mutation cannot affect the method's behavior.
	uidCopy := make([]byte, len(uid))
	copy(uidCopy, uid)
	return &signingMethodSM2SM3{uid: uidCopy}
}

// Alg returns the JWT "alg" header value for this method.
func (m *signingMethodSM2SM3) Alg() string { return string(AlgSM2SM3) }

// Sign signs signingString with an SM2 private key and returns the raw
// ASN.1-encoded signature bytes. key MUST be a non-nil *sm2.PrivateKey. The
// JWT library handles base64url encoding when assembling the final token.
func (m *signingMethodSM2SM3) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*sm2.PrivateKey)
	if !ok || priv == nil {
		return nil, fmt.Errorf("%w: sign expects *sm2.PrivateKey, got %T", ErrInvalidSM2Key, key)
	}
	sig, err := sm2.SignWithSM2(rand.Reader, priv, m.uid, []byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("jwt/sm2sm3: SM2 sign failed: %w", err)
	}
	return sig, nil
}

// Verify validates an SM2-SM3 signature. key MUST be a non-nil
// *ecdsa.PublicKey (which is what sm2.PublicKey aliases). sig is the raw
// (base64-decoded) signature bytes as delivered by the JWT library's parser.
//
// Any verification failure (bad signature, wrong key, tampered payload)
// returns an error. The JWT library further enforces that the token's alg
// header matches this method via the keyFunc the caller passes to
// jwt.ParseWithClaims, defending against alg-confusion attacks.
func (m *signingMethodSM2SM3) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("%w: verify expects *ecdsa.PublicKey, got %T", ErrInvalidSM2Key, key)
	}
	if !sm2.VerifyWithSM2(pub, m.uid, []byte(signingString), sig) {
		return jwt.ErrSignatureInvalid
	}
	return nil
}
