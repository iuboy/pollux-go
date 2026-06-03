// Package sm2 implements the SM2 elliptic curve public key cryptography
// algorithm (GM/T 0003-2012), following crypto/ecdsa conventions.
//
// SM2 provides digital signatures and key exchange on the SM2 elliptic curve.
// PrivateKey implements the crypto.Signer interface.
//
// Basic usage:
//
//	key, err := sm2.GenerateKey(rand.Reader)
//	sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
//	ok := sm2.VerifyASN1(&key.PublicKey, digest, sig)
//
// Status: wrapper around gmsm/sm2
package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// PrivateKey is an SM2 private key. It implements crypto.Signer.
type PrivateKey = gmsmSM2.PrivateKey

// PublicKey is an SM2 public key.
type PublicKey = ecdsa.PublicKey

// GenerateKey generates a new SM2 private key.
func GenerateKey(r io.Reader) (*PrivateKey, error) {
	return gmsmSM2.GenerateKey(r)
}

// SignASN1 signs a hash using SM2 and returns the signature in ASN.1 format.
// opts may be nil for default behavior, or SM2SignerOption(uid) for GM/T 0009.
func SignASN1(r io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	return gmsmSM2.SignASN1(r, priv, hash, opts)
}

// VerifyASN1 verifies an ASN.1-encoded SM2 signature.
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {
	return gmsmSM2.VerifyASN1(pub, hash, sig)
}

// SignWithSM2 signs data with SM2 using the specified user ID per GM/T 0009-2012.
func SignWithSM2(r io.Reader, priv *PrivateKey, uid, data []byte) ([]byte, error) {
	opts := gmsmSM2.NewSM2SignerOption(true, uid)
	return priv.Sign(r, data, opts)
}

// VerifyWithSM2 verifies an SM2 signature with the specified user ID.
func VerifyWithSM2(pub *ecdsa.PublicKey, uid, data, sig []byte) bool {
	return gmsmSM2.VerifyASN1WithSM2(pub, uid, data, sig)
}

// EncryptASN1 encrypts data with an SM2 public key, returning ASN.1 format.
func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return gmsmSM2.EncryptASN1(random, pub, msg)
}

// Decrypt decrypts SM2-encrypted data.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return gmsmSM2.Decrypt(priv, ciphertext)
}

// P256 returns the SM2 elliptic curve.
func P256() elliptic.Curve {
	return gmsmSM2.P256()
}

// SM2SignerOption returns crypto.SignerOpts for SM2 signing with a user ID.
func SM2SignerOption(uid []byte) crypto.SignerOpts {
	return gmsmSM2.NewSM2SignerOption(true, uid)
}

// Compile-time interface check: PrivateKey implements crypto.Signer.
var _ crypto.Signer = (*PrivateKey)(nil)

// GenerateKeyDefault generates a new SM2 private key using crypto/rand.Reader.
func GenerateKeyDefault() (*PrivateKey, error) {
	return GenerateKey(rand.Reader)
}

// NewPrivateKey parses a DER-encoded SM2 private key.
func NewPrivateKey(der []byte) (*PrivateKey, error) {
	return gmsmSM2.NewPrivateKey(der)
}

// NewPublicKey parses a DER-encoded SM2 public key.
func NewPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	return gmsmSM2.NewPublicKey(der)
}

// NewSM2SignerOption returns a signer option for SM2 signing.
// forceGMSign true uses the national standard SM2 signing mode.
func NewSM2SignerOption(forceGMSign bool, uid []byte) crypto.SignerOpts {
	return gmsmSM2.NewSM2SignerOption(forceGMSign, uid)
}
