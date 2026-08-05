package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// PrivateKey is an SM2 private key. It implements crypto.Signer.
//
// Note: this is a type alias (=) to gmsmSM2.PrivateKey, which provides
// direct access to all underlying methods. If the underlying library changes
// in a future major version, this alias will be replaced by a wrapper struct.
type PrivateKey = gmsmSM2.PrivateKey

// PublicKey is an SM2 public key.
//
// Note: this is a type alias (=) to ecdsa.PublicKey. See PrivateKey docs
// for implications.
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
//
// IMPORTANT — semantic difference from crypto.Signer.Sign: `data` here is the
// RAW message, NOT a pre-hashed digest. The GM signing primitive performs the
// full ZA||SM3(message) computation internally (ZA is the SM2 "user
// information" hash derived from uid + curve parameters + public key). This
// matches GB/T 32918 but diverges from crypto.Signer.Sign's contract, which
// expects the caller to supply a pre-hashed digest and the matching
// crypto.SignerOpts.HashFunc. Passing a pre-hashed digest to SignWithSM2 would
// hash the hash again, producing a different signature than intended.
//
// Callers integrating with crypto.Signer should use (*PrivateKey).Sign with an
// SM2SignerOption instead; SignWithSM2 is a convenience wrapper for callers
// that want the raw-message path directly.
func SignWithSM2(r io.Reader, priv *PrivateKey, uid, data []byte) ([]byte, error) {
	opts := gmsmSM2.NewSM2SignerOption(true, uid)
	return priv.Sign(r, data, opts)
}

// VerifyWithSM2 verifies an SM2 signature with the specified user ID.
//
// `data` is the RAW message that was signed (NOT a pre-hashed digest); the
// verifier recomputes ZA||SM3(message) using uid and compares. See SignWithSM2
// for the corresponding signing semantics.
//
// pub is *PublicKey (= *ecdsa.PublicKey via the package-level type alias).
// The alias form is preferred for in-package API consistency; the underlying
// type is identical so callers may pass either spelling.
func VerifyWithSM2(pub *PublicKey, uid, data, sig []byte) bool {
	return gmsmSM2.VerifyASN1WithSM2(pub, uid, data, sig)
}

// EncryptASN1 encrypts data with an SM2 public key, returning ASN.1 format.
//
// pub is *PublicKey (= *ecdsa.PublicKey via the package-level type alias).
func EncryptASN1(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	return gmsmSM2.EncryptASN1(random, pub, msg)
}

// Decrypt decrypts SM2-encrypted data.
//
// Despite the name lacking the ASN1 suffix, this is the inverse of
// EncryptASN1: it auto-detects the ciphertext encoding by the leading byte
// (0x30 → ASN.1 SEQUENCE, 0x04/0x02/0x03 → plain point-prefixed) and
// decrypts with the national-standard C1C3C2 ordering. The naming
// asymmetry (EncryptASN1 / Decrypt) is preserved for compatibility; new
// callers should pair EncryptASN1 with Decrypt and not assume Decrypt
// accepts a different format.
//
// LIMITATION: Decrypt ALWAYS assumes C1C3C2 ordering. To decrypt a legacy
// C1C2C3-ordered ciphertext (GM/T 0003-2012, old GmSSL / Java BC / 金融 IC
// 卡), use DecryptWithOpts with a NewDecrypterOpts(..., OrderC1C2C3) option,
// or first convert the ordering via AdjustCipherOrder(ct, OrderC1C2C3,
// OrderC1C3C2) and then call Decrypt.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return gmsmSM2.Decrypt(priv, ciphertext)
}

// Encrypt encrypts data with an SM2 public key under explicit cipher options.
//
// opts == nil selects the gmsm default (plain encoding, uncompressed point,
// C1C3C2 order). For ASN.1 output use EncryptASN1, or construct opts via
// NewEncrypterOpts(EncodingASN1, ...) and pass here. For legacy C1C2C3
// ordering or plain encoding, build opts with NewEncrypterOpts.
//
// Unlike EncryptASN1 (which fixes ASN.1 + C1C3C2), this entry point exposes
// the full encoding/ordering matrix and is the supported path for
// interoperating with legacy systems.
func Encrypt(random io.Reader, pub *PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("sm2: nil public key")
	}
	return gmsmSM2.Encrypt(random, pub, msg, opts)
}

// DecryptWithOpts decrypts SM2 ciphertext under explicit cipher options.
//
// Use this when the ciphertext uses non-default ordering (C1C2C3) or when
// you want to pin the encoding explicitly. opts == nil falls back to the
// same behavior as Decrypt (auto-detect encoding, C1C3C2 order). Construct
// opts via NewDecrypterOpts.
//
// This is the only decryption entry point that accepts C1C2C3-ordered
// ciphertext.
func DecryptWithOpts(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("sm2: nil private key")
	}
	// gmsm's package-level Decrypt(priv, ct) does not accept opts; the opts-aware
	// path is the method (*PrivateKey).Decrypt(rand, msg, crypto.DecrypterOpts),
	// which *DecrypterOpts implements. rand.Reader is unused by SM2 decryption
	// but required by the crypto.Decrypter interface.
	return priv.Decrypt(rand.Reader, ciphertext, opts)
}

// P256 returns the SM2 elliptic curve.
func P256() elliptic.Curve {
	return gmsmSM2.P256()
}

// SM2SignerOption returns crypto.SignerOpts for SM2 signing with a user ID.
//
// Deprecated: use NewSM2SignerOption(true, uid) instead for explicit control
// over the forceGMSign parameter.
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
