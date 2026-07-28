// Package sm9 provides Go-idiomatic wrappers around gmsm/sm9.
//
// SM9 (GM/T 0005-2012) is an identity-based cryptographic algorithm.
// This package simplifies the gmsm API by providing a cleaner interface
// for key generation, signing, encryption, and key encapsulation.
//
// Status: wrapper around gmsm/sm9
package sm9

import (
	"crypto/rand"
	"errors"
	"io"

	gmsmSM9 "github.com/emmansun/gmsm/sm9"
)

var errUIDEmpty = errors.New("sm9: uid must not be empty")

// DefaultSignHID is the default signing HID per GM/T 0005-2012.
const DefaultSignHID byte = 0x01

// DefaultEncryptHID is the default encryption HID per GM/T 0005-2012.
const DefaultEncryptHID byte = 0x03

// SignMasterPrivateKey represents an SM9 signing master private key.
type SignMasterPrivateKey = gmsmSM9.SignMasterPrivateKey

// SignMasterPublicKey represents an SM9 signing master public key.
type SignMasterPublicKey = gmsmSM9.SignMasterPublicKey

// SignPrivateKey represents an SM9 signing user private key.
type SignPrivateKey = gmsmSM9.SignPrivateKey

// EncryptMasterPrivateKey represents an SM9 encryption master private key.
type EncryptMasterPrivateKey = gmsmSM9.EncryptMasterPrivateKey

// EncryptMasterPublicKey represents an SM9 encryption master public key.
type EncryptMasterPublicKey = gmsmSM9.EncryptMasterPublicKey

// EncryptPrivateKey represents an SM9 encryption user private key.
type EncryptPrivateKey = gmsmSM9.EncryptPrivateKey

// EncrypterOpts configures SM9 encryption mode.
type EncrypterOpts = gmsmSM9.EncrypterOpts

// GenerateSignMasterKey generates a new SM9 signing master key pair.
func GenerateSignMasterKey() (*SignMasterPrivateKey, error) {
	return gmsmSM9.GenerateSignMasterKey(rand.Reader)
}

// GenerateSignUserKey derives a signing user private key from the master key.
func GenerateSignUserKey(master *SignMasterPrivateKey, uid []byte) (*SignPrivateKey, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return master.GenerateUserKey(uid, DefaultSignHID)
}

// GenerateEncryptMasterKey generates a new SM9 encryption master key pair.
func GenerateEncryptMasterKey() (*EncryptMasterPrivateKey, error) {
	return gmsmSM9.GenerateEncryptMasterKey(rand.Reader)
}

// GenerateEncryptUserKey derives an encryption user private key from the master key.
func GenerateEncryptUserKey(master *EncryptMasterPrivateKey, uid []byte) (*EncryptPrivateKey, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return master.GenerateUserKey(uid, DefaultEncryptHID)
}

// Sign signs data using SM9. The data parameter is the raw message to be signed;
// the SM9 library handles hashing internally, so callers should pass the original
// message, not a pre-hashed value.
func Sign(privateKey *SignPrivateKey, data []byte) ([]byte, error) {
	return gmsmSM9.SignASN1(rand.Reader, privateKey, data)
}

// Verify verifies an SM9 signature on data. The data parameter must match what was
// passed to Sign (the original message, not a hash).
func Verify(publicKey *SignMasterPublicKey, uid []byte, data, sig []byte) bool {
	if len(uid) == 0 {
		return false
	}
	return gmsmSM9.VerifyASN1(publicKey, uid, DefaultSignHID, data, sig)
}

// Encrypt encrypts plaintext using SM9 with the specified options.
func Encrypt(publicKey *EncryptMasterPublicKey, uid []byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return gmsmSM9.EncryptASN1(rand.Reader, publicKey, uid, DefaultEncryptHID, plaintext, opts)
}

// Decrypt decrypts SM9 ciphertext.
func Decrypt(privateKey *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return gmsmSM9.DecryptASN1(privateKey, uid, ciphertext)
}

// WrapKey encapsulates a key using SM9 key encapsulation mechanism.
func WrapKey(publicKey *EncryptMasterPublicKey, uid []byte, keyLen int) (key []byte, cipher []byte, err error) {
	if len(uid) == 0 {
		return nil, nil, errUIDEmpty
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, nil, errors.New("sm9: keyLen must be between 1 and 1024")
	}
	return gmsmSM9.WrapKey(rand.Reader, publicKey, uid, DefaultEncryptHID, keyLen)
}

// WrapKeyASN1 encapsulates a key using SM9 and returns ASN.1 encoded result.
func WrapKeyASN1(publicKey *EncryptMasterPublicKey, uid []byte, keyLen int) ([]byte, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, errors.New("sm9: keyLen must be between 1 and 1024")
	}
	return publicKey.WrapKeyASN1(rand.Reader, uid, DefaultEncryptHID, keyLen)
}

// UnwrapKey decapsulates a key from SM9 key encapsulation.
func UnwrapKey(privateKey *EncryptPrivateKey, uid, cipher []byte, keyLen int) ([]byte, error) {
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return gmsmSM9.UnwrapKey(privateKey, uid, cipher, keyLen)
}

// GenerateSignMasterKeyFromReader generates a signing master key using a custom reader.
func GenerateSignMasterKeyFromReader(r io.Reader) (*SignMasterPrivateKey, error) {
	return gmsmSM9.GenerateSignMasterKey(r)
}

// GenerateEncryptMasterKeyFromReader generates an encryption master key using a custom reader.
func GenerateEncryptMasterKeyFromReader(r io.Reader) (*EncryptMasterPrivateKey, error) {
	return gmsmSM9.GenerateEncryptMasterKey(r)
}
