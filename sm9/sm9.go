package sm9

import (
	"crypto/rand"
	"errors"
	"io"

	gmsmSM9 "github.com/emmansun/gmsm/sm9"
)

var (
	errUIDEmpty         = errors.New("sm9: uid must not be empty")
	errNilSignMaster    = errors.New("sm9: nil signing master key")
	errNilEncMaster     = errors.New("sm9: nil encryption master key")
	errNilSignPriv      = errors.New("sm9: nil signing private key")
	errNilEncPriv       = errors.New("sm9: nil encryption private key")
	errNilEncMasterPub  = errors.New("sm9: nil encryption master public key")
	errNilSignMasterPub = errors.New("sm9: nil signing master public key")
	errSigEmpty         = errors.New("sm9: empty signature")

	// ErrSignatureInvalid is returned by Verify when signature verification
	// fails. It is distinct from input-validation errors (nil key, empty uid,
	// empty signature), which indicate caller misuse rather than an invalid
	// signature. Use errors.Is to distinguish the two classes.
	ErrSignatureInvalid = errors.New("sm9: signature verification failed")
)

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
	if master == nil {
		return nil, errNilSignMaster
	}
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
	if master == nil {
		return nil, errNilEncMaster
	}
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return master.GenerateUserKey(uid, DefaultEncryptHID)
}

// Sign signs data using SM9. The data parameter is the raw message to be signed;
// the SM9 library handles hashing internally, so callers should pass the original
// message, not a pre-hashed value.
func Sign(privateKey *SignPrivateKey, data []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errNilSignPriv
	}
	return gmsmSM9.SignASN1(rand.Reader, privateKey, data)
}

// Verify verifies an SM9 signature on data. The data parameter must match what
// was passed to Sign (the original message, not a hash).
//
// It returns nil if the signature is valid, or an error describing the
// failure otherwise. Input-validation errors (nil publicKey, empty uid, empty
// signature) are returned separately from ErrSignatureInvalid so callers can
// distinguish caller misuse from a genuine verification failure via errors.Is:
//
//	if err := sm9.Verify(pub, uid, msg, sig); err != nil {
//	    if errors.Is(err, sm9.ErrSignatureInvalid) {
//	        // signature genuinely invalid
//	    } else {
//	        // input misuse (nil key, empty uid/sig)
//	    }
//	}
//
// NOTE: this is a breaking API change from the previous bool-returning Verify.
// Callers that want the legacy boolean behavior should use VerifyBool.
func Verify(publicKey *SignMasterPublicKey, uid, data, sig []byte) error {
	if publicKey == nil {
		return errNilSignMasterPub
	}
	if len(uid) == 0 {
		return errUIDEmpty
	}
	if len(sig) == 0 {
		return errSigEmpty
	}
	if !gmsmSM9.VerifyASN1(publicKey, uid, DefaultSignHID, data, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// VerifyBool is the legacy boolean variant of Verify. It returns true if and
// only if the signature is valid; any error (nil key, empty uid, malformed
// signature) returns false. New code should prefer Verify for richer error
// information. VerifyBool is retained for callers that chain directly into
// if/else branches and for backward compatibility with the pre-v2 API.
func VerifyBool(publicKey *SignMasterPublicKey, uid, data, sig []byte) bool {
	return Verify(publicKey, uid, data, sig) == nil
}

// Encrypt encrypts plaintext using SM9 with the specified options.
func Encrypt(publicKey *EncryptMasterPublicKey, uid []byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if publicKey == nil {
		return nil, errNilEncMasterPub
	}
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return gmsmSM9.EncryptASN1(rand.Reader, publicKey, uid, DefaultEncryptHID, plaintext, opts)
}

// Decrypt decrypts SM9 ciphertext.
func Decrypt(privateKey *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errNilEncPriv
	}
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	return gmsmSM9.DecryptASN1(privateKey, uid, ciphertext)
}

// WrapKey encapsulates a key using SM9 key encapsulation mechanism.
func WrapKey(publicKey *EncryptMasterPublicKey, uid []byte, keyLen int) (key []byte, cipher []byte, err error) {
	if publicKey == nil {
		return nil, nil, errNilEncMasterPub
	}
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
	if publicKey == nil {
		return nil, errNilEncMasterPub
	}
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, errors.New("sm9: keyLen must be between 1 and 1024")
	}
	return publicKey.WrapKeyASN1(rand.Reader, uid, DefaultEncryptHID, keyLen)
}

// UnwrapKey decapsulates a key from SM9 key encapsulation.
// keyLen is validated for the same 1..1024 range as WrapKey/WrapKeyASN1 to
// mirror the wrap-side contract and prevent gmsm panic on illegal lengths.
func UnwrapKey(privateKey *EncryptPrivateKey, uid, cipher []byte, keyLen int) ([]byte, error) {
	if privateKey == nil {
		return nil, errNilEncPriv
	}
	if len(uid) == 0 {
		return nil, errUIDEmpty
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, errors.New("sm9: keyLen must be between 1 and 1024")
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
