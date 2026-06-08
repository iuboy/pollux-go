package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/pkcs"
	gmsmPkcs7 "github.com/emmansun/gmsm/pkcs7"
	smx509 "github.com/emmansun/gmsm/smx509"
	"github.com/ycq/pollux/internal/memsecure"
	"github.com/ycq/pollux/sm4"
)

// EnvelopeResult represents a digital envelope encryption result.
type EnvelopeResult struct {
	// DER-encoded PKCS#7 EnvelopedData (contains SM2-encrypted SM4 key + SM4 ciphertext).
	EnvelopedData []byte
	// Temporary certificate DER, needed for RecipientInfo matching during decryption.
	certDER []byte
}

// EnvelopeEncrypt encrypts plaintext using SM2 public key digital envelope.
// Internal process: generate random SM4 key -> SM4-CBC encrypt plaintext -> SM2 encrypt SM4 key -> assemble PKCS#7 EnvelopedData.
func EnvelopeEncrypt(pub *ecdsa.PublicKey, plaintext []byte) (*EnvelopeResult, error) {
	if pub == nil {
		return nil, errors.New("sm2: nil public key")
	}

	cert, certDER, err := createTempCertForEnvelope()
	if err != nil {
		return nil, err
	}

	ed, err := gmsmPkcs7.NewSM2EnvelopedData(pkcs.SM4, plaintext)
	if err != nil {
		return nil, err
	}

	if err := ed.AddRecipient(cert, 0, func(c *smx509.Certificate, key []byte) ([]byte, error) {
		return EncryptASN1(rand.Reader, pub, key)
	}); err != nil {
		return nil, err
	}

	der, err := ed.Finish()
	if err != nil {
		return nil, err
	}

	return &EnvelopeResult{EnvelopedData: der, certDER: certDER}, nil
}

// EnvelopeDecrypt decrypts digital envelope using SM2 private key.
func EnvelopeDecrypt(priv *PrivateKey, env *EnvelopeResult) ([]byte, error) {
	if priv == nil || env == nil {
		return nil, errors.New("sm2: nil private key or envelope")
	}

	p7, err := gmsmPkcs7.Parse(env.EnvelopedData)
	if err != nil {
		return nil, err
	}

	if len(env.certDER) == 0 {
		return nil, errors.New("sm2: missing certificate in envelope")
	}
	cert, err := smx509.ParseCertificate(env.certDER)
	if err != nil {
		return nil, err
	}

	return p7.Decrypt(cert, priv)
}

// EnvelopeEncryptSM4 encrypts using SM2+SM4-GCM digital envelope (simplified, non-PKCS#7 format).
// Returns SM2-encrypted SM4 key, GCM nonce, SM4-GCM ciphertext.
func EnvelopeEncryptSM4(pub *ecdsa.PublicKey, plaintext []byte) (encryptedKey, nonce, ciphertext []byte, err error) {
	if pub == nil {
		return nil, nil, nil, errors.New("sm2: nil public key")
	}

	// Generate random SM4 key
	sm4Key, err := sm4.GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	defer memsecure.ZeroBytes(sm4Key)

	// SM2-encrypt the SM4 key
	encryptedKey, err = EncryptASN1(rand.Reader, pub, sm4Key)
	if err != nil {
		return nil, nil, nil, err
	}

	// SM4-GCM encrypt plaintext
	aead, err := sm4.NewGCM(sm4Key)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return
}

// EnvelopeDecryptSM4 decrypts SM2+SM4-GCM digital envelope (simplified).
//
// SECURITY NOTE: Error messages are intentionally generic ("sm2: decryption failed")
// to prevent timing side-channel leakage. An attacker who can measure decryption time
// should not be able to distinguish between "SM2 decryption failed" and
// "SM4-GCM authentication failed" errors.
func EnvelopeDecryptSM4(priv *PrivateKey, encryptedKey, nonce, ciphertext []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("sm2: nil private key")
	}

	// SM2-decrypt the SM4 key
	sm4Key, err := Decrypt(priv, encryptedKey)
	if err != nil {
		return nil, errors.New("sm2: decryption failed")
	}
	defer memsecure.ZeroBytes(sm4Key)

	// SM4-GCM decrypt
	aead, err := sm4.NewGCM(sm4Key)
	if err != nil {
		return nil, errors.New("sm2: decryption failed")
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("sm2: decryption failed")
	}

	return plaintext, nil
}

// createTempCertForEnvelope creates a temporary self-signed certificate for PKCS#7 envelope operations.
// Returns parsed certificate and raw DER (for RecipientInfo matching during subsequent decryption).
func createTempCertForEnvelope() (*smx509.Certificate, []byte, error) {
	tmpPriv, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &smx509.Certificate{
		SerialNumber:          sn,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &tmpPriv.PublicKey, tmpPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, der, nil
}
