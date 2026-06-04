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
	"github.com/ycq/pollux/sm4"
)

// EnvelopeResult 表示数字信封加密结果。
type EnvelopeResult struct {
	// DER 编码的 PKCS#7 EnvelopedData（包含 SM2 加密的 SM4 密钥 + SM4 密文）。
	EnvelopedData []byte
	// 临时证书 DER，解密时需要此证书匹配 RecipientInfo。
	certDER []byte
}

// EnvelopeEncrypt 使用 SM2 公钥对明文进行数字信封加密。
// 内部流程：生成随机 SM4 密钥 → SM4-CBC 加密明文 → SM2 加密 SM4 密钥 → 组装 PKCS#7 EnvelopedData。
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

// EnvelopeDecrypt 使用 SM2 私钥解密数字信封。
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

// EnvelopeEncryptSM4 使用 SM2+SM4-GCM 进行数字信封加密（简化版，不使用 PKCS#7 格式）。
// 返回 SM2 加密的 SM4 密钥、GCM nonce、SM4-GCM 密文。
func EnvelopeEncryptSM4(pub *ecdsa.PublicKey, plaintext []byte) (encryptedKey, nonce, ciphertext []byte, err error) {
	if pub == nil {
		return nil, nil, nil, errors.New("sm2: nil public key")
	}

	// 生成随机 SM4 密钥
	sm4Key, err := sm4.GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}

	// SM2 加密 SM4 密钥
	encryptedKey, err = EncryptASN1(rand.Reader, pub, sm4Key)
	if err != nil {
		return nil, nil, nil, err
	}

	// SM4-GCM 加密明文
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

// EnvelopeDecryptSM4 使用 SM2+SM4-GCM 解密数字信封（简化版）。
//
// SECURITY NOTE: This function does not implement timing-safe error handling.
// An attacker who can measure decryption time may be able to distinguish
// between "SM2 decryption failed" and "SM4-GCM authentication failed" errors,
// which could theoretically aid in chosen-ciphertext attacks. For applications
// where this distinction matters, add constant-time delays or unified error
// responses at the protocol layer.
func EnvelopeDecryptSM4(priv *PrivateKey, encryptedKey, nonce, ciphertext []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("sm2: nil private key")
	}

	// SM2 解密 SM4 密钥
	sm4Key, err := Decrypt(priv, encryptedKey)
	if err != nil {
		return nil, err
	}

	// SM4-GCM 解密
	aead, err := sm4.NewGCM(sm4Key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

// createTempCertForEnvelope 创建临时自签名证书用于 pkcs7 信封操作。
// 返回解析后的证书和原始 DER（用于后续解密时匹配 RecipientInfo）。
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
