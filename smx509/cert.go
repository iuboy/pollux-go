package smx509

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	gmsmSM3 "github.com/emmansun/gmsm/sm3"
	smx509 "github.com/emmansun/gmsm/smx509"
	"github.com/iuboy/pollux-go/internal/memsecure"
	polluxSM4 "github.com/iuboy/pollux-go/sm4"
	"golang.org/x/crypto/pbkdf2"
)

// IsSM2Key reports whether a private key is an SM2 key.
func IsSM2Key(key any) bool {
	switch k := key.(type) {
	case *sm2.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return k.Curve == sm2.P256()
	}
	return false
}

// IsSM2PublicKey reports whether a public key is an SM2 public key.
func IsSM2PublicKey(pub any) bool {
	if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
		return ecdsaPub.Curve == sm2.P256()
	}
	return false
}

// CreateCertificate creates a certificate, automatically selecting
// crypto/x509 or gmsm/smx509 based on the signer's key type.
func CreateCertificate(template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
	if IsSM2Key(priv) {
		return smx509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	}
	return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}

// CreateCertificateRequest creates a CSR, automatically selecting
// crypto/x509 or gmsm/smx509 based on the key type.
func CreateCertificateRequest(template *x509.CertificateRequest, priv any) ([]byte, error) {
	if IsSM2Key(priv) {
		return smx509.CreateCertificateRequest(rand.Reader, template, priv)
	}
	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

// ParseCertificate parses a DER-encoded certificate, attempting
// standard parsing first, then SM2-aware parsing as fallback.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		smCert, smErr := smx509.ParseCertificate(der)
		if smErr != nil {
			return nil, fmt.Errorf("x509: %w; smx509: %w", err, smErr)
		}
		return smCert.ToX509(), nil
	}
	return cert, nil
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("pollux/smx509: failed to decode certificate PEM")
	}
	return ParseCertificate(block.Bytes)
}

// ParseCertificateRequest parses a DER-encoded CSR, attempting
// standard parsing first, then SM2-aware parsing as fallback.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		smCSR, smErr := smx509.ParseCertificateRequest(der)
		if smErr != nil {
			return nil, fmt.Errorf("x509: %w; smx509: %w", err, smErr)
		}
		return smCSR.ToX509(), nil
	}
	return csr, nil
}

// SignatureAlgorithmForPrivateKey returns the appropriate signature algorithm
// for the given private key type.
func SignatureAlgorithmForPrivateKey(key any) x509.SignatureAlgorithm {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if bits >= 4096 {
			return x509.SHA512WithRSA
		}
		if bits >= 3072 {
			return x509.SHA384WithRSA
		}
		return x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		if k.Curve == sm2.P256() {
			return x509.UnknownSignatureAlgorithm
		}
		bits := k.Curve.Params().BitSize
		if bits >= 384 {
			return x509.ECDSAWithSHA384
		}
		return x509.ECDSAWithSHA256
	case *sm2.PrivateKey:
		return x509.UnknownSignatureAlgorithm
	case ed25519.PrivateKey:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// PublicKeyAlgorithmForPrivateKey returns the appropriate public key algorithm
// for the given private key type.
func PublicKeyAlgorithmForPrivateKey(key any) x509.PublicKeyAlgorithm {
	switch key.(type) {
	case *rsa.PrivateKey:
		return x509.RSA
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	case *sm2.PrivateKey:
		return x509.ECDSA
	case ed25519.PrivateKey:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// ExtractPublicKey extracts the public key from a private key.
func ExtractPublicKey(priv any) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *sm2.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// CheckCertificateRequestSignature verifies a CSR signature, handling SM2 automatically.
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		smCSR := &smx509.CertificateRequest{}
		*smCSR = smx509.CertificateRequest(*csr)
		return smCSR.CheckSignature()
	}
	return nil
}

// MarshalPKIXPublicKey serializes a public key to PKIX DER format.
// Supports SM2 public keys via gmsm/smx509.
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	return smx509.MarshalPKIXPublicKey(pub)
}

// MarshalECPrivateKey serializes an EC (including SM2) private key to DER format.
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return smx509.MarshalECPrivateKey(key)
}

// ParseECPrivateKey parses an EC (including SM2) private key from DER format.
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return smx509.ParseECPrivateKey(der)
}

// DecryptPEMPrivateKey decrypts an encrypted PEM private key using the given password.
// Returns the decrypted key in PEM format.
// Supports PKCS#8 encrypted keys (PBES2/PBKDF2 with AES-CBC/GCM, SM4-CBC/GCM, SM3 PRF)
// and traditional PEM encryption (Proc-Type/DEK-Info headers with DES-CBC, DES-EDE3-CBC, AES-CBC).
// Traditional PEM encryption is accepted only for reading legacy OpenSSL-compatible keys;
// new encrypted keys should use PKCS#8 PBES2 with an authenticated or modern block cipher mode.
func DecryptPEMPrivateKey(pemData []byte, password string) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("smx509: failed to decode PEM data")
	}

	if !isPEMEncrypted(block) {
		return pemData, nil
	}

	der, err := decryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, err
	}

	pemType := detectKeyType(der)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// DecryptPEMPrivateKeyDER decrypts an encrypted PEM private key and returns raw DER bytes.
func DecryptPEMPrivateKeyDER(pemData []byte, password string) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("smx509: failed to decode PEM data")
	}

	if !isPEMEncrypted(block) {
		return block.Bytes, nil
	}

	return decryptPEMBlock(block, []byte(password))
}

func decryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		der, err := decryptPKCS8(block.Bytes, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt PKCS#8 private key failed: %w", err)
		}
		return der, nil

	default:
		der, err := decryptLegacyPEM(block, password)
		if err != nil {
			return nil, fmt.Errorf("smx509: decrypt PEM block failed: %w", err)
		}
		return der, nil
	}
}

func isPEMEncrypted(block *pem.Block) bool {
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func detectKeyType(der []byte) string {
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return "RSA PRIVATE KEY"
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return "EC PRIVATE KEY"
	}
	return "PRIVATE KEY"
}

// --- PKCS#8 encrypted key decryption (PBES2) ---

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	oidHMACWithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 2}

	oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	oidSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes2Params struct {
	KDF pkix.AlgorithmIdentifier
	ES  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

type gcmParams struct {
	Nonce  []byte
	TagLen int `asn1:"optional"`
}

func decryptPKCS8(encryptedDER, password []byte) ([]byte, error) {
	var encInfo encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(encryptedDER, &encInfo); err != nil {
		return nil, fmt.Errorf("smx509: parse EncryptedPrivateKeyInfo: %w", err)
	}

	if !encInfo.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("smx509: unsupported encryption algorithm: %v (PBES2 only)", encInfo.EncryptionAlgorithm.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(encInfo.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("smx509: parse PBES2 params: %w", err)
	}

	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("smx509: unsupported KDF: %v", params.KDF.Algorithm)
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("smx509: parse PBKDF2 params: %w", err)
	}

	// Minimum iteration count for READING legacy keys: 10,000 (aligned with OpenSSL default).
	//
	// SECURITY WARNING: OWASP 2023 recommends >= 600,000 iterations for PBKDF2-HMAC-SHA256
	// and >= 600,000 for PBKDF2-HMAC-SM3 when GENERATING new keys. The 10,000 minimum here
	// is for reading existing keys only. Callers creating new encrypted keys MUST use
	// at least 600,000 iterations.
	//
	// See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	if kdfParams.IterationCount < 10000 {
		return nil, fmt.Errorf("PBKDF2 iterations %d below minimum 10000", kdfParams.IterationCount)
	}
	prf := newPRF(kdfParams.PRF.Algorithm)
	if prf == nil {
		// Fail-closed: PBKDF2 PRFs outside the allowlist (SHA-256/384/512, SM3)
		// are rejected rather than silently falling back to HMAC-SHA1. SHA1 is
		// cryptographically broken; accepting it would weaken offline brute-force
		// resistance of an attacker-supplied encrypted key. This mirrors the
		// strict strategy used by encKeySize() (returns 0 → reject) below.
		return nil, fmt.Errorf("smx509: unsupported PBKDF2 PRF: %v (allowed: HMAC-SHA256/384/512, HMAC-SM3)", kdfParams.PRF.Algorithm)
	}
	keyLen := encKeySize(params.ES.Algorithm)
	if keyLen == 0 {
		return nil, fmt.Errorf("smx509: unsupported encryption scheme: %v", params.ES.Algorithm)
	}
	derivedKey := pbkdf2.Key(password, kdfParams.Salt, kdfParams.IterationCount, keyLen, prf)
	defer memsecure.ZeroBytes(derivedKey)

	return decryptBlock(params.ES, derivedKey, encInfo.EncryptedData)
}

// newPRF returns the HMAC-PRF hash constructor for the given PBKDF2 PRF OID, or
// nil if the OID is not on the allowlist. Callers MUST treat nil as "reject"
// rather than falling back to a weaker default (see decryptPKCS8).
func newPRF(oid asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New
	case oid.Equal(oidHMACWithSHA384):
		return sha512.New384
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New
	case oid.Equal(oidHMACWithSM3):
		return gmsmSM3.New
	default:
		return nil
	}
}

func encKeySize(oid asn1.ObjectIdentifier) int {
	switch {
	case oid.Equal(oidAES128CBC), oid.Equal(oidAES128GCM),
		oid.Equal(oidSM4CBC), oid.Equal(oidSM4GCM):
		return 16
	case oid.Equal(oidAES192CBC), oid.Equal(oidAES192GCM):
		return 24
	case oid.Equal(oidAES256CBC), oid.Equal(oidAES256GCM):
		return 32
	default:
		return 0
	}
}

func decryptBlock(es pkix.AlgorithmIdentifier, key, ciphertext []byte) ([]byte, error) {
	keyLen := encKeySize(es.Algorithm)
	if keyLen == 0 {
		return nil, fmt.Errorf("smx509: unsupported encryption scheme: %v", es.Algorithm)
	}

	isSM4 := es.Algorithm.Equal(oidSM4CBC) || es.Algorithm.Equal(oidSM4GCM)

	var blockCipher cipher.Block
	var err error
	if isSM4 {
		blockCipher, err = polluxSM4.NewCipher(key)
	} else {
		blockCipher, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}

	switch {
	case es.Algorithm.Equal(oidAES128CBC) || es.Algorithm.Equal(oidAES192CBC) || es.Algorithm.Equal(oidAES256CBC),
		es.Algorithm.Equal(oidSM4CBC):
		var iv []byte
		if _, err := asn1.Unmarshal(es.Parameters.FullBytes, &iv); err != nil {
			return nil, fmt.Errorf("smx509: parse IV: %w", err)
		}
		if len(ciphertext)%blockCipher.BlockSize() != 0 {
			return nil, errors.New("ciphertext is not a multiple of the block size")
		}
		plaintext := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(blockCipher, iv).CryptBlocks(plaintext, ciphertext)
		return pkcs7Unpad(plaintext)

	case es.Algorithm.Equal(oidAES128GCM) || es.Algorithm.Equal(oidAES192GCM) || es.Algorithm.Equal(oidAES256GCM),
		es.Algorithm.Equal(oidSM4GCM):
		var gcmNonce []byte
		var rawParams gcmParams
		if _, err := asn1.Unmarshal(es.Parameters.FullBytes, &rawParams); err == nil && len(rawParams.Nonce) > 0 {
			gcmNonce = rawParams.Nonce
		} else if _, err := asn1.Unmarshal(es.Parameters.FullBytes, &gcmNonce); err != nil {
			return nil, fmt.Errorf("smx509: parse GCM nonce: %w", err)
		}
		aead, err := cipher.NewGCM(blockCipher)
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, gcmNonce, ciphertext, nil)

	default:
		return nil, fmt.Errorf("smx509: unsupported encryption scheme: %v", es.Algorithm)
	}
}

var errInvalidPadding = errors.New("smx509: invalid PKCS#7 padding")

// asn1IsSequence 检查 DER 数据是否以 ASN.1 SEQUENCE 标签开头。
// 用于在 CBC 解密后验证密码正确性（CBC 无认证，错误密码可能通过 PKCS7 unpad）。
// 使用常量时间比较以防止时序侧信道。
func asn1IsSequence(der []byte) bool {
	if len(der) == 0 {
		return false
	}
	return subtle.ConstantTimeByteEq(der[0], 0x30) == 1
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errInvalidPadding
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errInvalidPadding
	}
	// Constant-time validation: always iterate all padding bytes regardless of value.
	var valid int = 1
	for _, b := range data[len(data)-padLen:] {
		valid &= subtle.ConstantTimeByteEq(b, byte(padLen))
	}
	if valid == 0 {
		return nil, errInvalidPadding
	}
	return data[:len(data)-padLen], nil
}

// --- Legacy PEM encryption (Proc-Type/DEK-Info) ---

func decryptLegacyPEM(block *pem.Block, password []byte) ([]byte, error) {
	dekInfo := block.Headers["DEK-Info"]
	if dekInfo == "" {
		return nil, fmt.Errorf("smx509: missing DEK-Info header")
	}

	parts := strings.SplitN(dekInfo, ",", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("smx509: invalid DEK-Info format: %s", dekInfo)
	}

	cipherName := strings.TrimSpace(parts[0])
	iv, err := hex.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("smx509: parse IV failed: %w", err)
	}

	keyLen := legacyKeyLen(cipherName)
	if keyLen == 0 {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", cipherName)
	}
	// Salt 是 IV 的前 8 字节（与 OpenSSL/Go x509 一致）
	if len(iv) < 8 {
		return nil, fmt.Errorf("IV too short: need >= 8 bytes, got %d", len(iv))
	}
	key := evpBytesToKey(password, iv[:8], keyLen)

	blockCipher, err := legacyNewCipher(cipherName, key)
	if err != nil {
		return nil, err
	}

	if len(block.Bytes)%blockCipher.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(block.Bytes))
	cipher.NewCBCDecrypter(blockCipher, iv).CryptBlocks(plaintext, block.Bytes)
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, errors.New("smx509: decryption failed")
	}
	// CBC 没有 authenticated encryption，错误密码可能通过 PKCS7 unpad。
	// 通过 ASN.1 结构校验检测：私钥 DER 必须是合法的 SEQUENCE。
	// 返回与 pkcs7Unpad 相同的错误消息以防止 padding oracle 攻击。
	if !asn1IsSequence(unpadded) {
		return nil, errors.New("smx509: decryption failed")
	}
	return unpadded, nil
}

func legacyKeyLen(name string) int {
	switch name {
	case "DES-CBC":
		return 8
	case "DES-EDE3-CBC":
		return 24
	case "AES-128-CBC":
		return 16
	case "AES-192-CBC":
		return 24
	case "AES-256-CBC":
		return 32
	default:
		return 0
	}
}

// legacyNewCipher supports historical OpenSSL PEM ciphers only for decrypting
// existing Proc-Type/DEK-Info private keys. Do not use DES or 3DES for new data.
func legacyNewCipher(name string, key []byte) (cipher.Block, error) {
	switch name {
	case "DES-CBC":
		return des.NewCipher(key)
	case "DES-EDE3-CBC":
		return des.NewTripleDESCipher(key)
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", name)
	}
}

// evpBytesToKey implements OpenSSL's legacy EVP_BytesToKey key derivation.
//
// SECURITY WARNING: This function uses MD5 for key derivation, which is
// CRYPTOGRAPHICALLY BROKEN. It exists solely for reading legacy OpenSSL-encrypted
// PEM private keys (Proc-Type/DEK-Info headers). Do NOT use this function for
// any new key derivation. New encrypted keys must use PKCS#8 PBES2 with
// PBKDF2-HMAC-SHA256 or PBKDF2-HMAC-SM3 (see decryptPKCS8).
//
// Deprecated: Do not use in new code. This will never be removed for
// compatibility reasons, but new code should never call this directly.
func evpBytesToKey(password, salt []byte, keyLen int) []byte {
	var result, prev []byte
	for len(result) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		result = append(result, prev...)
	}
	return result[:keyLen]
}
