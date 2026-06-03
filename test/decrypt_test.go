package test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	polluxSM2 "github.com/ycq/pollux/sm2"
	polluxSMX509 "github.com/ycq/pollux/smx509"
)

func TestDecryptAES256CBC(t *testing.T) {
	encPEM := readCert(t, "sm2_sign_key_aes.pem")

	result, err := polluxSMX509.DecryptPEMPrivateKey(encPEM, certPassword)
	if err != nil {
		t.Fatalf("DecryptPEMPrivateKey AES: %v", err)
	}

	key, err := polluxSM2.ParsePrivateKeyFromPEM(result)
	if err != nil {
		t.Fatalf("parse decrypted key: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestDecryptSM4CBC(t *testing.T) {
	encPEM := readCert(t, "sm2_sign_key_sm4.pem")

	result, err := polluxSMX509.DecryptPEMPrivateKey(encPEM, certPassword)
	if err != nil {
		t.Fatalf("DecryptPEMPrivateKey SM4: %v", err)
	}

	key, err := polluxSM2.ParsePrivateKeyFromPEM(result)
	if err != nil {
		t.Fatalf("parse decrypted key: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestDecryptRSALegacyPEM(t *testing.T) {
	encPEM := readCert(t, "rsa_key_enc.pem")

	der, err := polluxSMX509.DecryptPEMPrivateKeyDER(encPEM, certPassword)
	if err != nil {
		t.Fatalf("DecryptPEMPrivateKeyDER RSA: %v", err)
	}

	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatalf("parse RSA key: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	encPEM := readCert(t, "sm2_sign_key_aes.pem")

	_, err := polluxSMX509.DecryptPEMPrivateKey(encPEM, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestDecryptUnencryptedKey(t *testing.T) {
	keyPEM := readCert(t, "sm2_sign_key.pem")

	result, err := polluxSMX509.DecryptPEMPrivateKey(keyPEM, "")
	if err != nil {
		t.Fatalf("unencrypted key: %v", err)
	}
	if string(result) != string(keyPEM) {
		t.Error("unencrypted key should be returned as-is")
	}
}

func TestDecryptAndParseSM2EncKey(t *testing.T) {
	encPEM := readCert(t, "sm2_enc_key_sm4.pem")

	result, err := polluxSMX509.DecryptPEMPrivateKey(encPEM, certPassword)
	if err != nil {
		t.Fatalf("DecryptPEMPrivateKey SM4 enc: %v", err)
	}

	key, err := polluxSM2.ParsePrivateKeyFromPEM(result)
	if err != nil {
		t.Fatalf("parse decrypted enc key: %v", err)
	}
	if key == nil {
		t.Fatal("enc key is nil")
	}
}

// --- SMX509 encrypted key decryption security regression tests ---

// buildMalformedPKCS8PEM constructs a PKCS#8 ENCRYPTED PRIVATE KEY PEM block
// with the given PBKDF2 parameters, encryption scheme OID, IV/nonce, and ciphertext.
// It builds DER by assembling raw ASN.1 bytes using a helper that wraps content
// in SEQUENCE/OCTET STRING tags.
func buildMalformedPKCS8PEM(
	t *testing.T,
	kdfSalt []byte,
	iterations int,
	prfOID asn1.ObjectIdentifier,
	esOID asn1.ObjectIdentifier,
	esIV []byte,
	ciphertext []byte,
) []byte {
	t.Helper()

	// Step 1: Build PBKDF2 params SEQUENCE { salt, iterationCount, prf }
	prfAIDer, err := asn1.Marshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}{
		Algorithm:  prfOID,
		Parameters: asn1.NullRawValue,
	})
	if err != nil {
		t.Fatalf("marshal PRF AI: %v", err)
	}

	saltDer, err := asn1.Marshal(kdfSalt)
	if err != nil {
		t.Fatalf("marshal salt: %v", err)
	}
	iterDer, err := asn1.Marshal(iterations)
	if err != nil {
		t.Fatalf("marshal iterations: %v", err)
	}

	// pbkdf2Params = SEQUENCE { salt, iterations, prf }
	pbkdf2ParamsDer := derAppend([]byte{0x30}, saltDer, iterDer, prfAIDer)

	// Step 2: KDF AlgorithmIdentifier = SEQUENCE { oidPBKDF2, pbkdf2Params }
	pbkdf2OidDer, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12})
	if err != nil {
		t.Fatalf("marshal PBKDF2 OID: %v", err)
	}
	kdfAIDer := derAppend([]byte{0x30}, pbkdf2OidDer, pbkdf2ParamsDer)

	// Step 3: ES AlgorithmIdentifier = SEQUENCE { esOID, OCTET STRING iv }
	esOidDer, err := asn1.Marshal(esOID)
	if err != nil {
		t.Fatalf("marshal ES OID: %v", err)
	}
	ivDer, err := asn1.Marshal(esIV)
	if err != nil {
		t.Fatalf("marshal IV: %v", err)
	}
	esAIDer := derAppend([]byte{0x30}, esOidDer, ivDer)

	// Step 4: PBES2 params = SEQUENCE { kdfAI, esAI }
	pbes2ParamsDer := derAppend([]byte{0x30}, kdfAIDer, esAIDer)

	// Step 5: Outer AlgorithmIdentifier = SEQUENCE { oidPBES2, pbes2Params }
	pbes2OidDer, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13})
	if err != nil {
		t.Fatalf("marshal PBES2 OID: %v", err)
	}
	outerAIDer := derAppend([]byte{0x30}, pbes2OidDer, pbes2ParamsDer)

	// Step 6: EncryptedPrivateKeyInfo = SEQUENCE { outerAI, ciphertext }
	ctDer, err := asn1.Marshal(ciphertext)
	if err != nil {
		t.Fatalf("marshal ciphertext: %v", err)
	}
	encInfoDer := derAppend([]byte{0x30}, outerAIDer, ctDer)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encInfoDer,
	})
}

// derAppend constructs a DER TLV with the given tag byte and content parts.
// tag should be a single byte like 0x30 (SEQUENCE).
func derAppend(tag []byte, parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	length := len(content)
	var lengthBytes []byte
	if length < 128 {
		lengthBytes = []byte{byte(length)}
	} else if length < 256 {
		lengthBytes = []byte{0x81, byte(length)}
	} else {
		lengthBytes = []byte{0x82, byte(length >> 8), byte(length)}
	}
	var result []byte
	result = append(result, tag...)
	result = append(result, lengthBytes...)
	result = append(result, content...)
	return result
}

// TestBlackBox_SMX509_X1_CBCCiphertextMisaligned verifies that a PKCS#8 encrypted key
// with ciphertext that is NOT a multiple of the block size returns an error (not panic).
func TestBlackBox_SMX509_X1_CBCCiphertextMisaligned(t *testing.T) {
	// AES-256-CBC OID
	aes256CBCOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	// HMAC-SHA256 PRF OID
	hmacSHA256OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	iv := make([]byte, 16) // valid 16-byte IV

	// 13 bytes of ciphertext -- not a multiple of AES block size (16)
	misalignedCiphertext := make([]byte, 13)

	pemData := buildMalformedPKCS8PEM(t,
		[]byte("0123456789abcdef"), // 16-byte salt
		2048,                       // valid iteration count
		hmacSHA256OID,
		aes256CBCOID,
		iv,
		misalignedCiphertext,
	)

	_, err := polluxSMX509.DecryptPEMPrivateKeyDER(pemData, "test-password")
	if err == nil {
		t.Fatal("expected error for misaligned CBC ciphertext, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestBlackBox_SMX509_X2_LegacyPEMShortIV verifies that a legacy PEM block
// with a very short IV (only 4 hex chars = 2 bytes) returns an error about IV being too short.
func TestBlackBox_SMX509_X2_LegacyPEMShortIV(t *testing.T) {
	block := &pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC,AABB", // only 4 hex chars = 2 bytes IV
		},
		Bytes: make([]byte, 32), // valid-looking ciphertext
	}
	pemData := pem.EncodeToMemory(block)

	_, err := polluxSMX509.DecryptPEMPrivateKeyDER(pemData, "test-password")
	if err == nil {
		t.Fatal("expected error for short IV, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestBlackBox_SMX509_X3_PBKDF2LowIterations verifies that a PKCS#8 encrypted key
// with PBKDF2 iterations below the minimum (2048) returns an error.
func TestBlackBox_SMX509_X3_PBKDF2LowIterations(t *testing.T) {
	// Use SM4-CBC OID for variety
	sm4CbcOID := asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	// HMAC-SM3 PRF OID
	hmacSM3OID := asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 2}

	iv := make([]byte, 16)
	ciphertext := make([]byte, 32) // valid multiple of block size

	pemData := buildMalformedPKCS8PEM(t,
		[]byte("0123456789abcdef"),
		100, // below minimum 2048
		hmacSM3OID,
		sm4CbcOID,
		iv,
		ciphertext,
	)

	_, err := polluxSMX509.DecryptPEMPrivateKeyDER(pemData, "test-password")
	if err == nil {
		t.Fatal("expected error for low PBKDF2 iterations, got nil")
	}
	t.Logf("got expected error: %v", err)
}
