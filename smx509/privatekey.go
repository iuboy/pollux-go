package smx509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	gmsmSMX509 "github.com/emmansun/gmsm/smx509"
	"github.com/iuboy/pollux-go/sm2"
)

// errEncryptedPrivateKey is returned when the input PEM is encrypted. Callers
// must decrypt first with DecryptPEMPrivateKey, then re-parse the cleartext.
var errEncryptedPrivateKey = errors.New("smx509: PEM private key is encrypted; decrypt first with DecryptPEMPrivateKey")

// ParsePrivateKeyPEM parses a PEM-encoded private key, auto-detecting SM2
// (PKCS#8 with SM2 OID, or SEC1 "EC PRIVATE KEY" on the SM2 P256 curve) and
// standard algorithms (RSA/ECDSA/Ed25519 across PKCS#8, PKCS#1, EC SEC1).
//
// Returns *sm2.PrivateKey for SM2, or the standard crypto/x509 types
// (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey) for others.
// Encrypted PEMs are rejected with a clear error; decrypt first with
// DecryptPEMPrivateKey.
//
// This is the recommended single entry point for private-key parsing in
// mixed SM2 / standard environments. Callers should not inline their own
// pem.Decode + x509.Parse* fallback chains.
func ParsePrivateKeyPEM(pemData []byte) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("smx509: failed to decode private key PEM")
	}

	// Detect encrypted PEM up front so the caller gets a clear, uniform error
	// regardless of which downstream parser would have rejected it. PKCS#8
	// encrypted envelopes ("ENCRYPTED PRIVATE KEY") and legacy PEM headers
	// ("Proc-Type: 4,ENCRYPTED") both require DecryptPEMPrivateKey first.
	if isEncryptedPEMBlock(block) {
		return nil, errEncryptedPrivateKey
	}

	// SM2 first: pollux-go sm2 accepts only SM2 keys; non-SM2 returns errNotSM2Key.
	if sm2Key, err := sm2.ParsePrivateKeyFromPEM(pemData); err == nil {
		return sm2Key, nil
	}

	// Standard algorithms: PKCS#8 → PKCS#1 (RSA) → EC SEC1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("smx509: cannot parse private key PEM (not SM2/RSA/ECDSA/Ed25519)")
}

// ParsePKCS8PrivateKey parses a PKCS#8 private key DER, SM2-aware: unlike
// crypto/x509.ParsePKCS8PrivateKey (which rejects the SM2 OID), this delegates
// to gmsm/smx509 and returns *sm2.PrivateKey for SM2 keys. For standard
// algorithms it returns the same types as x509.ParsePKCS8PrivateKey.
//
// Use this whenever the input might be SM2. For PEM input, use ParsePrivateKeyPEM.
func ParsePKCS8PrivateKey(der []byte) (any, error) {
	return gmsmSMX509.ParsePKCS8PrivateKey(der)
}

// MarshalPrivateKey serializes a private key to DER. SM2 uses PKCS#8 (with
// SM2 OID, via sm2.MarshalPKCS8PrivateKey); standard ECDSA uses SEC1
// (x509.MarshalECPrivateKey); RSA and Ed25519 use PKCS#8.
//
// The encoding choice is paired with PEMTypeForPrivateKey and must stay
// consistent with it: callers building PEM should use both together.
func MarshalPrivateKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case *sm2.PrivateKey:
		return sm2.MarshalPKCS8PrivateKey(k)
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	case *rsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(k)
	case ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(k)
	default:
		return nil, fmt.Errorf("smx509: unsupported private key type: %T", key)
	}
}

// PEMTypeForPrivateKey returns the PEM block type for a private key. SM2, RSA
// and Ed25519 return "PRIVATE KEY" (PKCS#8); standard ECDSA returns
// "EC PRIVATE KEY" (SEC1). Paired with MarshalPrivateKey.
func PEMTypeForPrivateKey(key any) string {
	switch key.(type) {
	case *sm2.PrivateKey:
		return "PRIVATE KEY"
	case *ecdsa.PrivateKey:
		return "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		return "PRIVATE KEY"
	case ed25519.PrivateKey:
		return "PRIVATE KEY"
	default:
		return "PRIVATE KEY"
	}
}

// isEncryptedPEMBlock reports whether the PEM block carries an encrypted
// private key. It detects both PKCS#8 encrypted envelopes (RFC 7468
// "ENCRYPTED PRIVATE KEY" type) and legacy PKCS#1/SEC1 PEM headers
// ("Proc-Type: 4,ENCRYPTED" + DEK-Info). Mirrors the detection in
// sm2.ParsePrivateKeyFromPEM so all paths surface a uniform error.
func isEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return true
	}
	return false
}
