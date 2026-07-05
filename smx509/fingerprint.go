package smx509

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

// FingerprintSHA256 returns the lowercase hex-encoded SHA-256 fingerprint of
// the certificate's DER encoding (cert.Raw). This is the canonical
// colon-free fingerprint form used by PKI discovery APIs, OCSP/CRT sharding,
// and pinning workflows. Returns "" for a nil cert.
func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

// FingerprintHash returns the hex-encoded fingerprint using the given hash
// (must be available, e.g. crypto.SHA1 for legacy OCSP CertID-style hashing).
// Returns "" for a nil cert. Returns an error if the hash is not linked into
// the binary.
func FingerprintHash(cert *x509.Certificate, h crypto.Hash) (string, error) {
	if cert == nil {
		return "", nil
	}
	if !h.Available() {
		return "", errors.New("smx509: requested hash function is not available")
	}
	hash := h.New()
	hash.Write(cert.Raw)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

