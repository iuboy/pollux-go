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
// and pinning workflows.
//
// Returns "" for a nil cert OR a cert with empty Raw (e.g. a freshly
// constructed *x509.Certificate{} that has never been parsed). A zero Raw
// would otherwise hash empty bytes and return a deterministic-but-meaningless
// value, masking the misconfiguration.
func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

// FingerprintHash returns the hex-encoded fingerprint using the given hash
// (must be available, e.g. crypto.SHA1 for legacy OCSP CertID-style hashing).
//
// Returns ("", nil) for a nil cert OR a cert with empty Raw. Returns an error
// if the hash is not linked into the binary.
//
// Note: hash.Write's return values are intentionally ignored — the standard
// library's hash.Hash contract documents that Write never returns a non-nil
// error (hashes never fail to absorb input). This matches the convention in
// crypto/x509's own fingerprint helpers. The (n, err) tuple is part of the
// io.Writer signature hash.Hash embeds for stream-composability, not an
// indicator of per-Write failure.
func FingerprintHash(cert *x509.Certificate, h crypto.Hash) (string, error) {
	if cert == nil {
		return "", nil
	}
	if len(cert.Raw) == 0 {
		return "", nil
	}
	if !h.Available() {
		return "", errors.New("smx509: requested hash function is not available")
	}
	hash := h.New()
	hash.Write(cert.Raw) // #nosec G104 -- hash.Hash.Write never errors per stdlib contract
	return hex.EncodeToString(hash.Sum(nil)), nil
}
