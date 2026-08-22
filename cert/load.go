package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	polluxSm2 "github.com/iuboy/pollux-go/sm2"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// LoadKeyPairPEM loads a TLS certificate from PEM-encoded cert and key.
// Supports SM2 keys. The cert PEM may contain a full chain (leaf + intermediate
// CA certificates); all CERTIFICATE blocks are collected so the complete chain
// is sent during the TLS/TLCP handshake.
//
// Trailing content after/between blocks is tolerated as follows (matching
// stdlib tls.X509KeyPair's lenient behavior): non-CERTIFICATE PEM blocks
// (comments, PRIVATE KEY, ...) and non-PEM garbage are ignored. A
// CERTIFICATE-typed block that fails to decode (truncated END line, corrupt
// base64) is NOT ignored — it returns an error, because silently dropping it
// would hand TLS a chain missing a certificate and fail open at verification
// time.
//
// After parsing, the private key is verified to match the leaf certificate's
// public key (chain[0]). A mismatch — e.g. the user passed cert A's PEM with
// key B — surfaces here as a clear error rather than as an opaque TLS handshake
// failure ("tls: private key does not match public key") minutes later.
func LoadKeyPairPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	var chain [][]byte
	anyPEMBlock := false
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		anyPEMBlock = true
		if block.Type != pemTypeCertificate {
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		// Distinguish "no PEM block at all" (ErrInvalidPEM) from "PEM
		// decoded but contained no CERTIFICATE-typed block". A caller that
		// passed a PRIVATE KEY PEM by mistake gets a hint at the cause
		// instead of a generic decode-failure error.
		if anyPEMBlock {
			return tls.Certificate{}, fmt.Errorf("cert: PEM input contains no CERTIFICATE-typed block (got non-CERTIFICATE PEM blocks only)")
		}
		return tls.Certificate{}, ErrInvalidPEM
	}
	// pem.Decode returns nil when the remainder holds no complete, well-formed
	// block, so at this point rest still contains any CERTIFICATE-typed block
	// it could not decode (truncated END line / corrupt base64 — verified
	// against encoding/pem behavior). Surface it instead of silently skipping
	// (same fail-closed style as parsePEMCertificates' skipped-count handling
	// in the tlcp package). Non-certificate content in rest stays ignored.
	if bytes.Contains(rest, []byte("-----BEGIN "+pemTypeCertificate+"-----")) {
		return tls.Certificate{}, fmt.Errorf("cert: malformed CERTIFICATE PEM block remains after chain (truncated END line or corrupt base64)")
	}

	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: parse private key: %w", err)
	}

	// Verify the private key matches the leaf certificate's public key.
	// A mismatch is almost always a configuration mistake (wrong key file);
	// failing here gives a precise error instead of deferring to the TLS
	// handshake's generic "private key does not match public key" message.
	leaf, parseErr := polluxSmx509.ParseCertificate(chain[0])
	if parseErr != nil {
		return tls.Certificate{}, fmt.Errorf("cert: parse leaf certificate for key match check: %w", parseErr)
	}
	if err := validatePrivateKeyMatchesLeaf(key, leaf); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
	}, nil
}

// validatePrivateKeyMatchesLeaf verifies that the parsed private key's public
// counterpart matches the leaf certificate's public key. Currently only SM2
// (ECDSA-on-P256) keys are checked because LoadKeyPairPEM only parses SM2
// private keys via polluxSm2.ParsePrivateKeyFromPEM; if/when RSA/Ed25519 are
// added this switch must grow correspondingly.
func validatePrivateKeyMatchesLeaf(key any, leaf *x509.Certificate) error {
	sm2Key, ok := key.(*polluxSm2.PrivateKey)
	if !ok {
		// Non-SM2 key — LoadKeyPairPEM only returns SM2 keys today, so reaching
		// here means a future code path slipped in without updating this check.
		return nil
	}
	certPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("cert: leaf certificate public key is %T, not ECDSA (SM2)", leaf.PublicKey)
	}
	// sm2.PublicKey 是 ecdsa.PublicKey 的类型别名（pollux sm2 包约定），
	// 故 &sm2Key.PublicKey 即 *ecdsa.PublicKey，可直接用 Equal：它同时
	// 比较 X/Y 坐标与曲线，消除此前仅比坐标时跨曲线同坐标点的误匹配。
	keyPub := &sm2Key.PublicKey
	if !certPub.Equal(keyPub) {
		return fmt.Errorf("cert: private key does not match leaf certificate's public key")
	}
	return nil
}

// LoadKeyPairFiles loads a TLS certificate from cert and key files.
func LoadKeyPairFiles(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: read cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: read key file: %w", err)
	}
	return LoadKeyPairPEM(certPEM, keyPEM)
}

// DualCertificate holds a TLCP sign/encrypt certificate pair.
type DualCertificate struct {
	Sign tls.Certificate
	Enc  tls.Certificate
}

// LoadDualCertificatePEM loads a TLCP dual certificate pair from PEM bytes.
func LoadDualCertificatePEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) (*DualCertificate, error) {
	sign, err := LoadKeyPairPEM(signCertPEM, signKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: load sign cert: %w", err)
	}
	enc, err := LoadKeyPairPEM(encCertPEM, encKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: load enc cert: %w", err)
	}
	return &DualCertificate{Sign: sign, Enc: enc}, nil
}

// LoadDualCertificateFiles loads a TLCP dual certificate pair from files.
// Error wrapping matches LoadDualCertificatePEM so a caller can tell from the
// error message alone whether the sign or enc pair failed (without it, a
// misconfigured enc key file surfaces as an opaque 'cert: parse private key'
// or 'cert: private key does not match leaf certificate's public key' with no
// indication of which side of the pair it came from).
func LoadDualCertificateFiles(signCertFile, signKeyFile, encCertFile, encKeyFile string) (*DualCertificate, error) {
	sign, err := LoadKeyPairFiles(signCertFile, signKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cert: load sign cert: %w", err)
	}
	enc, err := LoadKeyPairFiles(encCertFile, encKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cert: load enc cert: %w", err)
	}
	return &DualCertificate{Sign: sign, Enc: enc}, nil
}

// ParseCertificateRequest parses a DER-encoded certificate signing request.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	return polluxSmx509.ParseCertificateRequest(der)
}
