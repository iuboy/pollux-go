package http

import (
	"crypto/ecdsa"
	"crypto/tls"

	"github.com/emmansun/gmsm/sm2"
)

// Mode determines the cryptographic protocol for connections.
type Mode int

const (
	// ModeTLS uses standard crypto/tls.
	ModeTLS Mode = iota

	// ModeTLCP uses the national TLCP protocol (GB/T 38636-2020)
	// with dual certificate pairs (sign + encrypt).
	ModeTLCP

	// ModeHybrid accepts both TLS and TLCP on the same port.
	// Protocol is detected by peeking the record header version field.
	ModeHybrid
)

// String returns a human-readable name for the mode.
func (m Mode) String() string {
	switch m {
	case ModeTLS:
		return "TLS"
	case ModeTLCP:
		return "TLCP"
	case ModeHybrid:
		return "Hybrid"
	default:
		return "Unknown"
	}
}

// DetectMode inspects the given certificates and returns the appropriate mode.
// Returns ModeTLCP if the sign certificate has an SM2 public key,
// ModeTLS otherwise.
func DetectMode(signCert *tls.Certificate) Mode {
	if signCert == nil {
		return ModeTLS
	}

	switch pub := signCert.PrivateKey.(type) {
	case *sm2.PrivateKey:
		return ModeTLCP
	case *ecdsa.PrivateKey:
		// Guard against typed nil (e.g. var k *ecdsa.PrivateKey; cert.PrivateKey = k)
		// which would panic on pub.Curve access.
		if pub != nil && pub.Curve == sm2.P256() {
			return ModeTLCP
		}
	}
	return ModeTLS
}
