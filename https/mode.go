package https

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
		if pub == nil || pub.Curve == nil {
			return ModeTLS
		}
		// Compare curve parameters rather than interface identity: gmsm and
		// stdlib may expose distinct *elliptic.CurveParams-backed instances for
		// the same curve, so == on the Curve interface is unreliable. Match by
		// the SM2 curve's named parameters instead.
		sm2Params := sm2.P256().Params()
		gotParams := pub.Curve.Params()
		if gotParams != nil && sm2Params != nil &&
			gotParams.P.Cmp(sm2Params.P) == 0 &&
			gotParams.N.Cmp(sm2Params.N) == 0 &&
			gotParams.B.Cmp(sm2Params.B) == 0 &&
			gotParams.Gx.Cmp(sm2Params.Gx) == 0 &&
			gotParams.Gy.Cmp(sm2Params.Gy) == 0 {
			return ModeTLCP
		}
	}
	return ModeTLS
}
