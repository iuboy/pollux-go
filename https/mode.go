package https

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"

	"github.com/emmansun/gmsm/sm2"

	"github.com/iuboy/pollux-go/smx509"
)

// Mode determines the cryptographic protocol for connections.
type Mode int

const (
	// ModeUnset is the zero value of Mode and means "not configured" — the
	// builder falls back to auto-detection via DetectMode. It is NOT a usable
	// protocol mode; the named modes start at 1 so the zero value cannot be
	// confused with an explicit ModeTLS selection (the previous iota-from-0
	// design made `opts.Mode = ModeTLS` indistinguishable from "left unset",
	// silently overriding an explicit TLS choice with detected TLCP).
	ModeUnset Mode = iota

	// ModeTLS uses standard crypto/tls.
	ModeTLS

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
	case ModeUnset:
		return "Unset"
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

// isSM2Curve reports whether curve is the SM2 curve.
//
// Curve parameters are compared item by item rather than by interface
// identity: gmsm and stdlib may expose distinct *elliptic.CurveParams-backed
// instances for the same curve, so == on the Curve interface is unreliable.
// Match by the SM2 curve's named parameters instead.
func isSM2Curve(curve elliptic.Curve) bool {
	if curve == nil {
		return false
	}
	sm2Params := sm2.P256().Params()
	gotParams := curve.Params()
	return gotParams != nil && sm2Params != nil &&
		gotParams.P.Cmp(sm2Params.P) == 0 &&
		gotParams.N.Cmp(sm2Params.N) == 0 &&
		gotParams.B.Cmp(sm2Params.B) == 0 &&
		gotParams.Gx.Cmp(sm2Params.Gx) == 0 &&
		gotParams.Gy.Cmp(sm2Params.Gy) == 0
}

// DetectMode inspects the given certificates and returns the appropriate mode.
// Returns ModeTLCP if the sign certificate carries an SM2 key (private or
// public), ModeTLS otherwise.
//
// Detection prefers the private key when one is present: a *sm2.PrivateKey,
// or an *ecdsa.PrivateKey on the SM2 curve, selects ModeTLCP; any other
// concrete private key is a clear non-SM2 signal and keeps ModeTLS.
//
// When the private key is unjudgeable — absent (the client-side norm of
// configuring only the certificate PEM), a typed-nil *ecdsa.PrivateKey, or a
// custom/unknown key type — detection falls back to the leaf certificate's
// public key: an ECDSA public key on the SM2 curve (gmsm represents SM2
// public keys that way) selects ModeTLCP.
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
			break // unjudgeable — fall through to the leaf-cert public key
		}
		if isSM2Curve(pub.Curve) {
			return ModeTLCP
		}
		return ModeTLS
	case *rsa.PrivateKey, ed25519.PrivateKey:
		// Concrete non-SM2 key types are a clear private-key signal: keep the
		// historical ModeTLS determination. The cert fallback below applies
		// only when the key is absent or unjudgeable.
		return ModeTLS
	}

	// No usable private-key signal: judge by the leaf certificate's public
	// key. Prefer a caller-populated Leaf; otherwise parse the first DER
	// block. Parsing goes through pollux smx509 because crypto/x509 cannot
	// parse certificates on the SM2 curve. Unparseable input keeps ModeTLS.
	leaf := signCert.Leaf
	if leaf == nil && len(signCert.Certificate) > 0 {
		if parsed, err := smx509.ParseCertificate(signCert.Certificate[0]); err == nil {
			leaf = parsed
		}
	}
	if leaf == nil {
		return ModeTLS
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
		// gmsm has no separate SM2 public-key type: parsed SM2 certificates
		// expose their public key as *ecdsa.PublicKey on the SM2 curve, so the
		// curve-parameter match below (isSM2Curve) is what detects them.
		// Typed-nil guard, same reasoning as the private-key arm above.
		if pub != nil && isSM2Curve(pub.Curve) {
			return ModeTLCP
		}
	}
	return ModeTLS
}
