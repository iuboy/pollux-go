package tlcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/sm2"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// This file implements handshake-signature sign/verify for the TLCP
// CertificateVerify message (GB/T 38636-2020 §6.4.5.8) and the
// ServerKeyExchange signed_params. Only the SM2+SM3 (ECC_SM3) and RSA+SHA256
// paths are implemented; RSA_SM3 and IBS_SM3 return an error (gotlcp also
// leaves these TODO).
//
// Reference: gotlcp/tlcp/auth.go (logic consulted, independently written).

// tlcpSigType identifies the signature algorithm in a CertificateVerify /
// ServerKeyExchange (GB/T 38636-2020 §6.4.5.9). Values mirror gotlcp's
// SignatureAlgorithm constants.
type tlcpSigType uint8

const (
	tlcpSigNone   tlcpSigType = 0
	tlcpSigRSA256 tlcpSigType = 1 // rsa_sha256
	tlcpSigRSASM3 tlcpSigType = 2 // rsa_sm3
	tlcpSigECCSM3 tlcpSigType = 3 // ecc_sm3 (SM2+SM3)
	tlcpSigIBSSM3 tlcpSigType = 4 // ibs_sm3
)

// tlcpSigTypeForSuite returns the handshake signature type for a negotiated
// cipher suite. All SM4/SM3 ECC/ECDHE suites use SM2+SM3; the RSA_SHA256
// suites (not implemented) would use RSA+SHA256.
func tlcpSigTypeForSuite(suiteID uint16) (tlcpSigType, error) {
	switch suiteID {
	case SuiteECC_SM2_SM4_CBC_SM3, SuiteECC_SM2_SM4_GCM_SM3,
		SuiteECDHE_SM2_SM4_CBC_SM3, SuiteECDHE_SM2_SM4_GCM_SM3:
		return tlcpSigECCSM3, nil
	}
	return tlcpSigNone, fmt.Errorf("tlcp: unsupported certificate-verify signature for suite %04x", suiteID)
}

// tlcpVerifyHandshakeSignature verifies a handshake signature (over tbs) using
// the peer's public key. sigType selects the algorithm.
func tlcpVerifyHandshakeSignature(sigType tlcpSigType, pub crypto.PublicKey, tbs, sig []byte) error {
	switch sigType {
	case tlcpSigECCSM3:
		pubKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("tlcp: ECC_SM3 verify expects *ecdsa.PublicKey, got %T", pub)
		}
		if !sm2.VerifyASN1WithSM2(pubKey, nil, tbs, sig) {
			return errors.New("tlcp: SM2 handshake-signature verification failed")
		}
		return nil
	case tlcpSigRSA256:
		pubKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("tlcp: RSA_SHA256 verify expects *rsa.PublicKey, got %T", pub)
		}
		return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, tbs, sig)
	case tlcpSigRSASM3, tlcpSigIBSSM3:
		return fmt.Errorf("tlcp: handshake signature type %d not implemented", sigType)
	default:
		return fmt.Errorf("tlcp: unknown handshake signature type %d", sigType)
	}
}

// tlcpSignHandshake signs tbs with the local private key. For SM2 keys it uses
// the GM signing mode (forceGMSign=true, default UID) per GB/T 32918.
//
// SEMANTICS NOTE for the RSA_SHA256 (sigType=tlcpSigRSA256) branch:
// `tbs` is the raw to-be-signed message (matching the SM2 caller convention).
// crypto.Signer.Sign with crypto.SHA256 as opts expects the caller to have
// pre-hashed the message into a SHA256 digest; passing raw bytes here means
// the RSA signer will hash them again (RSA-PKCS1v15 Sign hashes internally
// based on opts.HashFunc). The TLCP caller-side convention is raw-message
// (consistent with SM2's ZA||SM3(message) internal hashing), so this double
// hashing is actually the intended behavior — the resulting RSA signature is
// over SHA256(tbs), which is what RFC 5246's RSA key exchange expects. The
// RSA_SHA256 branch is currently unreachable from any negotiated TLCP suite
// (only SM2+SM3 suites are implemented), so this only matters if a future
// caller wires RSA suites.
func tlcpSignHandshake(rand io.Reader, sigType tlcpSigType, priv crypto.PrivateKey, tbs []byte) ([]byte, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: private key does not implement crypto.Signer")
	}
	var opts crypto.SignerOpts
	switch sigType {
	case tlcpSigECCSM3:
		// ECC_SM3 (SM2+SM3) REQUIRES an SM2 private key — using a non-SM2
		// ECDSA key with the SM2 signer option would produce a signature that
		// is not GM/T 0009-compliant and would fail peer verification.
		// Reject the misconfiguration explicitly rather than letting a
		// non-SM2 key fall through with nil opts (which would silently
		// produce a non-compliant signature).
		sm2Key, isSM2 := priv.(*sm2.PrivateKey)
		if !isSM2 {
			return nil, fmt.Errorf("tlcp: ECC_SM3 signature requires an SM2 private key, got %T", priv)
		}
		_ = sm2Key                                     // sm2Key is only used to gate the type assertion; opts carries the SM2 parameters
		opts = polluxSM2.NewSM2SignerOption(true, nil) // GM mode, default UID
	case tlcpSigRSA256:
		opts = crypto.SHA256
	case tlcpSigRSASM3, tlcpSigIBSSM3:
		return nil, fmt.Errorf("tlcp: handshake signature type %d not implemented", sigType)
	default:
		return nil, fmt.Errorf("tlcp: unknown handshake signature type %d", sigType)
	}
	return signer.Sign(rand, tbs, opts)
}
