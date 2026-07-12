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
		return errors.New("tlcp: unknown handshake signature type")
	}
}

// tlcpSignHandshake signs tbs with the local private key. For SM2 keys it uses
// the GM signing mode (forceGMSign=true, default UID) per GB/T 32918.
func tlcpSignHandshake(rand io.Reader, sigType tlcpSigType, priv crypto.PrivateKey, tbs []byte) ([]byte, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: private key does not implement crypto.Signer")
	}
	var opts crypto.SignerOpts
	switch sigType {
	case tlcpSigECCSM3:
		if _, isSM2 := priv.(*sm2.PrivateKey); isSM2 {
			opts = polluxSM2.NewSM2SignerOption(true, nil) // GM mode, default UID
		}
		// Non-SM2 ECDSA keys fall through with nil opts (not expected in TLCP).
	case tlcpSigRSA256:
		opts = crypto.SHA256
	case tlcpSigRSASM3, tlcpSigIBSSM3:
		return nil, fmt.Errorf("tlcp: handshake signature type %d not implemented", sigType)
	default:
		return nil, fmt.Errorf("tlcp: unknown handshake signature type %d", sigType)
	}
	return signer.Sign(rand, tbs, opts)
}
