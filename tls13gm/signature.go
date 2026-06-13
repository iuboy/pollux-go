package tls13gm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/sm3"
)

// TLS 1.3 CertificateVerify context strings (RFC 8446 Section 4.4.3).
const (
	ServerCertificateVerifyContext = "TLS 1.3, server CertificateVerify"
	ClientCertificateVerifyContext = "TLS 1.3, client CertificateVerify"
)

// SM2 identifier constants per RFC 8998 §3.2.1.
//
// The SM2 signature algorithm uses an identifier (userID) that is incorporated
// into the ZA computation: ZA = SM3(userID || a || b || xG || yG || xA || yA).
// RFC 8998 mandates specific userID values for TLS 1.3 usage.
const (
	// SM2IDTLS13KeyExchange is the SM2 identifier for TLS 1.3 key exchange
	// (CertificateVerify signing and all non-certificate-verification uses).
	SM2IDTLS13KeyExchange = "TLSv1.3+GM+Cipher+Suite"

	// SM2IDCertificateVerify is the SM2 identifier for verifying a peer's SM2
	// certificate in the Certificate message, per GM/T 0009-2012.
	SM2IDCertificateVerify = "1234567812345678"
)

// BuildCertificateVerifyInput constructs the input for the CertificateVerify
// signature per RFC 8446 Section 4.4.3:
//
//	0x20 repeated 64 times || context string || 0x00 || SM3(transcript)
//
// The transcript parameter is the raw handshake transcript bytes; this function
// hashes it with SM3 before concatenation.
func BuildCertificateVerifyInput(context string, transcript []byte) []byte {
	transcriptHash := sm3.Sum(transcript)

	input := make([]byte, 0, 64+len(context)+1+sm3.Size)
	for range 64 {
		input = append(input, 0x20)
	}
	input = append(input, context...)
	input = append(input, 0x00)
	input = append(input, transcriptHash[:]...)
	return input
}

// SignCertificateVerify signs the CertificateVerify message using SM2-SM3.
//
// The caller provides the raw handshake transcript. This function:
//  1. Constructs the signed content per RFC 8446 §4.4.3
//     (64 × 0x20 + context + 0x00 + SM3(transcript)).
//  2. Signs with SM2 using the identifier "TLSv1.3+GM+Cipher+Suite"
//     as required by RFC 8998 §3.2.1 (ZA computation is performed internally).
func SignCertificateVerify(privateKey *sm2.PrivateKey, context string, transcript []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("tls13gm: privateKey is nil")
	}

	message := BuildCertificateVerifyInput(context, transcript)
	opts := sm2.NewSM2SignerOption(true, []byte(SM2IDTLS13KeyExchange))
	return sm2.SignASN1(rand.Reader, privateKey, message, opts)
}

// VerifyCertificateVerify verifies an SM2-SM3 CertificateVerify signature.
//
// It reconstructs the signed content from the context and transcript, then
// verifies the signature using the SM2 identifier "TLSv1.3+GM+Cipher+Suite"
// as required by RFC 8998 §3.2.1.
func VerifyCertificateVerify(publicKey *ecdsa.PublicKey, context string, transcript, signature []byte) bool {
	if publicKey == nil {
		return false
	}

	message := BuildCertificateVerifyInput(context, transcript)
	return sm2.VerifyWithSM2(publicKey, []byte(SM2IDTLS13KeyExchange), message, signature)
}

// SignSM2SM3 signs a raw message using SM2 with SM3.
// It uses the SM2 identifier "TLSv1.3+GM+Cipher+Suite" per RFC 8998 §3.2.1.
func SignSM2SM3(privateKey *sm2.PrivateKey, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("tls13gm: privateKey is nil")
	}
	opts := sm2.NewSM2SignerOption(true, []byte(SM2IDTLS13KeyExchange))
	return sm2.SignASN1(rand.Reader, privateKey, message, opts)
}

// VerifySM2SM3 verifies a raw SM2-SM3 signature.
// It uses the SM2 identifier "TLSv1.3+GM+Cipher+Suite" per RFC 8998 §3.2.1.
func VerifySM2SM3(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	if publicKey == nil {
		return false
	}
	return sm2.VerifyWithSM2(publicKey, []byte(SM2IDTLS13KeyExchange), message, signature)
}

// compile-time interface checks.
var (
	_ crypto.Signer = (*sm2.PrivateKey)(nil)
)
