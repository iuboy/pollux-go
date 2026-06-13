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
//  2. Hashes the content with SM3.
//  3. Signs the digest with SM2 in ASN.1 format.
func SignCertificateVerify(privateKey *sm2.PrivateKey, context string, transcript []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("tls13gm: privateKey is nil")
	}

	message := BuildCertificateVerifyInput(context, transcript)
	digest := sm3.Sum(message)

	return sm2.SignASN1(rand.Reader, privateKey, digest[:], nil)
}

// VerifyCertificateVerify verifies an SM2-SM3 CertificateVerify signature.
//
// It reconstructs the signed content from the context and transcript, then
// verifies the signature against the SM3 digest of that content.
func VerifyCertificateVerify(publicKey *ecdsa.PublicKey, context string, transcript, signature []byte) bool {
	if publicKey == nil {
		return false
	}

	message := BuildCertificateVerifyInput(context, transcript)
	digest := sm3.Sum(message)

	return sm2.VerifyASN1(publicKey, digest[:], signature)
}

// SignSM2SM3 signs a raw message digest using SM2 with SM3.
// It hashes the message with SM3 and signs the digest using SM2 in ASN.1 format.
func SignSM2SM3(privateKey *sm2.PrivateKey, message []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("tls13gm: privateKey is nil")
	}
	digest := sm3.Sum(message)
	return sm2.SignASN1(rand.Reader, privateKey, digest[:], nil)
}

// VerifySM2SM3 verifies a raw SM2-SM3 signature.
// It hashes the message with SM3 and verifies the signature against the digest.
func VerifySM2SM3(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	if publicKey == nil {
		return false
	}
	digest := sm3.Sum(message)
	return sm2.VerifyASN1(publicKey, digest[:], signature)
}

// compile-time interface checks.
var (
	_ crypto.Signer = (*sm2.PrivateKey)(nil)
)
