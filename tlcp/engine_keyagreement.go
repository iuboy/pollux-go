//go:build tlcp_native

package tlcp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/emmansun/gmsm/sm2"
	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

// This file implements the TLCP ECC key exchange (GB/T 38636-2020 §6.4.5.4/
// §6.4.5.9): the client encrypts a 48-byte pre-master secret with the server's
// encryption certificate SM2 public key; the server decrypts it with the
// encryption certificate private key. This is the "public-key encryption of
// PMS" model (like RSA key exchange, but using SM2), NOT ECDH.
//
// The ServerKeyExchange for ECC carries a signature over (client_random +
// server_random + encryption-cert-DER), signed by the signing certificate.
//
// Reference: gotlcp/tlcp/key_agreement.go eccKeyAgreement (logic consulted,
// independently written). ECDHE (sm2ECDHEKeyAgreement) is out of scope.

const tlcpPreMasterSecretLength = 48

// tlcpECCKeyExchange implements the ECC key-agreement role for one side of the
// handshake. It holds no persistent state between the two client-side methods
// (processServerKeyExchange / generateClientKeyExchange) beyond the random
// source, which is supplied by the handshake state.
type tlcpECCKeyExchange struct{}

// --- Client side ---

// tlcpECCProcessServerKeyExchange verifies the server's signed_params: the
// signature over (client_random || server_random || enc-cert-DER), made by the
// server's signing certificate.
//
// signCert/encCert are the server's two certificates (peerCertificates[0]/[1]).
func tlcpECCProcessServerKeyExchange(sigType tlcpSigType, signCertPub crypto.PublicKey, clientRandom, serverRandom, encCertDER, skeKey []byte) error {
	if len(skeKey) < 2 {
		return errors.New("tlcp: ServerKeyExchange too short")
	}
	sigLen := int(binary.BigEndian.Uint16(skeKey[:2]))
	if sigLen+2 != len(skeKey) {
		return errors.New("tlcp: ServerKeyExchange signature length mismatch")
	}
	sig := skeKey[2:]
	tbs := tlcpECCSignedParams(clientRandom, serverRandom, encCertDER)
	return tlcpVerifyHandshakeSignature(sigType, signCertPub, tbs, sig)
}

// tlcpECCGenerateClientKeyExchange encrypts a fresh 48-byte pre-master secret
// with the server's encryption certificate public key and returns both the PMS
// (for local key derivation) and the ClientKeyExchange ciphertext payload
// (uint16-length-prefixed SM2-ASN1 ciphertext).
func tlcpECCGenerateClientKeyExchange(version uint16, r io.Reader, encCertPub *ecdsa.PublicKey) (preMasterSecret, ckePayload []byte, err error) {
	preMasterSecret = make([]byte, tlcpPreMasterSecretLength)
	// First two bytes of the PMS carry the client-offered version (RFC 5246 §8.1.1
	// / GB/T 38636-2020 §6.5.1), matching the ClientHello.version field.
	preMasterSecret[0] = byte(version >> 8)
	preMasterSecret[1] = byte(version)
	if _, err = io.ReadFull(r, preMasterSecret[2:]); err != nil {
		return nil, nil, err
	}
	encrypted, err := polluxSM2.EncryptASN1(r, encCertPub, preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckePayload = make([]byte, len(encrypted)+2)
	binary.BigEndian.PutUint16(ckePayload[:2], uint16(len(encrypted)))
	copy(ckePayload[2:], encrypted)
	return preMasterSecret, ckePayload, nil
}

// --- Server side (used in Phase 4, defined here for cohesion) ---

// tlcpECCGenerateServerKeyExchange signs (client_random || server_random ||
// enc-cert-DER) with the server's signing certificate private key and returns
// the ServerKeyExchange payload (uint16-length-prefixed signature).
func tlcpECCGenerateServerKeyExchange(sigType tlcpSigType, signer crypto.Signer, clientRandom, serverRandom, encCertDER []byte) ([]byte, error) {
	tbs := tlcpECCSignedParams(clientRandom, serverRandom, encCertDER)
	sig, err := tlcpSignHandshake(rand.Reader, sigType, signer, tbs)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(sig)+2)
	binary.BigEndian.PutUint16(out[:2], uint16(len(sig)))
	copy(out[2:], sig)
	return out, nil
}

// tlcpECCProcessClientKeyExchange decrypts the client's SM2-encrypted PMS using
// the server's encryption certificate private key. Returns the 48-byte PMS or
// an error if the length/format is wrong.
//
// The decryption uses SM2 ASN1 mode (matching the client's EncryptASN1).
func tlcpECCProcessClientKeyExchange(decrypter crypto.Decrypter, ckePayload []byte) ([]byte, error) {
	if len(ckePayload) < 2 {
		return nil, errors.New("tlcp: ClientKeyExchange too short")
	}
	ctLen := int(binary.BigEndian.Uint16(ckePayload[:2]))
	if ctLen+2 != len(ckePayload) {
		return nil, errors.New("tlcp: ClientKeyExchange ciphertext length mismatch")
	}
	ciphertext := ckePayload[2:]
	if len(ciphertext) == 0 || ciphertext[0] != 0x30 {
		return nil, errors.New("tlcp: ClientKeyExchange ciphertext is not SM2 ASN1")
	}
	// gotlcp trims trailing extra padding beyond the ASN1 sequence length; we do
	// the same so a client that pads (or a non-conformant peer) does not break.
	// Long-form length is bounded (0x8001..0x80FF), so one length byte suffices.
	if len(ciphertext) >= 3 {
		seqLen := 3 + int(ciphertext[2])
		if seqLen <= len(ciphertext) {
			ciphertext = ciphertext[:seqLen]
		}
	}
	plain, err := decrypter.Decrypt(rand.Reader, ciphertext, sm2.ASN1DecrypterOpts)
	if err != nil {
		return nil, err
	}
	if len(plain) != tlcpPreMasterSecretLength {
		return nil, errors.New("tlcp: decrypted pre-master secret has wrong length")
	}
	return plain, nil
}

// tlcpECCSignedParams assembles the bytes signed in a TLCP ECC
// ServerKeyExchange (GB/T 38636-2020 §6.4.5.4 e): client_random || server_random
// || uint24-length-prefixed encryption certificate DER.
func tlcpECCSignedParams(clientRandom, serverRandom, encCertDER []byte) []byte {
	var buf bytes.Buffer
	buf.Write(clientRandom)
	buf.Write(serverRandom)
	var lenBytes [3]byte
	cl := len(encCertDER)
	lenBytes[0] = byte(cl >> 16)
	lenBytes[1] = byte(cl >> 8)
	lenBytes[2] = byte(cl)
	buf.Write(lenBytes[:])
	buf.Write(encCertDER)
	return buf.Bytes()
}
