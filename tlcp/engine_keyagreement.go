//go:build tlcp_native

package tlcp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

// =====================================================================
// ECDHE key exchange (SM2 MQV, GB/T 36322-2018)
//
// Unlike ECC (SM2 public-key encryption of the PMS), ECDHE uses the SM2 MQV
// key-agreement protocol: both sides contribute a long-term key (from the
// encryption certificate) AND an ephemeral key. MQV combines all four to
// derive a shared secret point, which is fed through SM3-KDF to produce the
// 48-byte PMS.
//
// Because MQV needs both peers' long-term encryption keys, ECDHE mandates
// mutual authentication: the client MUST also send a dual certificate pair
// (sign + enc), and the server requests it via CertificateRequest.
//
// The server is the MQV sponsor (initiator), the client is the responder:
//   - Server (sponsor): GenerateAgreementData (ephemeral key) → later GenerateKey
//     (after receiving the client's ephemeral key).
//   - Client (responder): GenerateAgreementDataAndKey (ephemeral key + PMS in
//     one step, using the server's ephemeral key from ServerKeyExchange).
//
// Wire format (ServerKeyExchange.key / ClientKeyExchange.ciphertext):
//   curve_type(1, =3) || named_curve(2, =CurveSM2=41) || pubkey_len(1) || point(65)
//   followed (server side only) by uint16-length-prefixed SM2 signature over
//   (client_random || server_random || ServerECDHParams).
//
// Reference: gotlcp/tlcp/key_agreement.go sm2ECDHEKeyAgreement + key_schedule.go
// sm2ke (logic consulted, independently written).
// =====================================================================

const (
	tlcpECDHECurveTypeNamed = 3       // curve_type: named_curve
	tlcpSM2PointLength      = 65      // uncompressed SM2 point: 0x04 || X(32) || Y(32)
)

// tlcpECDHEServerKeyExchange holds the server's ECDHE state across the two
// handshake steps (generate SKE → process CKE).
type tlcpECDHEServerKeyExchange struct {
	sponsorPriv  *ecdhPrivateKey // server long-term enc key (ecdh form)
	sponsorEph   *ecdhPrivateKey // server ephemeral key
}

// tlcpECDHEClientState holds the client's parsed server ephemeral key.
type tlcpECDHEClientState struct {
	serverEphPub *ecdhPublicKey // server ephemeral public key (from SKE)
}

// marshalECDHEParams encodes an SM2 ephemeral public key into the TLCP
// ECDHEParams wire format: curve_type(3) || named_curve(41) || len || point.
func tlcpMarshalECDHEParams(pubKey *ecdhPublicKey) ([]byte, error) {
	point := pubKey.bytes()
	if len(point) != tlcpSM2PointLength {
		return nil, fmt.Errorf("tlcp: unexpected SM2 point length %d", len(point))
	}
	out := make([]byte, 0, 4+len(point))
	out = append(out, tlcpECDHECurveTypeNamed)
	out = append(out, byte(uint16(tlcpCurveSM2)>>8), byte(uint16(tlcpCurveSM2)))
	out = append(out, byte(len(point)))
	out = append(out, point...)
	return out, nil
}

// parseECDHEParams decodes the ECDHEParams wire format and returns the point
// bytes (consumes curve_type + named_curve + len + point). Returns the params
// bytes (for signature verification) and the public key.
func tlcpParseECDHEParams(data []byte) (paramsBytes []byte, pubKey *ecdhPublicKey, err error) {
	if len(data) < 4 {
		return nil, nil, errors.New("tlcp: ECDHE params too short")
	}
	pubLen := int(data[3])
	if len(data) < 4+pubLen {
		return nil, nil, errors.New("tlcp: ECDHE params truncated")
	}
	paramsBytes = data[:4+pubLen]
	pubKey, err = newEcdhPublicKey(paramsBytes[4:])
	if err != nil {
		return nil, nil, fmt.Errorf("tlcp: parse ECDHE ephemeral key: %w", err)
	}
	return paramsBytes, pubKey, nil
}

// --- Server side (MQV sponsor / initiator) ---

// tlcpECDHEServerGenerateSKE generates the server's ephemeral key and produces
// the ServerKeyExchange payload (ECDHEParams || uint16-sig-len || SM2 signature
// over client_random||server_random||ECDHEParams).
func tlcpECDHEServerGenerateSKE(sigType tlcpSigType, signer crypto.Signer, encPriv crypto.Decrypter, clientRandom, serverRandom []byte) (*tlcpECDHEServerKeyExchange, []byte, error) {
	sponsorPriv, err := ecdhPrivFromDecrypter(encPriv)
	if err != nil {
		return nil, nil, err
	}
	sponsorEph, err := generateECDHEKey(randReader)
	if err != nil {
		return nil, nil, err
	}
	params, err := tlcpMarshalECDHEParams(sponsorEph.publicKey())
	if err != nil {
		return nil, nil, err
	}
	// Signature over client_random || server_random || ECDHEParams.
	tbs := tlcpECDHESignedParams(clientRandom, serverRandom, params)
	sig, err := tlcpSignHandshake(randReader, sigType, signer, tbs)
	if err != nil {
		return nil, nil, err
	}
	payload := make([]byte, 0, len(params)+2+len(sig))
	payload = append(payload, params...)
	payload = append(payload, byte(len(sig)>>8), byte(len(sig)))
	payload = append(payload, sig...)
	return &tlcpECDHEServerKeyExchange{sponsorPriv: sponsorPriv, sponsorEph: sponsorEph}, payload, nil
}

// tlcpECDHEServerProcessCKE derives the PMS from the client's ephemeral key
// (and the client's long-term enc public key from the encryption certificate).
// Uses SM2 MQV (sponsor role) + SM3-KDF.
func tlcpECDHEServerProcessCKE(state *tlcpECDHEServerKeyExchange, clientEncPub *ecdsa.PublicKey, ckePayload []byte) ([]byte, error) {
	_, clientEphPub, err := tlcpParseECDHEParams(ckePayload)
	if err != nil {
		return nil, err
	}
	clientLongPub, err := ecdhPubFromECDSA(clientEncPub)
	if err != nil {
		return nil, err
	}
	// MQV: uv = [t]·(sRemote + [avf(eRemote)]·eRemote), where t is the sponsor's
	// implicit signature from its long-term + ephemeral keys.
	uv, err := state.sponsorPriv.sm2mqv(state.sponsorEph, clientLongPub, clientEphPub)
	if err != nil {
		return nil, fmt.Errorf("tlcp: ECDHE MQV: %w", err)
	}
	// KDF: SM2SharedKey(isResponder=false, keyLen=48, sPub=sponsorPub, sRemote=clientLongPub).
	pms, err := uv.sm2SharedKey(false, tlcpPreMasterSecretLength, state.sponsorPriv.publicKey(), clientLongPub)
	if err != nil {
		return nil, err
	}
	return pms, nil
}

// --- Client side (MQV responder) ---

// tlcpECDHEClientProcessSKE verifies the server's ServerKeyExchange signature
// and extracts the server's ephemeral public key. Returns the client state
// holding the server ephemeral key.
func tlcpECDHEClientProcessSKE(sigType tlcpSigType, signCertPub *ecdsa.PublicKey, clientRandom, serverRandom, skeKey []byte) (*tlcpECDHEClientState, error) {
	if len(skeKey) < 4 {
		return nil, errors.New("tlcp: ECDHE ServerKeyExchange too short")
	}
	pubLen := int(skeKey[3])
	if len(skeKey) < 4+pubLen+2 {
		return nil, errors.New("tlcp: ECDHE ServerKeyExchange truncated")
	}
	paramsBytes := skeKey[:4+pubLen]
	serverEphPub, err := newEcdhPublicKey(paramsBytes[4:])
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse server ephemeral key: %w", err)
	}
	// Verify signature.
	sigLen := int(skeKey[4+pubLen])<<8 | int(skeKey[4+pubLen+1])
	if 4+pubLen+2+sigLen != len(skeKey) {
		return nil, errors.New("tlcp: ECDHE SKE signature length mismatch")
	}
	sig := skeKey[4+pubLen+2:]
	tbs := tlcpECDHESignedParams(clientRandom, serverRandom, paramsBytes)
	if err := tlcpVerifyHandshakeSignature(sigType, signCertPub, tbs, sig); err != nil {
		return nil, fmt.Errorf("tlcp: ECDHE SKE signature: %w", err)
	}
	return &tlcpECDHEClientState{serverEphPub: serverEphPub}, nil
}

// tlcpECDHEClientGenerateCKE generates the client's ephemeral key and derives
// the PMS (MQV responder role). Returns the PMS and the ClientKeyExchange
// payload (ECDHEParams of the client's ephemeral key).
func tlcpECDHEClientGenerateCKE(state *tlcpECDHEClientState, clientEncPriv crypto.Decrypter, serverEncPub *ecdsa.PublicKey) (preMasterSecret, ckePayload []byte, err error) {
	responderPriv, err := ecdhPrivFromDecrypter(clientEncPriv)
	if err != nil {
		return nil, nil, err
	}
	responderEph, err := generateECDHEKey(randReader)
	if err != nil {
		return nil, nil, err
	}
	serverLongPub, err := ecdhPubFromECDSA(serverEncPub)
	if err != nil {
		return nil, nil, err
	}
	// MQV (responder side): uv = [t]·(sRemote + [avf(eRemote)]·eRemote)
	uv, err := responderPriv.sm2mqv(responderEph, serverLongPub, state.serverEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("tlcp: ECDHE MQV: %w", err)
	}
	// KDF (responder): isResponder=true.
	pms, err := uv.sm2SharedKey(true, tlcpPreMasterSecretLength, responderPriv.publicKey(), serverLongPub)
	if err != nil {
		return nil, nil, err
	}
	payload, err := tlcpMarshalECDHEParams(responderEph.publicKey())
	if err != nil {
		return nil, nil, err
	}
	return pms, payload, nil
}

// tlcpECDHESignedParams assembles the bytes signed in an ECDHE
// ServerKeyExchange: client_random || server_random || ECDHEParams.
func tlcpECDHESignedParams(clientRandom, serverRandom, ecdheParams []byte) []byte {
	var buf bytes.Buffer
	buf.Write(clientRandom)
	buf.Write(serverRandom)
	buf.Write(ecdheParams)
	return buf.Bytes()
}
