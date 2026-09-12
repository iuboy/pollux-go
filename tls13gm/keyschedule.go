package tls13gm

import (
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/internal/memsecure"
	"github.com/iuboy/pollux-go/sm3"
)

// TrafficKeys holds the key and IV derived from a traffic secret.
type TrafficKeys struct {
	Key []byte
	IV  []byte
}

// Zero securely zeroes the Key and IV material via memsecure.ZeroBytes
// (constant-time XOR + unsafe write + runtime.KeepAlive). Call when the
// traffic keys are no longer needed (e.g. after a key update replaces them)
// so the material does not linger on the heap. Mirrors QUICPacketKeys.Zero
// for API consistency across the package's key-bearing types.
func (t *TrafficKeys) Zero() {
	if t == nil {
		return
	}
	memsecure.ZeroBytes(t.Key)
	memsecure.ZeroBytes(t.IV)
}

// DeriveEarlySecret computes the early secret from the IKM (PSK or zeros).
// salt is all zeros for the initial extract.
//
// When ikm is empty (nil or zero-length) it is replaced with a zero string of
// HashLen — this is the RFC 8446 §7.1 behavior for "no PSK" (the early secret
// is derived from a known all-zero IKM, which is cryptographically safe because
// the early secret only feeds into the "derived" label, not directly into
// traffic keys). This is INTENTIONAL and not a security weakness: the
// zero-IKM path is the standard full-handshake (non-resumption) path.
//
// Callers that DO have a PSK MUST pass it explicitly — relying on the
// zero-default would silently produce a full-handshake early secret instead
// of a PSK-bound one, defeating resumption. The HandshakeSecrets /
// NewClientHandshakerWithConfig / NewServerHandshakerWithConfig constructors
// route the PSK correctly; direct callers of DeriveEarlySecret should check
// len(ikm) > 0 before calling if they intend PSK mode.
func DeriveEarlySecret(ikm []byte) ([]byte, error) {
	if len(ikm) == 0 {
		ikm = make([]byte, sm3.Size)
	}
	return sm3.HKDFExtract(nil, ikm)
}

// DeriveHandshakeSecret derives the handshake secret from the early secret
// and the shared secret from ECDHE key exchange.
func DeriveHandshakeSecret(earlySecret, sharedSecret []byte) ([]byte, error) {
	// The "derived" label uses an empty transcript (RFC 8446 §7.1), i.e. the
	// SM3 hash of the empty string.
	emptyHash := sm3.Sum(nil)
	derivedSecret, err := DeriveSecret(earlySecret, LabelDerived, emptyHash[:])
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive handshake derived secret: %w", err)
	}
	// Per RFC 8446 §7.1, when (EC)DHE is not in use (PSK-only key exchange),
	// the IKM for the handshake secret is a string of Hash.length zero bytes,
	// not an empty string.
	if len(sharedSecret) == 0 {
		sharedSecret = make([]byte, sm3.Size)
	}
	return sm3.HKDFExtract(derivedSecret, sharedSecret)
}

// DeriveMasterSecret derives the master secret from the handshake secret.
func DeriveMasterSecret(handshakeSecret []byte) ([]byte, error) {
	emptyHash := sm3.Sum(nil)
	derivedSecret, err := DeriveSecret(handshakeSecret, LabelDerived, emptyHash[:])
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive master derived secret: %w", err)
	}
	// IKM is all zeros for master secret.
	ikm := make([]byte, sm3.Size)
	return sm3.HKDFExtract(derivedSecret, ikm)
}

// DeriveTrafficKeys derives the key and IV from a traffic secret.
// keyLen is the AEAD key length in bytes (16 for SM4-GCM).
// ivLen is the AEAD nonce length in bytes (12 for TLS 1.3).
func DeriveTrafficKeys(trafficSecret []byte, keyLen, ivLen int) (TrafficKeys, error) {
	key, err := HKDFExpandLabel(trafficSecret, LabelKey, nil, keyLen)
	if err != nil {
		return TrafficKeys{}, fmt.Errorf("tls13gm: derive traffic key: %w", err)
	}
	iv, err := HKDFExpandLabel(trafficSecret, LabelIV, nil, ivLen)
	if err != nil {
		// Zero the already-derived key on the IV error path so it does not
		// linger on the heap. Mirrors DeriveQUICPacketKeys (quic_keys.go).
		memsecure.ZeroBytes(key)
		return TrafficKeys{}, fmt.Errorf("tls13gm: derive traffic IV: %w", err)
	}
	return TrafficKeys{Key: key, IV: iv}, nil
}

// DeriveFinishedKey computes the finished_key used for the Finished message.
func DeriveFinishedKey(trafficSecret []byte) ([]byte, error) {
	return HKDFExpandLabel(trafficSecret, LabelFinished, nil, sm3.Size)
}

// ComputeFinishedVerifyData computes the verify_data for a Finished message.
// finishedKey is from DeriveFinishedKey, transcriptHash is the hash of the
// handshake transcript.
//
// Per RFC 8446 §4.4.4: verify_data = HMAC(finished_key, transcript_hash).
// This uses HMAC-SM3, NOT HKDF-Expand-Label.
func ComputeFinishedVerifyData(finishedKey, transcriptHash []byte) ([]byte, error) {
	if len(finishedKey) == 0 {
		return nil, errors.New("tls13gm: finishedKey is empty")
	}
	mac := sm3.NewHMAC(finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil), nil
}

// DeriveResumptionPSK derives the PSK from the resumption master secret
// and the NewSessionTicket.ticket_nonce.
func DeriveResumptionPSK(resumptionMasterSecret, ticketNonce []byte) ([]byte, error) {
	return HKDFExpandLabel(resumptionMasterSecret, LabelResumption, ticketNonce, sm3.Size)
}

// DeriveResumptionMasterSecret derives the resumption master secret.
func DeriveResumptionMasterSecret(masterSecret []byte, transcriptHash []byte) ([]byte, error) {
	return DeriveSecret(masterSecret, LabelResumptionMaster, transcriptHash)
}

// DeriveExporterMasterSecret derives the exporter master secret.
func DeriveExporterMasterSecret(masterSecret []byte, transcriptHash []byte) ([]byte, error) {
	return DeriveSecret(masterSecret, LabelExporterMaster, transcriptHash)
}

// DeriveEarlyTrafficKeys derives the 0-RTT QUIC packet keys from a resumption
// PSK (RFC 8446 §7.1: client_early_traffic_secret = DeriveSecret(Early Secret,
// "c e traffic", transcript)). transcriptHash is Hash(ClientHello) — the
// ClientHello carrying the early_data + pre_shared_key extensions. The client
// uses these keys to encrypt early data before the server responds; the server
// derives the same keys from the PSK to decrypt it.
func DeriveEarlyTrafficKeys(psk, transcriptHash []byte) (*QUICPacketKeys, error) {
	earlySecret, err := DeriveEarlySecret(psk)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive early secret for 0-RTT keys: %w", err)
	}
	earlyTraffic, err := DeriveSecret(earlySecret, LabelClientEarlyTraffic, transcriptHash)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive client early traffic secret: %w", err)
	}
	return DeriveQUICPacketKeys(earlyTraffic)
}
