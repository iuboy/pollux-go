package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/sm3"
)

// TrafficKeys holds the key and IV derived from a traffic secret.
type TrafficKeys struct {
	Key []byte
	IV  []byte
}

// DeriveEarlySecret computes the early secret from the IKM (PSK or zeros).
// salt is all zeros for the initial extract.
func DeriveEarlySecret(ikm []byte) []byte {
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
	return sm3.HKDFExtract(derivedSecret, sharedSecret), nil
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
	return sm3.HKDFExtract(derivedSecret, ikm), nil
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
		return nil, fmt.Errorf("tls13gm: finishedKey is empty")
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
