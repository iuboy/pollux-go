package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/internal/memsecure"
	"github.com/iuboy/pollux-go/sm3"
)

// QUIC packet protection parameter sizes per RFC 9001 §5.1 and RFC 8998.
const (
	// quicAEADKeyLen is the SM4-GCM AEAD key length (SM4-128).
	quicAEADKeyLen = 16
	// quicAEADIVLen is the AEAD nonce/IV length (96-bit) shared by QUIC and TLS 1.3.
	quicAEADIVLen = 12
	// quicHeaderKeyLen is the header protection key length. For SM4-GCM the
	// header protection key is the raw SM4 block cipher key (RFC 9001 §5.4.3).
	quicHeaderKeyLen = 16
)

// QUICPacketKeys holds the AEAD key, AEAD IV, and header protection key derived
// from a single QUIC traffic secret per RFC 9001 §5.1.
type QUICPacketKeys struct {
	AEADKey   []byte // 16 bytes (SM4-GCM)
	AEADIV    []byte // 12 bytes
	HeaderKey []byte // 16 bytes (SM4-ECB for header protection)
}

// DeriveQUICPacketKeys derives all QUIC packet protection keys from a traffic
// secret using HKDF-Expand-Label with the "quic key"/"quic iv"/"quic hp" labels
// (RFC 9001 §5.1). These labels differ from TLS 1.3's "key"/"iv" labels.
func DeriveQUICPacketKeys(trafficSecret []byte) (*QUICPacketKeys, error) {
	if len(trafficSecret) == 0 {
		return nil, fmt.Errorf("tls13gm: QUIC traffic secret must not be empty")
	}
	key, err := HKDFExpandLabel(trafficSecret, LabelQUICKey, nil, quicAEADKeyLen)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive QUIC AEAD key: %w", err)
	}
	iv, err := HKDFExpandLabel(trafficSecret, LabelQUICIV, nil, quicAEADIVLen)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive QUIC AEAD IV: %w", err)
	}
	hp, err := HKDFExpandLabel(trafficSecret, LabelQUICHP, nil, quicHeaderKeyLen)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: derive QUIC header protection key: %w", err)
	}
	return &QUICPacketKeys{AEADKey: key, AEADIV: iv, HeaderKey: hp}, nil
}

// QUICKeyUpdate derives the next-generation QUIC traffic secret using the
// "quic ku" label (RFC 9001 §6). The output length matches the input secret
// length, which for RFC 8998 is the SM3 hash length (32 bytes). Feed the result
// back into DeriveQUICPacketKeys to obtain the next set of packet protection keys.
//
// Caller responsibility — rekey cadence: AEAD nonces are IV XOR packet-number,
// so they stay unique within a key generation as long as packet numbers are
// monotonic, but a single generation must not protect an unbounded number of
// packets. RFC 9001 §6 requires a key update well before the AEAD nonces or
// counters could repeat; for TLS 1.3 records the update threshold is ~2^24.5
// records (RFC 8446 §5.5), and for QUIC packets it is governed by the packet
// number space. The transport layer (e.g. quic-go) is responsible for initiating
// the update at the appropriate threshold by calling this function and
// reconstructing the packet protector — pollux does not enforce the cadence.
func QUICKeyUpdate(trafficSecret []byte) ([]byte, error) {
	if len(trafficSecret) == 0 {
		return nil, fmt.Errorf("tls13gm: QUIC traffic secret must not be empty")
	}
	return HKDFExpandLabel(trafficSecret, LabelQUICKU, nil, len(trafficSecret))
}

// Zero securely zeroes all key material in a QUICPacketKeys using
// constant-time operations via memsecure.
func (k *QUICPacketKeys) Zero() {
	if k == nil {
		return
	}
	memsecure.ZeroBytes(k.AEADKey)
	memsecure.ZeroBytes(k.AEADIV)
	memsecure.ZeroBytes(k.HeaderKey)
	k.AEADKey = nil
	k.AEADIV = nil
	k.HeaderKey = nil
}

// quicV1InitialSalt is the QUIC version 1 initial salt used to derive Initial
// packet protection keys (RFC 9001 §5.2).
var quicV1InitialSalt = [20]byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// DeriveQUICInitialSecret derives the QUIC Initial secret from the destination
// connection ID using the QUIC v1 initial salt (RFC 9001 §5.2):
//
//	initial_secret = HKDF-Extract(initial_salt, dcid)
//
// The returned secret is fed into DeriveQUICInitialSecrets (or
// HKDFExpandLabel with "client in"/"server in") to obtain the per-endpoint
// Initial secrets, which in turn drive DeriveQUICPacketKeys.
func DeriveQUICInitialSecret(destinationConnectionID []byte) ([]byte, error) {
	if len(destinationConnectionID) == 0 {
		return nil, fmt.Errorf("tls13gm: QUIC destination connection ID must not be empty")
	}
	return sm3.HKDFExtract(quicV1InitialSalt[:], destinationConnectionID), nil
}

// DeriveQUICInitialSecrets derives both the client and server Initial secrets
// (RFC 9001 §5.2) from the destination connection ID. Each secret is sm3.Size
// (32) bytes and is passed to DeriveQUICPacketKeys to obtain Initial packet
// protection keys.
func DeriveQUICInitialSecrets(destinationConnectionID []byte) (clientIn, serverIn []byte, err error) {
	initialSecret, err := DeriveQUICInitialSecret(destinationConnectionID)
	if err != nil {
		return nil, nil, err
	}
	clientIn, err = HKDFExpandLabel(initialSecret, LabelQUICClientIn, nil, sm3.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("tls13gm: derive QUIC client initial secret: %w", err)
	}
	serverIn, err = HKDFExpandLabel(initialSecret, LabelQUICServerIn, nil, sm3.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("tls13gm: derive QUIC server initial secret: %w", err)
	}
	return clientIn, serverIn, nil
}
