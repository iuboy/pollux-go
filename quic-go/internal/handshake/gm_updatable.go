// gm_updatable.go is the 1-RTT AEAD with QUIC key update support (RFC 9001 §6).
// It replaces the P0 gmShortSealer/gmShortOpener (fixed key phase) for 1-RTT
// packets and implements both ShortHeaderSealer and ShortHeaderOpener. Key
// rotation is driven by tls13gm.QUICKeyUpdate; the send/rcv AEADs and header
// protectors are rebuilt each phase from the derived QUIC packet keys.

package handshake

import (
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
)

// gmFirstKeyUpdateInterval mirrors quic-go's FirstKeyUpdateInterval: the packet
// count after which the first key update is initiated (exercises the mechanism).
const gmFirstKeyUpdateInterval uint64 = 100

// gmAEADInvalidPacketLimit is the AEAD integrity limit for SM4-GCM
// (128-bit authentication tag): the maximum number of packets that may fail
// authentication before the connection is closed, denying a limitless
// decryption oracle (RFC 9001 §6.6).
const gmAEADInvalidPacketLimit uint64 = 1 << 36

// gmUpdatableAEAD is the 1-RTT AEAD with key update. It implements
// ShortHeaderSealer and ShortHeaderOpener. One instance serves as both the
// sealer and opener for a connection's 1-RTT level.
type gmUpdatableAEAD struct {
	sendKM, rcvKM *gmKeyMaterial // current phase send / receive
	prevRcvKM     *gmKeyMaterial // previous phase receive (for packet-number echo)
	// TODO(P1): prevRcvKM is currently retained for the connection lifetime.
	// Upstream drops it after PTO (startKeyDropTimer, RFC 9001 §6.5) to bound
	// how long the previous-phase key lives in memory; porting that weakens
	// forward-secrecy loss and bounds late-packet-echo replay surface.

	nextSendSecret []byte // seeds the next send keys via QUICKeyUpdate
	nextRcvSecret  []byte

	keyPhase protocol.KeyPhaseBit

	largestAcked       protocol.PacketNumber
	firstSent          protocol.PacketNumber
	firstRcvd          protocol.PacketNumber
	highestRcvdPN      protocol.PacketNumber
	numSent            uint64
	numRcvd            uint64
	invalidPacketCount uint64
	invalidPacketLimit uint64

	handshakeConfirmed bool
}

var (
	_ ShortHeaderSealer = &gmUpdatableAEAD{}
	_ ShortHeaderOpener = &gmUpdatableAEAD{}
)

// newGMUpdatableAEAD builds the 1-RTT AEAD from the initial send/rcv QUIC
// packet keys and their traffic secrets (the secrets roll forward via
// QUICKeyUpdate to produce later phases).
func newGMUpdatableAEAD(sendKeys, rcvKeys *tls13gm.QUICPacketKeys, sendSecret, rcvSecret []byte) (*gmUpdatableAEAD, error) {
	sendKM, err := newGMKeyMaterial(sendKeys)
	if err != nil {
		return nil, err
	}
	rcvKM, err := newGMKeyMaterial(rcvKeys)
	if err != nil {
		return nil, err
	}
	nextSend, err := tls13gm.QUICKeyUpdate(sendSecret)
	if err != nil {
		return nil, err
	}
	nextRcv, err := tls13gm.QUICKeyUpdate(rcvSecret)
	if err != nil {
		return nil, err
	}
	return &gmUpdatableAEAD{
		sendKM:             sendKM,
		rcvKM:              rcvKM,
		nextSendSecret:     nextSend,
		nextRcvSecret:      nextRcv,
		keyPhase:           protocol.KeyPhaseZero,
		firstSent:          protocol.InvalidPacketNumber,
		firstRcvd:          protocol.InvalidPacketNumber,
		largestAcked:       protocol.InvalidPacketNumber,
		highestRcvdPN:      protocol.InvalidPacketNumber,
		invalidPacketLimit: gmAEADInvalidPacketLimit,
	}, nil
}

// rollKeys advances to the next key phase: the current receive keys become the
// previous (for packet-number echo), the precomputed next keys become current,
// and new next keys are derived.
func (u *gmUpdatableAEAD) rollKeys() error {
	u.prevRcvKM = u.rcvKM

	nextSendKeys, err := tls13gm.DeriveQUICPacketKeys(u.nextSendSecret)
	if err != nil {
		return err
	}
	nextRcvKeys, err := tls13gm.DeriveQUICPacketKeys(u.nextRcvSecret)
	if err != nil {
		return err
	}
	u.sendKM, err = newGMKeyMaterial(nextSendKeys)
	if err != nil {
		return err
	}
	u.rcvKM, err = newGMKeyMaterial(nextRcvKeys)
	if err != nil {
		return err
	}
	u.nextSendSecret, err = tls13gm.QUICKeyUpdate(u.nextSendSecret)
	if err != nil {
		return err
	}
	u.nextRcvSecret, err = tls13gm.QUICKeyUpdate(u.nextRcvSecret)
	if err != nil {
		return err
	}

	u.keyPhase ^= 1
	u.firstSent = protocol.InvalidPacketNumber
	u.firstRcvd = protocol.InvalidPacketNumber
	u.numSent = 0
	u.numRcvd = 0
	return nil
}

func (u *gmUpdatableAEAD) updateAllowed() bool {
	if !u.handshakeConfirmed {
		return false
	}
	return u.keyPhase == protocol.KeyPhaseZero ||
		(u.firstSent != protocol.InvalidPacketNumber &&
			u.largestAcked != protocol.InvalidPacketNumber &&
			u.largestAcked >= u.firstSent)
}

func (u *gmUpdatableAEAD) shouldInitiateKeyUpdate() bool {
	if !u.updateAllowed() {
		return false
	}
	if u.keyPhase == protocol.KeyPhaseZero {
		if u.numRcvd >= gmFirstKeyUpdateInterval || u.numSent >= gmFirstKeyUpdateInterval {
			return true
		}
	}
	return u.numRcvd >= protocol.KeyUpdateInterval || u.numSent >= protocol.KeyUpdateInterval
}

// --- ShortHeaderSealer ---

func (u *gmUpdatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	ct, err := u.sendKM.aead.Seal(uint64(pn), src, ad)
	if err != nil {
		panic(fmt.Sprintf("handshake: GM 1-RTT Seal failed for packet %d: %v", pn, err))
	}
	u.numSent++
	if u.firstSent == protocol.InvalidPacketNumber {
		u.firstSent = pn
	}
	return append(dst, ct...)
}

func (u *gmUpdatableAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(u.sendKM.hp, false, sample, firstByte, pnBytes)
}

func (u *gmUpdatableAEAD) Overhead() int { return u.sendKM.aead.Overhead() }

// KeyPhase returns the current send key phase, initiating a key update if the
// packet counts cross the threshold (RFC 9001 §6).
func (u *gmUpdatableAEAD) KeyPhase() protocol.KeyPhaseBit {
	if u.shouldInitiateKeyUpdate() {
		if err := u.rollKeys(); err != nil {
			// rollKeys fails only on an invariant violation (OOM / HKDF bug).
			// The ShortHeaderSealer.KeyPhase interface has no error return
			// (mirroring upstream updatable_aead.go), so we fail closed here
			// rather than continue with stale keys past the AEAD nonce budget.
			panic(fmt.Sprintf("handshake: GM key update failed: %v", err))
		}
	}
	return u.keyPhase
}

// --- ShortHeaderOpener ---

func (u *gmUpdatableAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(u.rcvKM.hp, false, sample, firstByte, pnBytes)
}

func (u *gmUpdatableAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, u.highestRcvdPN, wirePN)
}

func (u *gmUpdatableAEAD) Open(dst, src []byte, _ monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if kp != u.keyPhase {
		// RFC 9001 §6.1: the peer must not initiate a key update until it has
		// received an ACK for a packet it sent under the current key phase. If
		// we have not yet sent anything in this phase, the peer updated too
		// quickly — close the connection.
		if u.keyPhase != protocol.KeyPhaseZero && u.firstSent == protocol.InvalidPacketNumber {
			return nil, &qerr.TransportError{ErrorCode: qerr.KeyUpdateError, ErrorMessage: "keys updated too quickly"}
		}
		// Peer initiated a key update: roll to the next phase and try there.
		if err := u.rollKeys(); err != nil {
			return nil, err
		}
		if kp != u.keyPhase {
			return nil, ErrKeysNotYetAvailable
		}
	}
	pt, err := u.rcvKM.aead.Open(uint64(pn), src, ad)
	if err != nil && u.prevRcvKM != nil {
		// Packet-number echo: a late packet from the previous phase.
		if pt2, err2 := u.prevRcvKM.aead.Open(uint64(pn), src, ad); err2 == nil {
			pt, err = pt2, nil
		}
	}
	if err != nil {
		// RFC 9001 §6.6: close the connection once too many packets fail AEAD
		// authentication, denying an attacker a limitless decryption oracle.
		u.invalidPacketCount++
		if u.invalidPacketCount >= u.invalidPacketLimit {
			return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
		}
		return nil, ErrDecryptionFailed
	}
	u.numRcvd++
	if u.firstRcvd == protocol.InvalidPacketNumber {
		u.firstRcvd = pn
	}
	if pn > u.highestRcvdPN {
		u.highestRcvdPN = pn
	}
	return append(dst, pt...), nil
}

// --- key-update control ---

// SetLargestAcked records the largest acknowledged 1-RTT packet number (governs
// when a locally-initiated key update is allowed) and detects a peer that ACKed
// our new key phase without having updated its own keys.
func (u *gmUpdatableAEAD) SetLargestAcked(pn protocol.PacketNumber) error {
	if u.firstSent != protocol.InvalidPacketNumber && pn >= u.firstSent && u.numRcvd == 0 {
		return fmt.Errorf("quic-go: received ACK for key phase %d but peer didn't update keys", u.keyPhase)
	}
	u.largestAcked = pn
	return nil
}

// SetHandshakeConfirmed enables key updates (the first update is allowed once
// the handshake is confirmed).
func (u *gmUpdatableAEAD) SetHandshakeConfirmed() {
	u.handshakeConfirmed = true
}
