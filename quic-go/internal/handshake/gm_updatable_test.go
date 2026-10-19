package handshake

// gm_updatable_test.go covers the key-phase mismatch handling in
// gmUpdatableAEAD.Open (third security review, H3). The previous
// implementation diverged structurally from upstream updatable_aead.go: it
// rolled the keys unconditionally on any mismatch, so a late packet from the
// previous phase (we updated, the peer had not) advanced the phase again and
// permanently desynchronized the connection; and it returned KeyUpdateError
// BEFORE authenticating the packet, so a single corrupted packet with a
// flipped phase bit deterministically tore down the connection. These tests
// pin the upstream-equivalent behavior.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
)

// openPacket adapts the ShortHeaderOpener.Open signature (monotime first
// payload arg) for the tests below.
func openPacket(u *gmUpdatableAEAD, src []byte, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	return u.Open(nil, src, monotime.Now(), pn, kp, ad)
}

// newGMUpdatablePair builds two complementary gmUpdatableAEAD instances from
// deterministic secrets so that sender.sendKM protects exactly the keys
// receiver.rcvKM opens, and both sides are handshake-confirmed (key updates
// allowed).
func newGMUpdatablePair(t *testing.T) (receiver, sender *gmUpdatableAEAD) {
	t.Helper()
	secretA := bytes.Repeat([]byte{0x11}, 32) // receiver sends, sender receives
	secretB := bytes.Repeat([]byte{0x22}, 32) // sender sends, receiver receives
	keysA, err := tls13gm.DeriveQUICPacketKeys(secretA)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys(A): %v", err)
	}
	keysB, err := tls13gm.DeriveQUICPacketKeys(secretB)
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys(B): %v", err)
	}
	receiver, err = newGMUpdatableAEAD(keysA, keysB, secretA, secretB)
	if err != nil {
		t.Fatalf("newGMUpdatableAEAD(receiver): %v", err)
	}
	sender, err = newGMUpdatableAEAD(keysB, keysA, secretB, secretA)
	if err != nil {
		t.Fatalf("newGMUpdatableAEAD(sender): %v", err)
	}
	receiver.SetHandshakeConfirmed()
	sender.SetHandshakeConfirmed()
	return receiver, sender
}

// phaseOneReceiver drives the pair to the "too quickly" preconditions: the
// receiver is on key phase 1 (it initiated an update, so firstSent is unset),
// has already received packet 100 under phase 1, and the sender is still on
// phase 1.
func phaseOneReceiver(t *testing.T) (receiver, sender *gmUpdatableAEAD) {
	t.Helper()
	receiver, sender = newGMUpdatablePair(t)
	ad := []byte("gm-ku-ad")
	receiver.Seal(nil, []byte("phase-0 proof"), 1, ad) // firstSent set: local update allowed
	if err := receiver.rollKeys(); err != nil {
		t.Fatalf("receiver rollKeys: %v", err)
	}
	if err := sender.rollKeys(); err != nil {
		t.Fatalf("sender rollKeys: %v", err)
	}
	ct := sender.Seal(nil, []byte("phase-1 packet"), 100, ad)
	if _, err := openPacket(receiver, ct, 100, protocol.KeyPhaseOne, ad); err != nil {
		t.Fatalf("setup: open phase-1 packet: %v", err)
	}
	return receiver, sender
}

// TestGMUpdatable_LatePacketAfterLocalUpdate pins the packet-number echo path:
// after WE initiated an update, a late packet still protected with the
// previous phase must decrypt via prevRcvKM and must NOT advance the phase
// (the old code rolled again on every mismatch, desynchronizing forever).
func TestGMUpdatable_LatePacketAfterLocalUpdate(t *testing.T) {
	receiver, sender := newGMUpdatablePair(t)
	ad := []byte("gm-ku-ad")
	payload := []byte("late packet payload")

	// The sender is still on phase 0; protect packet 6 under it.
	ct := sender.Seal(nil, payload, 6, ad)
	// We sent under phase 0 and then initiated an update ourselves.
	receiver.Seal(nil, []byte("local"), 1, ad)
	if err := receiver.rollKeys(); err != nil {
		t.Fatalf("rollKeys: %v", err)
	}

	pt, err := openPacket(receiver, ct, 6, protocol.KeyPhaseZero, ad)
	if err != nil {
		t.Fatalf("late packet after local update: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("late packet payload mismatch: %q", pt)
	}
	if receiver.keyPhase != protocol.KeyPhaseOne {
		t.Fatalf("late packet must not advance the key phase, now %v", receiver.keyPhase)
	}
	// And phase-1 traffic from the (now updated) peer still decrypts.
	if err := sender.rollKeys(); err != nil {
		t.Fatalf("sender rollKeys: %v", err)
	}
	ct2 := sender.Seal(nil, []byte("new phase"), 7, ad)
	if _, err := openPacket(receiver, ct2, 7, protocol.KeyPhaseOne, ad); err != nil {
		t.Fatalf("phase-1 packet after echo: %v", err)
	}
}

// TestGMUpdatable_PeerInitiatedUpdate pins the authenticated-update path: a
// packet that trial-opens under the NEXT phase rolls the keys, but only after
// the AEAD authenticated it.
func TestGMUpdatable_PeerInitiatedUpdate(t *testing.T) {
	receiver, sender := newGMUpdatablePair(t)
	ad := []byte("gm-ku-ad")
	payload := []byte("peer updated")

	// We have sent under phase 0, so the peer is allowed to update.
	receiver.Seal(nil, []byte("proof"), 1, ad)
	if err := sender.rollKeys(); err != nil {
		t.Fatalf("sender rollKeys: %v", err)
	}
	ct := sender.Seal(nil, payload, 10, ad)

	pt, err := openPacket(receiver, ct, 10, protocol.KeyPhaseOne, ad)
	if err != nil {
		t.Fatalf("peer-initiated update: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("payload mismatch: %q", pt)
	}
	if receiver.keyPhase != protocol.KeyPhaseOne {
		t.Fatalf("phase must roll after an authenticated peer update, now %v", receiver.keyPhase)
	}
	if receiver.firstRcvd != 10 {
		t.Fatalf("firstRcvd = %d, want 10", receiver.firstRcvd)
	}
	// Subsequent phase-1 packets take the normal path.
	ct2 := sender.Seal(nil, []byte("next"), 11, ad)
	if _, err := openPacket(receiver, ct2, 11, protocol.KeyPhaseOne, ad); err != nil {
		t.Fatalf("post-update packet: %v", err)
	}
}

// TestGMUpdatable_PeerUpdatedTooQuickly pins RFC 9001 §6.1: the peer may not
// update again before it has proof we can use the current phase. The
// KeyUpdateError must only be returned AFTER the packet authenticated under
// the next phase.
func TestGMUpdatable_PeerUpdatedTooQuickly(t *testing.T) {
	receiver, sender := phaseOneReceiver(t)
	ad := []byte("gm-ku-ad")

	// Peer jumps to phase 2 without any ACK proof (receiver.firstSent unset).
	if err := sender.rollKeys(); err != nil {
		t.Fatalf("sender rollKeys: %v", err)
	}
	ct := sender.Seal(nil, []byte("too fast"), 150, ad)

	_, err := openPacket(receiver, ct, 150, protocol.KeyPhaseZero /* phase 2 bit */, ad)
	var te *qerr.TransportError
	if !errors.As(err, &te) || te.ErrorCode != qerr.KeyUpdateError {
		t.Fatalf("want KeyUpdateError, got %v", err)
	}
	if receiver.keyPhase != protocol.KeyPhaseOne {
		t.Fatalf("phase must not roll on a rejected update, now %v", receiver.keyPhase)
	}
}

// TestGMUpdatable_CorruptedPacketDoesNotKillConnection pins that a corrupted
// or injected packet whose header decodes to the wrong phase bit fails AEAD
// and counts toward the integrity limit instead of being treated as a key
// update (the old code returned KeyUpdateError before any authentication).
func TestGMUpdatable_CorruptedPacketDoesNotKillConnection(t *testing.T) {
	receiver, sender := phaseOneReceiver(t)
	ad := []byte("gm-ku-ad")

	garbage := bytes.Repeat([]byte{0xA5}, 40)
	_, err := openPacket(receiver, garbage, 150, protocol.KeyPhaseZero, ad)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("want ErrDecryptionFailed, got %v", err)
	}
	if receiver.invalidPacketCount != 1 {
		t.Fatalf("invalidPacketCount = %d, want 1", receiver.invalidPacketCount)
	}
	if receiver.keyPhase != protocol.KeyPhaseOne {
		t.Fatalf("phase must not move on garbage, now %v", receiver.keyPhase)
	}
	// The connection survives: valid phase-1 traffic still decrypts.
	ct := sender.Seal(nil, []byte("still alive"), 151, ad)
	if _, err := openPacket(receiver, ct, 151, protocol.KeyPhaseOne, ad); err != nil {
		t.Fatalf("valid packet after garbage: %v", err)
	}
}
