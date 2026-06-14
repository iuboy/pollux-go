package tls13gm

import (
	"hash"

	"github.com/iuboy/pollux-go/sm3"
)

// Transcript accumulates the TLS 1.3 handshake transcript (RFC 8446 §4.4.1) as
// the raw bytes of every handshake message in order, each framed as
// [type(1) | length(3) | body] to match the on-the-wire handshake message
// layout.
//
// A running incremental SM3 digest is maintained alongside the raw buffer so
// that Sum() returns an O(1) snapshot (gmsm sm3 digest.Sum copies internal state
// and finalizes without disturbing the running hash). This avoids the O(n²)
// cost of re-hashing the entire accumulated buffer at every key-schedule
// boundary, of which there are ~8-10 per handshake. Callers that need the
// transcript hash (DeriveSecret, ComputeFinishedVerifyData,
// Sign/VerifyCertificateVerify) MUST pass Sum(), not Bytes().
type Transcript struct {
	buf []byte    // raw accumulated handshake bytes (Bytes())
	h   hash.Hash // incremental SM3 digest; Sum() snapshots it
}

// NewTranscript returns a fresh empty transcript.
func NewTranscript() *Transcript {
	return &Transcript{h: sm3.New()}
}

// AddMessage incorporates a handshake message — its type and raw body — into
// the transcript. The body excludes the 4-byte handshake header; AddMessage
// synthesizes that header from the type and body length and feeds both the
// header and body to the incremental digest.
func (t *Transcript) AddMessage(msgType uint8, body []byte) {
	l := len(body)
	var hdr [4]byte
	hdr[0] = msgType
	hdr[1] = byte(l >> 16)
	hdr[2] = byte(l >> 8)
	hdr[3] = byte(l)
	t.buf = append(t.buf, hdr[:]...)
	t.buf = append(t.buf, body...)
	t.h.Write(hdr[:])
	t.h.Write(body)
}

// Bytes returns the raw accumulated handshake-message bytes (each framed as
// type|length(3)|body). Prefer Sum() for cryptographic consumption — Bytes()
// is retained for inspection/debugging only and must not be passed to
// DeriveSecret or the Certificate/Finished routines (they expect a hash).
func (t *Transcript) Bytes() []byte {
	return t.buf
}

// Sum returns the SM3 transcript-hash snapshot without altering the running
// accumulation, so further messages can still be added. This is the value to
// pass to DeriveSecret, ComputeFinishedVerifyData, and
// Sign/VerifyCertificateVerify.
func (t *Transcript) Sum() []byte {
	return t.h.Sum(nil)
}
