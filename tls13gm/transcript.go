package tls13gm

import (
	"github.com/iuboy/pollux-go/sm3"
)

// Transcript accumulates the TLS 1.3 handshake transcript (RFC 8446 §4.4.1) as
// the raw bytes of every handshake message in order, each framed as
// [type(1) | length(3) | body] to match the on-the-wire handshake message
// layout. The raw bytes are what DeriveSecret (hkdf.go) and
// SignCertificateVerify/VerifyCertificateVerify (signature.go) consume — both
// hash the transcript internally with SM3 — so Bytes() is the canonical form
// for key-schedule boundaries. Sum() returns SM3(Bytes()) as a convenience
// snapshot that does not disturb the running accumulation.
type Transcript struct {
	buf []byte
}

// NewTranscript returns a fresh empty transcript.
func NewTranscript() *Transcript {
	return &Transcript{}
}

// AddMessage incorporates a handshake message — its type and raw body — into
// the transcript. The body excludes the 4-byte handshake header; AddMessage
// synthesizes that header from the type and body length.
func (t *Transcript) AddMessage(msgType uint8, body []byte) {
	l := len(body)
	t.buf = append(t.buf, msgType, byte(l>>16), byte(l>>8), byte(l))
	t.buf = append(t.buf, body...)
}

// Bytes returns the raw accumulated handshake-message bytes (each framed as
// type|length(3)|body). This is the value to pass to DeriveSecret and to
// SignCertificateVerify/VerifyCertificateVerify, which hash it with SM3
// internally.
func (t *Transcript) Bytes() []byte {
	return t.buf
}

// Sum returns SM3(Bytes()) — the transcript hash snapshot — without altering
// the running accumulation, so further messages can still be added.
func (t *Transcript) Sum() []byte {
	s := sm3.Sum(t.buf)
	return s[:]
}
