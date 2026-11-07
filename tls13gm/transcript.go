package tls13gm

import (
	"errors"
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

// Bytes returns a COPY of the raw accumulated handshake-message bytes (each
// framed as type|length(3)|body). The copy is intentional: returning the
// internal slice would let callers mutate transcript state. Prefer Sum() for
// cryptographic consumption — Bytes() is retained for inspection/debugging
// only and must not be passed to DeriveSecret or the Certificate/Finished
// routines (they expect a hash).
func (t *Transcript) Bytes() []byte {
	out := make([]byte, len(t.buf))
	copy(out, t.buf)
	return out
}

// Sum returns the SM3 transcript-hash snapshot without altering the running
// accumulation, so further messages can still be added. This is the value to
// pass to DeriveSecret, ComputeFinishedVerifyData, and
// Sign/VerifyCertificateVerify.
func (t *Transcript) Sum() []byte {
	return t.h.Sum(nil)
}

// ResetForHelloRetry re-initializes the transcript for the HelloRetryRequest
// case (RFC 8446 §4.4.1): the transcript becomes a synthetic message_hash
// message carrying Hash(ClientHello1), followed by the HelloRetryRequest. The
// caller then adds ClientHello2 and the rest of the handshake continues
// normally. clientHello1 is the full ClientHello1 message (4-byte header +
// body); hrr is the full HelloRetryRequest message (a ServerHello carrying the
// sentinel random).
//
// 第四轮审计 P3:此前对短于 4 字节头的 hrr 静默跳过(转写不含 HRR,两侧
// transcript 从此 desync 且无任何报告)。导出 API 不得静默 desync——现返回
// error,且先校验后清空,出错时转写保持原样。调用方(客户端
// HandleHelloRetryRequest)在解出合法 HRR 消息后才调用本方法,故该路径
// 实际不可达;防御性返回仅为守住"永不静默 desync"的契约。
func (t *Transcript) ResetForHelloRetry(clientHello1, hrr []byte) error {
	if len(hrr) < 4 {
		return errors.New("tls13gm: transcript: HelloRetryRequest message shorter than the 4-byte handshake header")
	}
	hash1 := sm3.Sum(clientHello1)
	t.buf = t.buf[:0]
	t.h.Reset()
	t.AddMessage(HandshakeTypeMessageHash, hash1[:])
	t.AddMessage(HandshakeTypeServerHello, hrr[4:])
	return nil
}
