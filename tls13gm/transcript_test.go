package tls13gm

import (
	"bytes"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

// wantTranscript builds the expected on-the-wire handshake framing for the
// given (type, body) pairs and returns its SM3 digest, to compare against
// Transcript.Sum().
func wantTranscript(t *testing.T, msgs ...struct {
	typ  uint8
	body []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range msgs {
		buf.WriteByte(m.typ)
		l := len(m.body)
		buf.WriteByte(byte(l >> 16))
		buf.WriteByte(byte(l >> 8))
		buf.WriteByte(byte(l))
		buf.Write(m.body)
	}
	sum := sm3.Sum(buf.Bytes())
	return sum[:]
}

func TestTranscript_SingleMessage(t *testing.T) {
	body := []byte("ClientHello-body")
	tr := NewTranscript()
	tr.AddMessage(HandshakeTypeClientHello, body)

	got := tr.Sum()
	want := wantTranscript(t, struct {
		typ  uint8
		body []byte
	}{HandshakeTypeClientHello, body})
	if !bytes.Equal(got, want) {
		t.Errorf("single-message transcript mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestTranscript_AccumulatesMultiple(t *testing.T) {
	ch := []byte("CH")
	sh := []byte("ServerHello-body-longer")
	ee := []byte{0x00, 0x00} // empty EncryptedExtensions body

	tr := NewTranscript()
	tr.AddMessage(HandshakeTypeClientHello, ch)
	tr.AddMessage(HandshakeTypeServerHello, sh)
	tr.AddMessage(HandshakeTypeEncryptedExtensions, ee)

	want := wantTranscript(t,
		struct {
			typ  uint8
			body []byte
		}{HandshakeTypeClientHello, ch},
		struct {
			typ  uint8
			body []byte
		}{HandshakeTypeServerHello, sh},
		struct {
			typ  uint8
			body []byte
		}{HandshakeTypeEncryptedExtensions, ee},
	)
	if got := tr.Sum(); !bytes.Equal(got, want) {
		t.Errorf("multi-message transcript mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestTranscript_SumPreservesState(t *testing.T) {
	tr := NewTranscript()
	tr.AddMessage(HandshakeTypeClientHello, []byte("A"))

	first := tr.Sum()
	// A second Sum with nothing added must be identical (state preserved).
	if again := tr.Sum(); !bytes.Equal(first, again) {
		t.Error("Sum altered running state (two consecutive Sum calls differ)")
	}
	// Adding another message changes the digest.
	tr.AddMessage(HandshakeTypeFinished, []byte("B"))
	if changed := tr.Sum(); bytes.Equal(first, changed) {
		t.Error("digest did not change after adding a second message")
	}
}

func TestTranscript_EmptyBody(t *testing.T) {
	// An empty body still contributes the 4-byte header to the transcript.
	tr := NewTranscript()
	tr.AddMessage(HandshakeTypeEncryptedExtensions, nil)
	want := wantTranscript(t, struct {
		typ  uint8
		body []byte
	}{HandshakeTypeEncryptedExtensions, nil})
	if got := tr.Sum(); !bytes.Equal(got, want) {
		t.Errorf("empty-body transcript mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestHandshakeHeaderRoundTrip(t *testing.T) {
	// Verify the message header framing round-trips and that ReadHandshakeMessage
	// reports the exact consumed length, so trailing bytes are not swallowed.
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	full := []byte{HandshakeTypeFinished, 0x00, 0x00, byte(len(body))}
	full = append(full, body...)
	trailing := []byte{0xAA, 0xBB}
	packet := append(full, trailing...)

	msgType, gotBody, n, err := ReadHandshakeMessage(packet)
	if err != nil {
		t.Fatalf("ReadHandshakeMessage: %v", err)
	}
	if msgType != HandshakeTypeFinished {
		t.Errorf("type: got %d want %d", msgType, HandshakeTypeFinished)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body: got %x want %x", gotBody, body)
	}
	if n != len(full) {
		t.Errorf("consumed: got %d want %d (trailing must be left untouched)", n, len(full))
	}
}

func TestReadHandshakeMessage_Truncated(t *testing.T) {
	cases := [][]byte{
		nil,
		{HandshakeTypeFinished},
		{HandshakeTypeFinished, 0x00},
		{HandshakeTypeFinished, 0x00, 0x00},
		// Declares 1 byte of body but none present.
		{HandshakeTypeFinished, 0x00, 0x00, 0x01},
	}
	for i, b := range cases {
		if _, _, _, err := ReadHandshakeMessage(b); err == nil {
			t.Errorf("case %d: expected error for truncated header", i)
		}
	}
}
