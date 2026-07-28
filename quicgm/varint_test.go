package quicgm

import (
	"bytes"
	"testing"
)

func TestAppendVarint_Boundaries(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{63, []byte{0x3f}},
		{64, []byte{0x40, 0x40}},                     // first 2-octet value
		{16383, []byte{0x7f, 0xff}},                  // max 2-octet
		{16384, []byte{0x80, 0x00, 0x40, 0x00}},      // first 4-octet value
		{1073741823, []byte{0xbf, 0xff, 0xff, 0xff}}, // max 4-octet
	}
	for _, c := range cases {
		got, err := AppendVarint(nil, c.v)
		if err != nil {
			t.Errorf("AppendVarint(%d): %v", c.v, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("AppendVarint(%d): got %x, want %x", c.v, got, c.want)
		}
		if len(got) != VarintLen(c.v) {
			t.Errorf("VarintLen(%d)=%d, encoded len=%d", c.v, VarintLen(c.v), len(got))
		}
	}
}

func TestAppendVarint_EightOctetMax(t *testing.T) {
	got, err := AppendVarint(nil, MaxVarint)
	if err != nil {
		t.Fatalf("AppendVarint(MaxVarint): %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("encoded len: got %d, want 8", len(got))
	}
	if got[0]&0xc0 != 0xc0 {
		t.Errorf("first octet prefix: got %#x, want 0xc0", got[0]&0xc0)
	}
	if _, err := AppendVarint(nil, MaxVarint+1); err == nil {
		t.Error("value above MaxVarint should be rejected")
	}
}

// TestVarint_RoundTrip exercises encode -> decode for representative values,
// including the RFC 9000 §16 examples.
func TestVarint_RoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 37, 63, 64, 15293, 16383, 16384, 494878333, 1073741823,
		1073741824, 151288809941772709, MaxVarint,
	}
	for _, v := range values {
		buf, err := AppendVarint(nil, v)
		if err != nil {
			t.Fatalf("AppendVarint(%d): %v", v, err)
		}
		got, n, err := ReadVarint(buf)
		if err != nil {
			t.Fatalf("ReadVarint(%d): %v", v, err)
		}
		if got != v {
			t.Errorf("round-trip: got %d, want %d", got, v)
		}
		if n != len(buf) {
			t.Errorf("consumed: got %d, want %d", n, len(buf))
		}
	}
}

func TestReadVarint_FollowingBytesPreserved(t *testing.T) {
	// A varint at the start of a longer buffer must consume only its own length.
	buf, _ := AppendVarint(nil, 15293) // 0x7b 0xbd (RFC 9000 §16 example, 2 octets)
	buf = append(buf, 0xAA, 0xBB)
	v, n, err := ReadVarint(buf)
	if err != nil {
		t.Fatal(err)
	}
	if v != 15293 || n != 2 {
		t.Errorf("got (%d, %d), want (15293, 2)", v, n)
	}
	if !bytes.Equal(buf[n:], []byte{0xAA, 0xBB}) {
		t.Errorf("trailing bytes altered: %x", buf[n:])
	}
}

func TestReadVarint_Errors(t *testing.T) {
	if _, _, err := ReadVarint(nil); err == nil {
		t.Error("empty buffer should error")
	}
	if _, _, err := ReadVarint([]byte{0x40}); err == nil {
		t.Error("truncated 2-octet varint should error")
	}
	if _, _, err := ReadVarint([]byte{0xc0, 0, 0, 0}); err == nil {
		t.Error("truncated 8-octet varint should error")
	}
}
