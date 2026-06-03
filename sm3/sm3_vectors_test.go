package sm3_test

import (
	"encoding/hex"
	"testing"

	"github.com/ycq/pollux/sm3"
)

// GM/T 0004-2012 标准测试向量

func TestVectors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantHex string
	}{
		{
			name:    "abc",
			input:   "616263",
			wantHex: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
		},
		{
			name:    "empty",
			input:   "",
			wantHex: "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		},
		{
			name:    "repeated abcd pattern (16 bytes)",
			input:   "61626364616263646162636461626364",
			wantHex: "639c6f6b30d93ecebd559a953ba2eb72705db7d2be82bbf32979380e02124971",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input []byte
			if tt.input != "" {
				var err error
				input, err = hex.DecodeString(tt.input)
				if err != nil {
					t.Fatalf("invalid hex input: %v", err)
				}
			}

			// Test one-shot Sum
			got := sm3.Sum(input)
			gotHex := hex.EncodeToString(got[:])
			if gotHex != tt.wantHex {
				t.Errorf("Sum()\ninput:  %s\ngot:    %s\nexpect: %s", tt.input, gotHex, tt.wantHex)
			}

			// Test streaming New
			h := sm3.New()
			h.Write(input)
			streamGot := h.Sum(nil)
			streamHex := hex.EncodeToString(streamGot)
			if streamHex != tt.wantHex {
				t.Errorf("New().Sum()\ninput:  %s\ngot:    %s\nexpect: %s", tt.input, streamHex, tt.wantHex)
			}
		})
	}
}

func TestStreamingConsistency(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	// One-shot
	oneshot := sm3.Sum(data)

	// Byte-by-byte
	h := sm3.New()
	for _, b := range data {
		h.Write([]byte{b})
	}
	streaming := h.Sum(nil)

	if hex.EncodeToString(oneshot[:]) != hex.EncodeToString(streaming) {
		t.Error("byte-by-byte streaming does not match one-shot Sum")
	}
}

func TestBlockBoundary(t *testing.T) {
	// SM3 block size is 64 bytes. Test values at boundaries.
	for _, size := range []int{55, 56, 63, 64, 65, 127, 128, 129} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i)
		}

		// Ensure no panic and consistent results
		h1 := sm3.New()
		h1.Write(data)
		d1 := h1.Sum(nil)

		h2 := sm3.New()
		h2.Write(data)
		d2 := h2.Sum(nil)

		if hex.EncodeToString(d1) != hex.EncodeToString(d2) {
			t.Errorf("inconsistent hash for size %d", size)
		}
	}
}
