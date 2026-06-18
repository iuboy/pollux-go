package memsecure

import (
	"fmt"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty slice", []byte{}},
		{"single byte", []byte{0x42}},
		{"multiple bytes", []byte{0x01, 0x02, 0x03, 0xFF}},
		{"large slice", make([]byte, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with non-zero data if empty
			if len(tt.data) > 0 && tt.data[0] == 0 {
				for i := range tt.data {
					tt.data[i] = 0xFF
				}
			}

			// Save original length
			origLen := len(tt.data)
			origCap := cap(tt.data)

			// Zero the data
			ZeroBytes(tt.data)

			// Verify all bytes are zero
			for i, b := range tt.data {
				if b != 0 {
					t.Errorf("byte at index %d not zeroed: got 0x%02x", i, b)
				}
			}

			// Verify slice properties unchanged
			if len(tt.data) != origLen {
				t.Errorf("slice length changed: got %d, want %d", len(tt.data), origLen)
			}
			if cap(tt.data) != origCap {
				t.Errorf("slice capacity changed: got %d, want %d", cap(tt.data), origCap)
			}
		})
	}
}

func TestZeroBytes_Nil(t *testing.T) {
	// Should not panic on nil slice
	var data []byte
	ZeroBytes(data)
	// Should still be nil
	if data != nil {
		t.Error("nil slice became non-nil")
	}
}

func TestZeroUint32(t *testing.T) {
	data := []uint32{0x12345678, 0x9ABCDEF0, 0xFFFFFFFF}
	ZeroUint32(data)

	for i, v := range data {
		if v != 0 {
			t.Errorf("element at index %d not zeroed: got 0x%08x", i, v)
		}
	}
}

func TestZeroUint64(t *testing.T) {
	data := []uint64{0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF}
	ZeroUint64(data)

	for i, v := range data {
		if v != 0 {
			t.Errorf("element at index %d not zeroed: got 0x%016x", i, v)
		}
	}
}

// BenchmarkZeroBytes measures the performance of ZeroBytes.
func BenchmarkZeroBytes(b *testing.B) {
	sizes := []int{16, 32, 64, 128, 256, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				// Fill with non-zero data
				for j := range data {
					data[j] = 0xFF
				}
				ZeroBytes(data)
			}
		})
	}
}
