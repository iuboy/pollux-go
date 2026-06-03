package sm3_test

import (
	"hash"
	"testing"

	"github.com/ycq/pollux/sm3"
)

func TestNewReturnsHashHash(t *testing.T) {
	var h hash.Hash = sm3.New()
	if h.Size() != sm3.Size {
		t.Errorf("Size() = %d, want %d", h.Size(), sm3.Size)
	}
	if h.BlockSize() != sm3.BlockSize {
		t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), sm3.BlockSize)
	}
}

func TestSum(t *testing.T) {
	_ = sm3.Sum([]byte("abc"))
}

func TestWriteAndSum(t *testing.T) {
	h := sm3.New()
	h.Write([]byte("abc"))
	got := h.Sum(nil)
	want := sm3.Sum([]byte("abc"))
	if string(got) != string(want[:]) {
		t.Errorf("incremental hash != one-shot hash")
	}
}

func TestReset(t *testing.T) {
	h := sm3.New()
	h.Write([]byte("abc"))
	h.Reset()
	h.Write([]byte("abc"))
	got := h.Sum(nil)
	want := sm3.Sum([]byte("abc"))
	if string(got) != string(want[:]) {
		t.Errorf("after Reset, hash mismatch")
	}
}
