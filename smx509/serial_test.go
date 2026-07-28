package smx509

import (
	"math/big"
	"testing"
)

func TestGenerateSerialNumber_Range(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, err := GenerateSerialNumber()
		if err != nil {
			t.Fatalf("GenerateSerialNumber: %v", err)
		}
		if s.Sign() <= 0 {
			t.Fatalf("serial must be positive, got %v", s)
		}
		upper := new(big.Int).Lsh(big.NewInt(1), 160)
		if s.Cmp(upper) >= 0 {
			t.Fatalf("serial %v >= 2^160", s)
		}
		// 20-byte encoded length: serial must fit in 20 bytes.
		if len(s.Bytes()) > 20 {
			t.Fatalf("serial %v exceeds 20 bytes", s)
		}
	}
}

func TestGenerateSerialNumber_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		s, err := GenerateSerialNumber()
		if err != nil {
			t.Fatalf("GenerateSerialNumber: %v", err)
		}
		key := s.String()
		if seen[key] {
			t.Fatalf("duplicate serial %v at iteration %d", s, i)
		}
		seen[key] = true
	}
}
