package kdf

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/iuboy/pollux-go/sm3"
)

// RFC 6070 PBKDF2-HMAC-SHA-1 vectors. SHA-1 is used purely as a test PRF —
// the implementation is hash-agnostic, so SHA-1 vectors cross-check the
// exact RFC reference while the production path uses SHA-256 or SM3.

func TestPBKDF2_RFC6070(t *testing.T) {
	cases := []struct {
		name     string
		password string
		salt     string
		iter     int
		keyLen   int
		wantHex  string
	}{
		{"1 cbc", "password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"2 cbc", "password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"4096 cbc", "password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"4096 cbc 25 bytes", "passwordPASSWORDpassword",
			"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
			"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		// Low-overhead vector for slow CI; 16777216 cbc vector omitted.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PBKDF2([]byte(tc.password), []byte(tc.salt), tc.iter, tc.keyLen, sha1.New)
			if err != nil {
				t.Fatalf("PBKDF2 err = %v", err)
			}
			want, _ := hex.DecodeString(tc.wantHex)
			if !bytes.Equal(got, want) {
				t.Errorf("PBKDF2 = %x, want %x", got, want)
			}
		})
	}
}

func TestPBKDF2_RejectsNonPositiveIter(t *testing.T) {
	_, err := PBKDF2([]byte("p"), []byte("s"), 0, 16, sha256.New)
	if !errors.Is(err, ErrInvalidIteration) {
		t.Errorf("err = %v, want ErrInvalidIteration", err)
	}
}

func TestPBKDF2_RejectsNonPositiveKeyLen(t *testing.T) {
	_, err := PBKDF2([]byte("p"), []byte("s"), 100, 0, sha256.New)
	if !errors.Is(err, ErrInvalidKeyLen) {
		t.Errorf("err = %v, want ErrInvalidKeyLen", err)
	}
}

func TestPBKDF2_RejectsNilHashFactory(t *testing.T) {
	_, err := PBKDF2([]byte("p"), []byte("s"), 100, 16, nil)
	if err == nil {
		t.Error("nil hash factory unexpectedly succeeded")
	}
}

// TestPBKDF2_SM3Deterministic ensures the SM3 path produces stable output.
// SM3 has no RFC vector for PBKDF2, so the assertion is structural: the same
// inputs must yield the same output, and a different password must not.
func TestPBKDF2_SM3Deterministic(t *testing.T) {
	dk1, err := PBKDF2([]byte("password"), []byte("salt"), 1000, 32, sm3.New)
	if err != nil {
		t.Fatalf("PBKDF2 sm3 err = %v", err)
	}
	if len(dk1) != 32 {
		t.Fatalf("dk len = %d, want 32", len(dk1))
	}
	dk2, _ := PBKDF2([]byte("password"), []byte("salt"), 1000, 32, sm3.New)
	if !bytes.Equal(dk1, dk2) {
		t.Error("PBKDF2 sm3 not deterministic for identical inputs")
	}
	dk3, _ := PBKDF2([]byte("different"), []byte("salt"), 1000, 32, sm3.New)
	if bytes.Equal(dk1, dk3) {
		t.Error("different password produced same derived key")
	}
}

// TestPBKDF2_DifferentHashesProduceDifferentKeys confirms the hash factory
// actually drives the PRF — switching SHA-256 ↔ SM3 must change the output.
func TestPBKDF2_DifferentHashesProduceDifferentKeys(t *testing.T) {
	const (
		pwd    = "password"
		salt   = "salt"
		iter   = 1000
		keyLen = 32
	)
	dkSHA, _ := PBKDF2([]byte(pwd), []byte(salt), iter, keyLen, sha256.New)
	dkSM3, _ := PBKDF2([]byte(pwd), []byte(salt), iter, keyLen, sm3.New)
	if bytes.Equal(dkSHA, dkSM3) {
		t.Error("SHA-256 and SM3 PBKDF2 outputs are identical (hash factory ignored?)")
	}
}

func TestPBKDF2_LongerKeySpansMultipleBlocks(t *testing.T) {
	// SHA-256 block size = 32; request 70 bytes to force 3 blocks.
	dk, err := PBKDF2([]byte("p"), []byte("s"), 10, 70, sha256.New)
	if err != nil {
		t.Fatalf("PBKDF2 err = %v", err)
	}
	if len(dk) != 70 {
		t.Errorf("dk len = %d, want 70", len(dk))
	}
}

// TestPBKDF2_KeyLenSmallerThanHashSize verifies the truncation path.
func TestPBKDF2_KeyLenSmallerThanHashSize(t *testing.T) {
	dk, err := PBKDF2([]byte("p"), []byte("s"), 100, 5, sha256.New)
	if err != nil {
		t.Fatalf("PBKDF2 err = %v", err)
	}
	if len(dk) != 5 {
		t.Errorf("dk len = %d, want 5", len(dk))
	}
}
