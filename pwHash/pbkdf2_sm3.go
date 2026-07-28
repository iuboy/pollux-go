package pwhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/iuboy/pollux-go/kdf"
	"github.com/iuboy/pollux-go/sm3"
)

// pbkdf2SM3Algo is the PHC-style scheme identifier prefix for pbkdf2-sm3 hashes.
const pbkdf2SM3Algo = "pbkdf2-sm3"

// PBKDF2SM3 implements [PasswordHasher] using PBKDF2-HMAC-SM3 (RFC 2898 with
// SM3 as the PRF, satisfying GM compliance regimes).
//
// The encoded format mirrors the PHC style used by argon2id but adapted for
// PBKDF2's single tunable parameter (iteration count):
//
//	$pbkdf2-sm3$i=<iter>$<raw-b64-salt>$<raw-b64-hash>
type PBKDF2SM3 struct {
	params PBKDF2Params
}

// NewPBKDF2SM3 constructs a pbkdf2-sm3 hasher with the given parameters.
// Use [DefaultPBKDF2SM3Params] unless you have a specific reason to deviate.
func NewPBKDF2SM3(p PBKDF2Params) *PBKDF2SM3 {
	return &PBKDF2SM3{params: p}
}

// Algorithm returns "pbkdf2-sm3".
func (h *PBKDF2SM3) Algorithm() string { return pbkdf2SM3Algo }

// Hash derives a PBKDF2-HMAC-SM3 digest from password and returns the
// PHC-style encoded string. A fresh random salt of params.SaltLength bytes is
// generated for each call via crypto/rand.
func (h *PBKDF2SM3) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pwhash/pbkdf2-sm3: %w", err)
	}
	dk, err := kdf.PBKDF2(
		[]byte(password), salt,
		h.params.Iterations, h.params.KeyLength, sm3.New,
	)
	if err != nil {
		return "", fmt.Errorf("pwhash/pbkdf2-sm3: %w", err)
	}
	return encodePBKDF2SM3(h.params, salt, dk), nil
}

// Verify returns true iff password matches the encoded pbkdf2-sm3 hash.
// The iteration count is read from the encoded string, so verification
// succeeds even if this instance was constructed with different parameters.
//
// The derived key is compared to the stored digest via
// subtle.ConstantTimeCompare so the result bit does not leak via timing.
func (h *PBKDF2SM3) Verify(password, encoded string) bool {
	params, salt, want, err := decodePBKDF2SM3(encoded)
	if err != nil {
		return false
	}
	got, err := kdf.PBKDF2(
		[]byte(password), salt,
		params.Iterations, params.KeyLength, sm3.New,
	)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether encoded was produced with parameters different
// from this hasher's current ones. Returns true for any non-pbkdf2-sm3 input
// (so callers can use it to drive algorithm migrations too).
func (h *PBKDF2SM3) NeedsRehash(encoded string) bool {
	params, _, _, err := decodePBKDF2SM3(encoded)
	if err != nil {
		return true
	}
	return params.Iterations != h.params.Iterations ||
		params.SaltLength != h.params.SaltLength ||
		params.KeyLength != h.params.KeyLength
}

// encodePBKDF2SM3 renders the PHC-style string.
func encodePBKDF2SM3(p PBKDF2Params, salt, dk []byte) string {
	return fmt.Sprintf(
		"$%s$i=%d$%s$%s",
		pbkdf2SM3Algo, p.Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	)
}

// decodePBKDF2SM3 parses a PHC-style pbkdf2-sm3 string into params + salt + digest.
func decodePBKDF2SM3(encoded string) (PBKDF2Params, []byte, []byte, error) {
	// Layout: $pbkdf2-sm3$i=<iter>$<b64-salt>$<b64-hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[1] != pbkdf2SM3Algo {
		return PBKDF2Params{}, nil, nil, ErrMalformedHash
	}
	if !strings.HasPrefix(parts[2], "i=") {
		return PBKDF2Params{}, nil, nil, ErrMalformedHash
	}
	iter, err := strconv.Atoi(strings.TrimPrefix(parts[2], "i="))
	if err != nil || iter <= 0 {
		return PBKDF2Params{}, nil, nil, fmt.Errorf("%w: bad iteration", ErrMalformedHash)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return PBKDF2Params{}, nil, nil, fmt.Errorf("%w: bad salt b64", ErrMalformedHash)
	}
	dk, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PBKDF2Params{}, nil, nil, fmt.Errorf("%w: bad hash b64", ErrMalformedHash)
	}
	return PBKDF2Params{
		Iterations: iter,
		SaltLength: len(salt),
		KeyLength:  len(dk),
	}, salt, dk, nil
}
