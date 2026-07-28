package pwhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2idAlgo is the PHC scheme identifier prefix for argon2id hashes.
const argon2idAlgo = "argon2id"

// Argon2id implements [PasswordHasher] using argon2id (RFC 9106).
//
// The encoded format follows the PHC standard:
//
//	$argon2id$v=19$m=<KiB>,t=<iter>,p=<par>$<raw-b64-salt>$<raw-b64-hash>
type Argon2id struct {
	params Argon2idParams
}

// NewArgon2id constructs an argon2id hasher with the given parameters.
// Use [DefaultArgon2idParams] unless you have a specific reason to deviate.
//
// Returns an error if any parameter is outside the safe range — this is the
// fail-fast boundary so a misconfigured hasher never reaches [Argon2id.Hash],
// where the underlying argon2 primitive would panic on zero cost parameters.
func NewArgon2id(p Argon2idParams) (*Argon2id, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Argon2id{params: p}, nil
}

// Algorithm returns "argon2id".
func (h *Argon2id) Algorithm() string { return argon2idAlgo }

// Hash derives an argon2id digest from password and returns the PHC-encoded
// string. A fresh random salt of params.SaltLength bytes is generated for
// each call via crypto/rand.
func (h *Argon2id) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := readRandom(salt); err != nil {
		return "", fmt.Errorf("pwhash/argon2id: %w", err)
	}
	dk := argon2.IDKey(
		[]byte(password), salt,
		h.params.Iterations, h.params.Memory, h.params.Parallelism,
		h.params.KeyLength,
	)
	return encodeArgon2id(h.params, salt, dk), nil
}

// Verify returns true iff password matches the encoded argon2id hash.
// Parameters are read from the encoded string, so verification succeeds
// even if this instance was constructed with different parameters than the
// one that produced the hash.
//
// The comparison of the derived key against the stored digest uses
// subtle.ConstantTimeCompare so the result bit does not leak via timing.
func (h *Argon2id) Verify(password, encoded string) bool {
	params, salt, want, err := decodeArgon2id(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey(
		[]byte(password), salt,
		params.Iterations, params.Memory, params.Parallelism,
		params.KeyLength,
	)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether encoded was produced with parameters different
// from this hasher's current ones. Returns true for any non-argon2id input
// (so callers can use it to drive algorithm migrations too).
func (h *Argon2id) NeedsRehash(encoded string) bool {
	params, _, _, err := decodeArgon2id(encoded)
	if err != nil {
		return true
	}
	return params != h.params
}

// encodeArgon2id renders the PHC string.
func encodeArgon2id(p Argon2idParams, salt, dk []byte) string {
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2idAlgo, argon2.Version,
		p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	)
}

// decodeArgon2id parses a PHC argon2id string into parameters + salt + digest.
func decodeArgon2id(encoded string) (Argon2idParams, []byte, []byte, error) {
	// Layout: $argon2id$v=<ver>$m=<>,t=<>,p=<>$<b64-salt>$<b64-hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != argon2idAlgo {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}
	ver, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "v="), 10, 32)
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrMalformedHash
	}
	if ver != argon2.Version {
		return Argon2idParams{}, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrMalformedHash, ver)
	}

	params, err := parseArgon2idParamBlock(parts[3])
	if err != nil {
		return Argon2idParams{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("%w: bad salt b64", ErrMalformedHash)
	}
	dk, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("%w: bad hash b64", ErrMalformedHash)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(dk))

	// Defense against attacker-controlled PHC: argon2.IDKey panics (not errors)
	// on time<1 or threads<1, and a zero KeyLength dereferences nil internally.
	// Reject these up-front so Verify never crashes on untrusted input.
	if err := params.validateDecoded(len(salt), len(dk)); err != nil {
		return Argon2idParams{}, nil, nil, err
	}

	return params, salt, dk, nil
}

// validateDecoded checks that parameters parsed from a PHC string are safe to
// feed to argon2.IDKey. It is the security boundary between untrusted encoded
// input and the underlying C-less argon2 implementation, which panics on
// out-of-range cost parameters.
func (p Argon2idParams) validateDecoded(saltLen, keyLen int) error {
	switch {
	case p.Memory == 0:
		return fmt.Errorf("%w: memory must be positive", ErrMalformedHash)
	case p.Iterations == 0:
		return fmt.Errorf("%w: iterations must be positive", ErrMalformedHash)
	case p.Parallelism == 0:
		return fmt.Errorf("%w: parallelism must be positive", ErrMalformedHash)
	case keyLen == 0:
		return fmt.Errorf("%w: hash must be non-empty", ErrMalformedHash)
	case saltLen < minSaltLength:
		return fmt.Errorf("%w: salt too short", ErrMalformedHash)
	}
	return nil
}

// parseArgon2idParamBlock parses "m=<>,t=<>,p=<>" into Argon2idParams.
func parseArgon2idParamBlock(block string) (Argon2idParams, error) {
	var p Argon2idParams
	gotM, gotT, gotP := false, false, false
	for _, kv := range strings.Split(block, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			return Argon2idParams{}, fmt.Errorf("%w: bad param %q", ErrMalformedHash, kv)
		}
		k, v := kv[:eq], kv[eq+1:]
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Argon2idParams{}, fmt.Errorf("%w: bad param value %q", ErrMalformedHash, kv)
		}
		switch k {
		case "m":
			p.Memory = uint32(n)
			gotM = true
		case "t":
			p.Iterations = uint32(n)
			gotT = true
		case "p":
			// Reject p > 255 rather than silently truncating via uint8(n); a
			// truncated parallelism would silently disagree with the issuer.
			if n > 255 {
				return Argon2idParams{}, fmt.Errorf("%w: parallelism out of range", ErrMalformedHash)
			}
			p.Parallelism = uint8(n)
			gotP = true
		default:
			return Argon2idParams{}, fmt.Errorf("%w: unknown param %q", ErrMalformedHash, k)
		}
	}
	if !(gotM && gotT && gotP) {
		return Argon2idParams{}, fmt.Errorf("%w: missing m/t/p", ErrMalformedHash)
	}
	return p, nil
}

// ErrMalformedHash is returned when an encoded hash cannot be parsed.
var ErrMalformedHash = errors.New("pwhash: malformed encoded hash")

// readRandom fills b with cryptographically secure random bytes. It is a
// package-level variable (not a plain func) so tests can replace it with a
// deterministic source via `readRandom = mockRead`. Production uses
// crypto/rand.Read.
var readRandom = rand.Read
