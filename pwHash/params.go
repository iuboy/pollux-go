package pwhash

import "errors"

// Minimum parameter bounds enforced both at construction (H1) and when parsing
// untrusted PHC strings (C1). They are the floor below which a password hash
// either panics in the underlying primitive or loses its security properties
// (empty salt → rainbow tables; zero iterations → no work factor).
const (
	// minSaltLength is the smallest salt we consider safe. 8 bytes (64 bits)
	// is the absolute floor for collision resistance across a credential
	// store; 16 is the recommended default.
	minSaltLength = 8

	// minKeyLength is the smallest derived-key length we accept. Anything
	// shorter undermines the hash's preimage resistance.
	minKeyLength = 16

	// minArgon2Memory is the smallest memory cost (in KiB) we allow. argon2's
	// own floor is 8*p KiB; 4 MiB keeps unit-test params valid while still
	// being meaningfully memory-hard.
	minArgon2Memory = 4 * 1024

	// maxPBKDF2Iteration mirrors kdf.maxIteration so a hasher configured here
	// agrees with the bound enforced inside kdf.PBKDF2.
	maxPBKDF2Iteration = 10_000_000
)

// Argon2idParams configures the argon2id memory-hard password hash.
//
// The defaults match the OWASP 2023 recommendation for typical servers:
// m=64 MiB, t=3, p=2. Tune m down for memory-constrained environments;
// never tune t below 1 or p below 1.
type Argon2idParams struct {
	// Memory in KiB. 65536 = 64 MiB (OWASP minimum as of 2023).
	Memory uint32
	// Iterations (time cost). 3 is the OWASP-recommended starting point.
	Iterations uint32
	// Parallelism (lanes). 2 is a reasonable default for typical servers.
	// The same value must be used at verify time (it is embedded in the
	// encoded hash, so verify auto-adapts).
	Parallelism uint8
	// SaltLength in bytes. 16 is the standard.
	SaltLength uint32
	// KeyLength in bytes. 32 is the standard (matches SM3/SHA-256 output).
	KeyLength uint32
}

// Validate returns an error if any parameter is outside the safe range. It is
// enforced at construction (NewArgon2id) and when parsing untrusted PHC
// strings (decodeArgon2id), so a misconfigured hasher or an attacker-crafted
// hash cannot reach argon2.IDKey — which panics on zero cost parameters.
func (p Argon2idParams) Validate() error {
	switch {
	case p.Memory < minArgon2Memory:
		return errors.New("pwhash: argon2id memory must be at least 4 MiB (4096 KiB)")
	case p.Iterations == 0:
		return errors.New("pwhash: argon2id iterations must be positive")
	case p.Parallelism == 0:
		return errors.New("pwhash: argon2id parallelism must be positive")
	case p.SaltLength < minSaltLength:
		return errors.New("pwhash: argon2id salt length must be at least 8 bytes")
	case p.KeyLength < minKeyLength:
		return errors.New("pwhash: argon2id key length must be at least 16 bytes")
	}
	return nil
}

// DefaultArgon2idParams returns OWASP-recommended argon2id parameters.
//
//	memory=64 MiB, iterations=3, parallelism=2, salt=16B, key=32B
//
// At ~100ms per hash on 2024-era server hardware, this is the right
// cost/UX tradeoff for online password verification.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// PBKDF2Params configures a PBKDF2 password hash.
//
// PBKDF2 is not memory-hard; its strength comes entirely from the iteration
// count. The defaults compensate by setting a high iteration count suitable
// for ~100ms derivation on 2024-era hardware. The hash algorithm (PRF) is
// selected by the hasher type (e.g. [PBKDF2SM3] for SM3); this struct only
// holds the tunable cost parameters.
type PBKDF2Params struct {
	// Iterations. 200000 is the default for SM3/SHA-256 to match the
	// ~100ms online-verification baseline. NIST SP 800-132 recommends at
	// least 1000; OWASP recommends ≥600000 for PBKDF2-HMAC-SHA-256 as of
	// 2023. SM3 is slower per iteration than SHA-256, so 200000 with SM3
	// gives comparable wall-clock cost.
	Iterations int
	// SaltLength in bytes. 16 is the standard.
	SaltLength int
	// KeyLength in bytes. 32 matches SM3/SHA-256 output.
	KeyLength int
}

// Validate returns an error if any parameter is outside the safe range. It is
// enforced at construction (NewPBKDF2SM3). An upper bound on iterations mirrors
// the one in kdf.PBKDF2 so a misconfigured hasher fails fast rather than
// stalling on the first Hash/Verify call.
func (p PBKDF2Params) Validate() error {
	switch {
	case p.Iterations < 1:
		return errors.New("pwhash: pbkdf2 iterations must be positive")
	case p.Iterations > maxPBKDF2Iteration:
		return errors.New("pwhash: pbkdf2 iterations exceed safe upper bound")
	case p.SaltLength < minSaltLength:
		return errors.New("pwhash: pbkdf2 salt length must be at least 8 bytes")
	case p.KeyLength < minKeyLength:
		return errors.New("pwhash: pbkdf2 key length must be at least 16 bytes")
	}
	return nil
}

// DefaultPBKDF2SM3Params returns default PBKDF2-HMAC-SM3 parameters.
func DefaultPBKDF2SM3Params() PBKDF2Params {
	return PBKDF2Params{
		Iterations: 200000,
		SaltLength: 16,
		KeyLength:  32,
	}
}
