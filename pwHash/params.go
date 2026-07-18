package pwhash

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
// for ~100ms derivation on 2024-era hardware. The Hash field selects the PRF:
//
//   - "sm3":   GM compliance (pbkdf2-sm3 hasher)
//   - "sha256": international baseline (pbkdf2-sha256 hasher, if added later)
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

// DefaultPBKDF2SM3Params returns default PBKDF2-HMAC-SM3 parameters.
func DefaultPBKDF2SM3Params() PBKDF2Params {
	return PBKDF2Params{
		Iterations: 200000,
		SaltLength: 16,
		KeyLength:  32,
	}
}
