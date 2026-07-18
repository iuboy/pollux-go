package pwhash

import (
	"strings"
	"testing"
)

// lightArgon2idParams keeps tests fast (default 64MiB×3 is ~100ms each).
// Tests assert correctness of the encode/decode/verify logic, not the
// strength of the parameters.
func lightArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      4 * 1024, // 4 MiB
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// ─── argon2id ───

func TestArgon2id_RoundTrip(t *testing.T) {
	h := NewArgon2id(lightArgon2idParams())
	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash err = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Errorf("encoded = %q, want $argon2id$ prefix", encoded)
	}
	if !h.Verify("correct horse battery staple", encoded) {
		t.Error("Verify rejected the correct password")
	}
}

func TestArgon2id_RejectsWrongPassword(t *testing.T) {
	h := NewArgon2id(lightArgon2idParams())
	encoded, _ := h.Hash("right-password")
	if h.Verify("wrong-password", encoded) {
		t.Error("Verify accepted the wrong password")
	}
}

func TestArgon2id_UniqueSaltPerHash(t *testing.T) {
	h := NewArgon2id(lightArgon2idParams())
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Error("two hashes of same password are identical (salt not random?)")
	}
}

func TestArgon2id_VerifyAdaptsToDifferentParams(t *testing.T) {
	// Hash with light params; verify with a differently-configured instance.
	// The hash embeds its own params, so verify must use those, not the
	// instance's.
	h1 := NewArgon2id(Argon2idParams{Memory: 4 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	encoded, _ := h1.Hash("pw")
	h2 := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
	if !h2.Verify("pw", encoded) {
		t.Error("Verify with different instance params failed on hash from h1")
	}
}

func TestArgon2id_NeedsRehash_DifferentParams(t *testing.T) {
	light := lightArgon2idParams()
	h := NewArgon2id(light)
	encoded, _ := h.Hash("pw")
	if h.NeedsRehash(encoded) {
		t.Error("NeedsRehash true for hash produced with same params")
	}
	// Bump parameters; the old hash should now need rehash.
	h.params.Iterations = light.Iterations + 1
	if !h.NeedsRehash(encoded) {
		t.Error("NeedsRehash false after bumping iterations")
	}
}

func TestArgon2id_NeedsRehash_ForeignAlgorithm(t *testing.T) {
	h := NewArgon2id(lightArgon2idParams())
	// A pbkdf2-sm3 hash should report NeedsRehash (drives algorithm migration).
	if !h.NeedsRehash("$pbkdf2-sm3$i=1000$sg$sg") {
		t.Error("NeedsRehash false for foreign-algorithm hash")
	}
}

func TestArgon2id_VerifyRejectsMalformed(t *testing.T) {
	h := NewArgon2id(lightArgon2idParams())
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$garbage",
		"$argon2id$v=99$m=1,t=1,p=1$x$x", // bad version
		"$pbkdf2-sm3$i=1000$x$x",          // wrong scheme
	} {
		if h.Verify("any", bad) {
			t.Errorf("Verify unexpectedly accepted %q", bad)
		}
	}
}

func TestArgon2id_Algorithm(t *testing.T) {
	if NewArgon2id(lightArgon2idParams()).Algorithm() != "argon2id" {
		t.Error("Algorithm() != argon2id")
	}
}

// ─── pbkdf2-sm3 ───

func TestPBKDF2SM3_RoundTrip(t *testing.T) {
	// Light iterations for test speed; production uses 200000.
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	encoded, err := h.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash err = %v", err)
	}
	if !strings.HasPrefix(encoded, "$pbkdf2-sm3$") {
		t.Errorf("encoded = %q, want $pbkdf2-sm3$ prefix", encoded)
	}
	if !h.Verify("hunter2", encoded) {
		t.Error("Verify rejected the correct password")
	}
}

func TestPBKDF2SM3_RejectsWrongPassword(t *testing.T) {
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	encoded, _ := h.Hash("right")
	if h.Verify("wrong", encoded) {
		t.Error("Verify accepted the wrong password")
	}
}

func TestPBKDF2SM3_UniqueSaltPerHash(t *testing.T) {
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 500, SaltLength: 16, KeyLength: 32})
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Error("two hashes of same password are identical (salt not random?)")
	}
}

func TestPBKDF2SM3_VerifyAdaptsToDifferentParams(t *testing.T) {
	// Hash with 1000 iters; verify with an instance configured for 5000.
	// The hash embeds its own iteration count, so verify must use it.
	h1 := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	encoded, _ := h1.Hash("pw")
	h2 := NewPBKDF2SM3(PBKDF2Params{Iterations: 5000, SaltLength: 16, KeyLength: 32})
	if !h2.Verify("pw", encoded) {
		t.Error("Verify with different instance iterations failed on hash from h1")
	}
}

func TestPBKDF2SM3_NeedsRehash_DifferentParams(t *testing.T) {
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	encoded, _ := h.Hash("pw")
	if h.NeedsRehash(encoded) {
		t.Error("NeedsRehash true for hash produced with same params")
	}
	h.params.Iterations = 5000
	if !h.NeedsRehash(encoded) {
		t.Error("NeedsRehash false after bumping iterations")
	}
}

func TestPBKDF2SM3_NeedsRehash_ForeignAlgorithm(t *testing.T) {
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	if !h.NeedsRehash("$argon2id$v=19$m=1,t=1,p=1$x$x") {
		t.Error("NeedsRehash false for foreign-algorithm hash")
	}
}

func TestPBKDF2SM3_VerifyRejectsMalformed(t *testing.T) {
	h := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$pbkdf2-sm3$x$x",                 // missing iteration
		"$pbkdf2-sm3$i=0$x$x",             // non-positive iteration
		"$pbkdf2-sm3$i=1000$",             // truncated
		"$argon2id$v=19$m=1,t=1,p=1$x$x",  // wrong scheme
	} {
		if h.Verify("any", bad) {
			t.Errorf("Verify unexpectedly accepted %q", bad)
		}
	}
}

func TestPBKDF2SM3_Algorithm(t *testing.T) {
	if NewPBKDF2SM3(PBKDF2Params{}).Algorithm() != "pbkdf2-sm3" {
		t.Error("Algorithm() != pbkdf2-sm3")
	}
}

// ─── interface conformance ───

func TestBothImplementPasswordHasher(t *testing.T) {
	// Compile-time check: both types satisfy the interface.
	var _ PasswordHasher = (*Argon2id)(nil)
	var _ PasswordHasher = (*PBKDF2SM3)(nil)
}

// TestCrossAlgorithmVerifyFails ensures Verify is scheme-specific: an argon2id
// hash must NOT verify via a pbkdf2-sm3 hasher and vice versa. This guards
// against accidental fallthrough in a future unified dispatcher.
func TestCrossAlgorithmVerifyFails(t *testing.T) {
	argon := NewArgon2id(lightArgon2idParams())
	pbkdf := NewPBKDF2SM3(PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32})

	aEnc, _ := argon.Hash("shared-secret")
	pEnc, _ := pbkdf.Hash("shared-secret")

	if pbkdf.Verify("shared-secret", aEnc) {
		t.Error("pbkdf2-sm3 accepted an argon2id hash")
	}
	if argon.Verify("shared-secret", pEnc) {
		t.Error("argon2id accepted a pbkdf2-sm3 hash")
	}
}
