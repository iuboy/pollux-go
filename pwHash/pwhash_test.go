package pwhash

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
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

// mustArgon2id wraps NewArgon2id for tests that use known-good params; the
// error return is real (H1), but a test fixture never misconfigures it.
func mustArgon2id(t *testing.T, p Argon2idParams) *Argon2id {
	t.Helper()
	h, err := NewArgon2id(p)
	if err != nil {
		t.Fatalf("NewArgon2id(%+v) err = %v", p, err)
	}
	return h
}

// mustPBKDF2SM3 is the pbkdf2-sm3 analogue of mustArgon2id.
func mustPBKDF2SM3(t *testing.T, p PBKDF2Params) *PBKDF2SM3 {
	t.Helper()
	h, err := NewPBKDF2SM3(p)
	if err != nil {
		t.Fatalf("NewPBKDF2SM3(%+v) err = %v", p, err)
	}
	return h
}

// lightPBKDF2Params returns the standard light fixture used across pbkdf2 tests.
func lightPBKDF2Params() PBKDF2Params {
	return PBKDF2Params{Iterations: 1000, SaltLength: 16, KeyLength: 32}
}

// ─── argon2id ───

func TestArgon2id_RoundTrip(t *testing.T) {
	h := mustArgon2id(t, lightArgon2idParams())
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
	h := mustArgon2id(t, lightArgon2idParams())
	encoded, _ := h.Hash("right-password")
	if h.Verify("wrong-password", encoded) {
		t.Error("Verify accepted the wrong password")
	}
}

func TestArgon2id_UniqueSaltPerHash(t *testing.T) {
	h := mustArgon2id(t, lightArgon2idParams())
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
	h1 := mustArgon2id(t, Argon2idParams{Memory: 4 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	encoded, _ := h1.Hash("pw")
	h2 := mustArgon2id(t, Argon2idParams{Memory: 8 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
	if !h2.Verify("pw", encoded) {
		t.Error("Verify with different instance params failed on hash from h1")
	}
}

func TestArgon2id_NeedsRehash_DifferentParams(t *testing.T) {
	light := lightArgon2idParams()
	h := mustArgon2id(t, light)
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
	h := mustArgon2id(t, lightArgon2idParams())
	// A pbkdf2-sm3 hash should report NeedsRehash (drives algorithm migration).
	if !h.NeedsRehash("$pbkdf2-sm3$i=1000$sg$sg") {
		t.Error("NeedsRehash false for foreign-algorithm hash")
	}
}

func TestArgon2id_VerifyRejectsMalformed(t *testing.T) {
	h := mustArgon2id(t, lightArgon2idParams())
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$garbage",
		"$argon2id$v=99$m=1,t=1,p=1$x$x", // bad version
		"$pbkdf2-sm3$i=1000$x$x",         // wrong scheme
	} {
		if h.Verify("any", bad) {
			t.Errorf("Verify unexpectedly accepted %q", bad)
		}
	}
}

func TestArgon2id_Algorithm(t *testing.T) {
	if mustArgon2id(t, lightArgon2idParams()).Algorithm() != "argon2id" {
		t.Error("Algorithm() != argon2id")
	}
}

// ─── pbkdf2-sm3 ───

func TestPBKDF2SM3_RoundTrip(t *testing.T) {
	// Light iterations for test speed; production uses 200000.
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
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
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
	encoded, _ := h.Hash("right")
	if h.Verify("wrong", encoded) {
		t.Error("Verify accepted the wrong password")
	}
}

func TestPBKDF2SM3_UniqueSaltPerHash(t *testing.T) {
	h := mustPBKDF2SM3(t, PBKDF2Params{Iterations: 500, SaltLength: 16, KeyLength: 32})
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Error("two hashes of same password are identical (salt not random?)")
	}
}

func TestPBKDF2SM3_VerifyAdaptsToDifferentParams(t *testing.T) {
	// Hash with 1000 iters; verify with an instance configured for 5000.
	// The hash embeds its own iteration count, so verify must use it.
	h1 := mustPBKDF2SM3(t, lightPBKDF2Params())
	encoded, _ := h1.Hash("pw")
	h2 := mustPBKDF2SM3(t, PBKDF2Params{Iterations: 5000, SaltLength: 16, KeyLength: 32})
	if !h2.Verify("pw", encoded) {
		t.Error("Verify with different instance iterations failed on hash from h1")
	}
}

func TestPBKDF2SM3_NeedsRehash_DifferentParams(t *testing.T) {
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
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
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
	if !h.NeedsRehash("$argon2id$v=19$m=1,t=1,p=1$x$x") {
		t.Error("NeedsRehash false for foreign-algorithm hash")
	}
}

func TestPBKDF2SM3_VerifyRejectsMalformed(t *testing.T) {
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$pbkdf2-sm3$x$x",                // missing iteration
		"$pbkdf2-sm3$i=0$x$x",            // non-positive iteration
		"$pbkdf2-sm3$i=1000$",            // truncated
		"$argon2id$v=19$m=1,t=1,p=1$x$x", // wrong scheme
	} {
		if h.Verify("any", bad) {
			t.Errorf("Verify unexpectedly accepted %q", bad)
		}
	}
}

func TestPBKDF2SM3_Algorithm(t *testing.T) {
	if mustPBKDF2SM3(t, lightPBKDF2Params()).Algorithm() != "pbkdf2-sm3" {
		t.Error("Algorithm() != pbkdf2-sm3")
	}
}

// TestNewArgon2id_RejectsInvalidParams covers H1: the constructor validates
// parameters fail-fast rather than letting a misconfigured hasher reach Hash
// (where argon2 would panic) or produce an empty-salt hash.
func TestNewArgon2id_RejectsInvalidParams(t *testing.T) {
	good := lightArgon2idParams()
	cases := []struct {
		name string
		mut  func(Argon2idParams) Argon2idParams
	}{
		{"memory too low", func(p Argon2idParams) Argon2idParams { p.Memory = 1024; return p }},
		{"zero iterations", func(p Argon2idParams) Argon2idParams { p.Iterations = 0; return p }},
		{"zero parallelism", func(p Argon2idParams) Argon2idParams { p.Parallelism = 0; return p }},
		{"salt too short", func(p Argon2idParams) Argon2idParams { p.SaltLength = 4; return p }},
		{"key too short", func(p Argon2idParams) Argon2idParams { p.KeyLength = 8; return p }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewArgon2id(c.mut(good)); err == nil {
				t.Errorf("NewArgon2id accepted %s", c.name)
			}
		})
	}
}

// TestNewPBKDF2SM3_RejectsInvalidParams covers H1 for the pbkdf2 variant.
func TestNewPBKDF2SM3_RejectsInvalidParams(t *testing.T) {
	good := lightPBKDF2Params()
	cases := []struct {
		name string
		mut  func(PBKDF2Params) PBKDF2Params
	}{
		{"zero iterations", func(p PBKDF2Params) PBKDF2Params { p.Iterations = 0; return p }},
		{"excessive iterations", func(p PBKDF2Params) PBKDF2Params { p.Iterations = maxPBKDF2Iteration + 1; return p }},
		{"salt too short", func(p PBKDF2Params) PBKDF2Params { p.SaltLength = 4; return p }},
		{"key too short", func(p PBKDF2Params) PBKDF2Params { p.KeyLength = 8; return p }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPBKDF2SM3(c.mut(good)); err == nil {
				t.Errorf("NewPBKDF2SM3 accepted %s", c.name)
			}
		})
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
	argon := mustArgon2id(t, lightArgon2idParams())
	pbkdf := mustPBKDF2SM3(t, lightPBKDF2Params())

	aEnc, _ := argon.Hash("shared-secret")
	pEnc, _ := pbkdf.Hash("shared-secret")

	if pbkdf.Verify("shared-secret", aEnc) {
		t.Error("pbkdf2-sm3 accepted an argon2id hash")
	}
	if argon.Verify("shared-secret", pEnc) {
		t.Error("argon2id accepted a pbkdf2-sm3 hash")
	}
}

// ─── security regression tests (C1 / C2 / H3) ───
//
// These guard against attacker-controlled PHC strings crashing the process
// (argon2 panic) or hanging it (pbkdf2 CPU exhaustion). All must return
// ok=false WITHOUT panicking or stalling.

// validB64 returns a zero-filled RawStdEncoding string of n decoded bytes,
// matching what an attacker would craft to bypass "bad base64" short-circuits.
func validB64(n int) string {
	return base64.RawStdEncoding.EncodeToString(make([]byte, n))
}

// TestArgon2id_VerifyRejectsPanicParams covers C1: attacker-controlled PHC
// params (t=0, p=0, m=0, empty hash) must not reach argon2.IDKey and panic.
// Uses defer/recover so a regression surfaces as a test failure, not a crash.
func TestArgon2id_VerifyRejectsPanicParams(t *testing.T) {
	h := mustArgon2id(t, lightArgon2idParams())
	salt, dk := validB64(16), validB64(32)

	cases := []struct{ name, phc string }{
		{"t=0", "$argon2id$v=19$m=65536,t=0,p=2$" + salt + "$" + dk},
		{"p=0", "$argon2id$v=19$m=65536,t=3,p=0$" + salt + "$" + dk},
		{"m=0", "$argon2id$v=19$m=0,t=3,p=2$" + salt + "$" + dk},
		{"t=0,p=0", "$argon2id$v=19$m=65536,t=0,p=0$" + salt + "$" + dk},
		{"empty-hash (nil ptr)", "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$"},
		{"empty-salt", "$argon2id$v=19$m=65536,t=3,p=2$" + "$" + dk},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify panicked on %q: %v", c.phc, r)
				}
			}()
			if h.Verify("any-password", c.phc) {
				t.Errorf("Verify unexpectedly accepted %q", c.phc)
			}
		})
	}
}

// TestPBKDF2SM3_VerifyRejectsExcessiveIterations covers C2: an attacker-crafted
// iteration count must not hang the verifier. We assert the call returns well
// within a generous budget rather than timing the derivation (which is
// machine-dependent). The point: with the upper bound in place, a 1e8 iter
// string is rejected up-front; without it, this test stalls for minutes.
func TestPBKDF2SM3_VerifyRejectsExcessiveIterations(t *testing.T) {
	h := mustPBKDF2SM3(t, lightPBKDF2Params())
	salt, dk := validB64(16), validB64(32)
	doSHash := "$pbkdf2-sm3$i=100000000$" + salt + "$" + dk

	done := make(chan struct{})
	go func() {
		// Must return false (rejected by iter cap) rather than stalling.
		_ = h.Verify("any", doSHash)
		close(done)
	}()
	select {
	case <-done:
		// pass — the upper bound short-circuited the derivation.
	case <-time.After(2 * time.Second):
		t.Fatal("Verify stalled >2s on i=1e8 — iteration upper bound missing")
	}
}

// TestArgon2id_VerifyRejectsOversizedParallelism covers H3: p=300 must be
// rejected, not silently truncated to 44. We can't observe the truncation
// directly (Verify would just fail on key mismatch), but the malformed-hash
// rejection keeps invalid params out of argon2.IDKey entirely.
func TestArgon2id_VerifyRejectsOversizedParallelism(t *testing.T) {
	h := mustArgon2id(t, lightArgon2idParams())
	salt, dk := validB64(16), validB64(32)
	phc := "$argon2id$v=19$m=65536,t=3,p=300$" + salt + "$" + dk

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on p=300: %v", r)
		}
	}()
	if h.Verify("any", phc) {
		t.Error("Verify accepted p=300 (parallelism should be rejected, not truncated)")
	}
}
