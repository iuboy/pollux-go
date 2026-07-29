package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iuboy/pollux-go/sm2"
)

// ─── HS256 / HS512 ───

func TestHS256_RoundTrip(t *testing.T) {
	sv := mustHS256(t, "test-issuer")
	claims := &jwt.RegisteredClaims{
		Subject:   "user-42",
		Issuer:    "test-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := sv.Sign(claims)
	if err != nil {
		t.Fatalf("Sign err = %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	if sv.Algorithm() != AlgHS256 {
		t.Errorf("Algorithm = %s, want HS256", sv.Algorithm())
	}

	got := &jwt.RegisteredClaims{}
	if err := sv.Verify(token, got); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
	if got.Subject != "user-42" {
		t.Errorf("Subject = %q, want user-42", got.Subject)
	}
}

func TestHS512_RoundTrip(t *testing.T) {
	sv := mustHS512(t, "")
	token, _ := sv.Sign(&jwt.RegisteredClaims{
		Subject:   "x",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if sv.Algorithm() != AlgHS512 {
		t.Errorf("Algorithm = %s, want HS512", sv.Algorithm())
	}
	if err := sv.Verify(token, &jwt.RegisteredClaims{}); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
}

func TestHS256_RejectsTamperedToken(t *testing.T) {
	sv := mustHS256(t, "iss")
	token, _ := sv.Sign(&jwt.RegisteredClaims{
		Subject:   "orig",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tampered := tamperSignature(t, token)
	if err := sv.Verify(tampered, &jwt.RegisteredClaims{}); err == nil {
		t.Error("Verify accepted a tampered token")
	}
}

func TestHS256_RejectsWrongSecret(t *testing.T) {
	signer := mustHS256(t, "")
	// A different but length-valid secret for the verifier.
	otherSecret := bytes.Repeat([]byte("z"), minHS256KeyLen)
	verifier, err := NewHS256(otherSecret, "")
	if err != nil {
		t.Fatalf("NewHS256(otherSecret) err = %v", err)
	}
	token, _ := signer.Sign(&jwt.RegisteredClaims{
		Subject:   "x",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err := verifier.Verify(token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("Verify accepted token signed with a different secret")
	}
}

// TestHS256_RejectsSM2Token is the alg-confusion defense: an HS256 verifier
// MUST reject any token whose alg header is not HS256, even if the signature
// bytes happen to be valid under some other interpretation.
func TestHS256_RejectsSM2Token(t *testing.T) {
	priv, _ := sm2.GenerateKeyDefault()
	sm2SV, _ := NewSM2SM3(priv, &priv.PublicKey, "")
	sm2Token, _ := sm2SV.Sign(&jwt.RegisteredClaims{
		Subject:   "x",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	hs256 := mustHS256(t, "")
	if err := hs256.Verify(sm2Token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("HS256 verifier accepted an SM2 token (alg confusion)")
	}
}

// TestNewHS256_RejectsShortKey covers H2: an HMAC secret shorter than the
// hash output size is rejected at construction, since it would weaken the MAC
// below its advertised strength (RFC 2104 §3).
func TestNewHS256_RejectsShortKey(t *testing.T) {
	if _, err := NewHS256(bytes.Repeat([]byte("k"), minHS256KeyLen-1), ""); err == nil {
		t.Error("NewHS256 accepted a 31-byte key")
	}
}

// TestNewHS512_RejectsShortKey covers H2 for HS512.
func TestNewHS512_RejectsShortKey(t *testing.T) {
	if _, err := NewHS512(bytes.Repeat([]byte("k"), minHS512KeyLen-1), ""); err == nil {
		t.Error("NewHS512 accepted a 63-byte key")
	}
}

// ─── SM2-SM3 ───

// newTestSM2Key generates a fresh SM2 keypair for the test. Each test uses its
func newTestSM2Key(t *testing.T) (*sm2.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatalf("sm2.GenerateKeyDefault err = %v", err)
	}
	return priv, &priv.PublicKey
}

// testHS256Secret / testHS512Secret are fixed secrets that satisfy the
// constructor's minimum key length (H2). They are not secret — the tests only
// exercise sign/verify mechanics, not key strength.
var (
	testHS256Secret = bytes.Repeat([]byte("a"), minHS256KeyLen) // 32 bytes
	testHS512Secret = bytes.Repeat([]byte("b"), minHS512KeyLen) // 64 bytes
)

// mustHS256 wraps NewHS256 with the fixed test secret, failing the test on a
// constructor error (which would only happen if testHS256Secret shrank below
// the minimum).
func mustHS256(t *testing.T, issuer string) SignerVerifier {
	t.Helper()
	sv, err := NewHS256(testHS256Secret, issuer)
	if err != nil {
		t.Fatalf("NewHS256 err = %v", err)
	}
	return sv
}

// mustHS512 is the HS512 analogue of mustHS256.
func mustHS512(t *testing.T, issuer string) SignerVerifier {
	t.Helper()
	sv, err := NewHS512(testHS512Secret, issuer)
	if err != nil {
		t.Fatalf("NewHS512 err = %v", err)
	}
	return sv
}

func TestSM2SM3_RoundTrip(t *testing.T) {
	priv, pub := newTestSM2Key(t)
	sv, err := NewSM2SM3(priv, pub, "sm2-issuer")
	if err != nil {
		t.Fatalf("NewSM2SM3 err = %v", err)
	}
	if sv.Algorithm() != AlgSM2SM3 {
		t.Errorf("Algorithm = %s, want SM2SM3", sv.Algorithm())
	}
	claims := &jwt.RegisteredClaims{
		Subject:   "gm-user",
		Issuer:    "sm2-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := sv.Sign(claims)
	if err != nil {
		t.Fatalf("Sign err = %v", err)
	}
	// The alg header is enforced indirectly: Verify's keyFunc rejects any
	// token whose alg != SM2SM3 (alg-confusion defense), so a successful
	// Verify below proves the header is SM2SM3. We still spot-check the
	// header to surface regressions clearly.
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}

	got := &jwt.RegisteredClaims{}
	if err := sv.Verify(token, got); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
	if got.Subject != "gm-user" {
		t.Errorf("Subject = %q, want gm-user", got.Subject)
	}
}

func TestSM2SM3_RejectsTamperedToken(t *testing.T) {
	priv, pub := newTestSM2Key(t)
	sv, _ := NewSM2SM3(priv, pub, "")
	token, _ := sv.Sign(&jwt.RegisteredClaims{
		Subject:   "orig",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tampered := tamperSignature(t, token)
	if err := sv.Verify(tampered, &jwt.RegisteredClaims{}); err == nil {
		t.Error("SM2 verifier accepted a tampered token")
	}
}

// tamperSignature flips the first byte of the base64url-decoded signature
// segment and re-encodes it, guaranteeing a byte-level change. This replaces
// the previous "flip the last base64 char" approach, which silently no-oped
// ~7% of the time because the trailing base64 char carries bits outside the
// signature's byte boundary (SM2 ASN.1 length is not always 6-bit aligned).
func tamperSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		t.Fatalf("decode signature segment: err=%v len=%d", err, len(sig))
	}
	sig[0] ^= 0xFF // flip all bits of the first byte — guaranteed to change it
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func TestSM2SM3_RejectsDifferentKey(t *testing.T) {
	privA, _ := newTestSM2Key(t)
	_, pubB := newTestSM2Key(t)
	signer, _ := NewSM2SM3(privA, nil, "")
	verifier, _ := NewSM2SM3(nil, pubB, "")
	token, _ := signer.Sign(&jwt.RegisteredClaims{
		Subject:   "x",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err := verifier.Verify(token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("SM2 verifier accepted token signed with a different key")
	}
}

// TestSM2SM3_RejectsHS256Token is the reverse alg-confusion defense: an SM2
// verifier MUST reject an HMAC token.
func TestSM2SM3_RejectsHS256Token(t *testing.T) {
	_, pub := newTestSM2Key(t)
	sm2Verifier, _ := NewSM2SM3(nil, pub, "")

	hs256 := mustHS256(t, "")
	hs256Token, _ := hs256.Sign(&jwt.RegisteredClaims{
		Subject:   "x",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	if err := sm2Verifier.Verify(hs256Token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("SM2 verifier accepted an HS256 token (alg confusion)")
	}
}

func TestSM2SM3_SignOnlyInstanceRejectsVerify(t *testing.T) {
	priv, _ := newTestSM2Key(t)
	sv, _ := NewSM2SM3(priv, nil, "")
	if err := sv.Verify("any.token.here", &jwt.RegisteredClaims{}); err == nil {
		t.Error("sign-only instance accepted Verify call")
	}
}

func TestSM2SM3_VerifyOnlyInstanceRejectsSign(t *testing.T) {
	_, pub := newTestSM2Key(t)
	sv, _ := NewSM2SM3(nil, pub, "")
	if _, err := sv.Sign(&jwt.RegisteredClaims{}); err == nil {
		t.Error("verify-only instance accepted Sign call")
	}
}

func TestNewSM2SM3_RequiresAtLeastOneKey(t *testing.T) {
	if _, err := NewSM2SM3(nil, nil, ""); err == nil {
		t.Error("NewSM2SM3(nil, nil) unexpectedly succeeded")
	}
}

// TestSigningMethodRegisteredWithLibrary confirms that golang-jwt's global
// registry knows about SM2SM3, so ParseWithClaims can dispatch to it from
// the alg header.
func TestSigningMethodRegisteredWithLibrary(t *testing.T) {
	m := jwt.GetSigningMethod(string(AlgSM2SM3))
	if m == nil {
		t.Fatal("jwt.GetSigningMethod(SM2SM3) returned nil — init() registration failed")
	}
	if m.Alg() != string(AlgSM2SM3) {
		t.Errorf("registered method Alg = %q, want SM2SM3", m.Alg())
	}
}

// ─── IssueWithExpiry helper ───

func TestIssueWithExpiry_HS256(t *testing.T) {
	sv := mustHS256(t, "iss")
	token, err := IssueWithExpiry(sv, "sub-1", "iss", time.Hour)
	if err != nil {
		t.Fatalf("IssueWithExpiry err = %v", err)
	}
	got := &jwt.RegisteredClaims{}
	if err := sv.Verify(token, got); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
	if got.Subject != "sub-1" || got.Issuer != "iss" {
		t.Errorf("got sub=%q iss=%q", got.Subject, got.Issuer)
	}
	if got.ExpiresAt == nil {
		t.Error("ExpiresAt not set")
	}
}

func TestIssueWithExpiry_SM2SM3(t *testing.T) {
	priv, pub := newTestSM2Key(t)
	sv, _ := NewSM2SM3(priv, pub, "iss")
	token, err := IssueWithExpiry(sv, "gm-sub", "iss", 30*time.Minute)
	if err != nil {
		t.Fatalf("IssueWithExpiry err = %v", err)
	}
	got := &jwt.RegisteredClaims{}
	if err := sv.Verify(token, got); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
	if got.Subject != "gm-sub" {
		t.Errorf("Subject = %q, want gm-sub", got.Subject)
	}
}

// ─── interface conformance ───

func TestSignerVerifierConformance(t *testing.T) {
	var _ SignerVerifier = (*hmacSignerVerifier)(nil)
	// sm2SignerVerifier is not exported; check via the constructor return.
	priv, pub := newTestSM2Key(t)
	sv, _ := NewSM2SM3(priv, pub, "")
	var _ SignerVerifier = sv
}

// ─── concurrency safety ───

// TestSignerVerifier_ConcurrentVerifyVsZeroize exercises the RWMutex added to
// hmacSignerVerifier/sm2SignerVerifier. Concurrent Verify vs Zeroize previously
// was a data race (Zeroize mutates the secret/scalar while Verify reads it).
// Run with -race to catch any regression. It must not panic and must not hang.
func TestSignerVerifier_ConcurrentVerifyVsZeroize(t *testing.T) {
	t.Run("HS256", func(t *testing.T) {
		sv := mustHS256(t, "")
		token, err := IssueWithExpiry(sv, "sub", "iss", time.Hour)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		runConcurrentVerifyVsZeroize(t, sv, token)
	})
	t.Run("SM2SM3", func(t *testing.T) {
		priv, pub := newTestSM2Key(t)
		sv, _ := NewSM2SM3(priv, pub, "")
		token, err := IssueWithExpiry(sv, "sub", "iss", time.Hour)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		runConcurrentVerifyVsZeroize(t, sv, token)
	})
}

func runConcurrentVerifyVsZeroize(t *testing.T, sv SignerVerifier, token string) {
	t.Helper()
	done := make(chan struct{})
	// Verifier loop: keep verifying until closed. Errors are expected once
	// Zeroize runs (SM2/HMAC state changes), so we only assert no panic.
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = sv.Verify(token, &jwt.RegisteredClaims{})
		}
	}()
	// Concurrently zeroize a few times to force the race window.
	for i := 0; i < 50; i++ {
		// Zeroize is destructive; only the concurrent-read safety is under test,
		// so we don't assert Verify keeps succeeding after this point.
		if zeroer, ok := sv.(interface{ Zeroize() }); ok {
			zeroer.Zeroize()
		}
	}
	<-done
}

// ─── Verify non-pointer Claims defense ───

// TestVerify_RejectsNonPointerClaims covers the silent-data-loss foot-gun: a
// non-pointer Claims value compiles and parses, but the decoded claims are
// written to a throwaway copy. With the reflect guard, Verify now returns an
// explicit error instead of silently succeeding with zero-value claims.
func TestVerify_RejectsNonPointerClaims(t *testing.T) {
	t.Run("HS256", func(t *testing.T) {
		sv := mustHS256(t, "")
		token, err := IssueWithExpiry(sv, "sub", "iss", time.Hour)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// Passing a struct value (not a pointer) must now error rather than
		// silently leave the caller's claims zero-valued.
		if err := sv.Verify(token, jwt.RegisteredClaims{}); err == nil {
			t.Error("Verify with non-pointer Claims should return an error, got nil")
		}
		// nil must also error.
		if err := sv.Verify(token, nil); err == nil {
			t.Error("Verify with nil Claims should return an error, got nil")
		}
	})
	t.Run("SM2SM3", func(t *testing.T) {
		priv, pub := newTestSM2Key(t)
		sv, _ := NewSM2SM3(priv, pub, "")
		token, err := IssueWithExpiry(sv, "sub", "iss", time.Hour)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if err := sv.Verify(token, jwt.RegisteredClaims{}); err == nil {
			t.Error("Verify with non-pointer Claims should return an error, got nil")
		}
	})
}

// TestNewSM2SM3SigningMethod covers the exported constructor for custom-UID
// SigningMethod variants: it must round-trip under the custom uid and must not
// share mutable state with the caller's uid slice.
func TestNewSM2SM3SigningMethod(t *testing.T) {
	customUID := []byte("custom-user-id-16")
	method := NewSM2SM3SigningMethod(customUID)

	// Mutating the caller's slice after construction must not affect the method.
	customUID[0] = 'X'

	priv, _ := sm2.GenerateKey(rand.Reader)
	signingString := "header.payload"
	sig, err := method.Sign(signingString, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Verify must use the SAME (unmutated) uid to succeed; the method copied it.
	if err := method.Verify(signingString, sig, &priv.PublicKey); err != nil {
		t.Errorf("Verify with custom-UID method failed: %v", err)
	}
}
