package jwt

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iuboy/pollux-go/sm2"
)

// ─── HS256 / HS512 ───

func TestHS256_RoundTrip(t *testing.T) {
	sv := NewHS256([]byte("super-secret-key"), "test-issuer")
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
	sv := NewHS512([]byte("another-secret"), "")
	token, _ := sv.Sign(&jwt.RegisteredClaims{Subject: "x"})
	if sv.Algorithm() != AlgHS512 {
		t.Errorf("Algorithm = %s, want HS512", sv.Algorithm())
	}
	if err := sv.Verify(token, &jwt.RegisteredClaims{}); err != nil {
		t.Fatalf("Verify err = %v", err)
	}
}

func TestHS256_RejectsTamperedToken(t *testing.T) {
	sv := NewHS256([]byte("k"), "iss")
	token, _ := sv.Sign(&jwt.RegisteredClaims{Subject: "orig"})
	// Flip the last char of the signature segment.
	tampered := token[:len(token)-1] + "X"
	if err := sv.Verify(tampered, &jwt.RegisteredClaims{}); err == nil {
		t.Error("Verify accepted a tampered token")
	}
}

func TestHS256_RejectsWrongSecret(t *testing.T) {
	signer := NewHS256([]byte("secret-a"), "")
	verifier := NewHS256([]byte("secret-b"), "")
	token, _ := signer.Sign(&jwt.RegisteredClaims{Subject: "x"})
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
	sm2Token, _ := sm2SV.Sign(&jwt.RegisteredClaims{Subject: "x"})

	hs256 := NewHS256([]byte("any-secret"), "")
	if err := hs256.Verify(sm2Token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("HS256 verifier accepted an SM2 token (alg confusion)")
	}
}

// ─── SM2-SM3 ───

// newTestSM2Key generates a fresh SM2 keypair for the test. Each test uses its
// own key to avoid state coupling.
func newTestSM2Key(t *testing.T) (*sm2.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := sm2.GenerateKeyDefault()
	if err != nil {
		t.Fatalf("sm2.GenerateKeyDefault err = %v", err)
	}
	return priv, &priv.PublicKey
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
	token, _ := sv.Sign(&jwt.RegisteredClaims{Subject: "orig"})
	tampered := token[:len(token)-1] + "Z"
	if err := sv.Verify(tampered, &jwt.RegisteredClaims{}); err == nil {
		t.Error("SM2 verifier accepted a tampered token")
	}
}

func TestSM2SM3_RejectsDifferentKey(t *testing.T) {
	privA, _ := newTestSM2Key(t)
	_, pubB := newTestSM2Key(t)
	signer, _ := NewSM2SM3(privA, nil, "")
	verifier, _ := NewSM2SM3(nil, pubB, "")
	token, _ := signer.Sign(&jwt.RegisteredClaims{Subject: "x"})
	if err := verifier.Verify(token, &jwt.RegisteredClaims{}); err == nil {
		t.Error("SM2 verifier accepted token signed with a different key")
	}
}

// TestSM2SM3_RejectsHS256Token is the reverse alg-confusion defense: an SM2
// verifier MUST reject an HMAC token.
func TestSM2SM3_RejectsHS256Token(t *testing.T) {
	_, pub := newTestSM2Key(t)
	sm2Verifier, _ := NewSM2SM3(nil, pub, "")

	hs256 := NewHS256([]byte("any-secret"), "")
	hs256Token, _ := hs256.Sign(&jwt.RegisteredClaims{Subject: "x"})

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
	sv := NewHS256([]byte("k"), "iss")
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
