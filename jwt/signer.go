package jwt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iuboy/pollux-go/sm2"
)

// ErrAlgorithmMismatch is returned by Verify when the token's alg header does
// not match the verifier's configured algorithm. This is the explicit
// alg-confusion defense (rejecting, say, an HS256 token presented to an SM2
// verifier).
var ErrAlgorithmMismatch = errors.New("jwt: token alg header does not match verifier")

// hmacSignerVerifier implements [SignerVerifier] for HS256/HS512.
//
// The issuer is stored for reference/debugging but is NOT auto-injected into
// claims — callers set the iss claim themselves on the Claims they pass to
// Sign. This keeps Sign a pure pass-through and avoids mutating caller-owned
// claim structs.
type hmacSignerVerifier struct {
	method jwt.SigningMethod
	algo   Algorithm
	secret []byte
	issuer string
}

// NewHS256 constructs an HS256 SignerVerifier backed by the given symmetric
// secret. issuer is recorded for the verifier's iss enforcement if the
// caller wires one via jwt.WithIssuer at parse time.
func NewHS256(secret []byte, issuer string) SignerVerifier {
	return &hmacSignerVerifier{
		method: jwt.SigningMethodHS256,
		algo:   AlgHS256,
		secret: secret,
		issuer: issuer,
	}
}

// NewHS512 constructs an HS512 SignerVerifier. See [NewHS256].
func NewHS512(secret []byte, issuer string) SignerVerifier {
	return &hmacSignerVerifier{
		method: jwt.SigningMethodHS512,
		algo:   AlgHS512,
		secret: secret,
		issuer: issuer,
	}
}

func (h *hmacSignerVerifier) Algorithm() Algorithm { return h.algo }

func (h *hmacSignerVerifier) Sign(claims Claims) (string, error) {
	token := jwt.NewWithClaims(h.method, claims)
	return token.SignedString(h.secret)
}

func (h *hmacSignerVerifier) Verify(tokenString string, v Claims) error {
	parsed, err := jwt.ParseWithClaims(tokenString, v, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != h.method.Alg() {
			return nil, fmt.Errorf("%w: got %s want %s", ErrAlgorithmMismatch, t.Method.Alg(), h.method.Alg())
		}
		return h.secret, nil
	})
	if err != nil {
		return err
	}
	if !parsed.Valid {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}

// sm2SignerVerifier implements [SignerVerifier] for SM2-SM3.
type sm2SignerVerifier struct {
	algo   Algorithm
	priv   *sm2.PrivateKey  // *gmsmSM2.PrivateKey (embeds ecdsa.PrivateKey)
	pub    *ecdsa.PublicKey // sm2.PublicKey is an alias for *ecdsa.PublicKey
	issuer string
}

// NewSM2SM3 constructs an SM2-SM3 SignerVerifier.
//
// For signing, priv MUST be non-nil. For verifying, pub MUST be non-nil.
// A single instance configured with both can sign and verify (typical for a
// service that issues and later validates its own tokens). An instance with
// only pub set is verify-only (a resource service validating tokens issued
// by a central auth service).
//
// Both keys MUST be on the SM2 P-256 curve. Use [github.com/iuboy/pollux-go/sm2]
// helpers (GenerateKey, PEM loaders) to obtain them.
func NewSM2SM3(priv *sm2.PrivateKey, pub *ecdsa.PublicKey, issuer string) (SignerVerifier, error) {
	if priv == nil && pub == nil {
		return nil, errors.New("jwt: NewSM2SM3 requires at least one of priv/pub")
	}
	return &sm2SignerVerifier{algo: AlgSM2SM3, priv: priv, pub: pub, issuer: issuer}, nil
}

func (s *sm2SignerVerifier) Algorithm() Algorithm { return s.algo }

func (s *sm2SignerVerifier) Sign(claims Claims) (string, error) {
	if s.priv == nil {
		return "", errors.New("jwt/sm2sm3: Sign called on a verify-only instance (priv is nil)")
	}
	token := jwt.NewWithClaims(SigningMethodSM2SM3, claims)
	return token.SignedString(s.priv)
}

func (s *sm2SignerVerifier) Verify(tokenString string, v Claims) error {
	if s.pub == nil {
		return errors.New("jwt/sm2sm3: Verify called on a sign-only instance (pub is nil)")
	}
	parsed, err := jwt.ParseWithClaims(tokenString, v, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != SigningMethodSM2SM3.Alg() {
			return nil, fmt.Errorf("%w: got %s want %s", ErrAlgorithmMismatch, t.Method.Alg(), SigningMethodSM2SM3.Alg())
		}
		return s.pub, nil
	})
	if err != nil {
		return err
	}
	if !parsed.Valid {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}

// IssueWithExpiry is a convenience helper that builds standard
// RegisteredClaims with sub, issuer, and an expiry offset, then signs with sv.
// Returned for callers that want a one-shot issue API without constructing
// claims manually.
func IssueWithExpiry(sv Signer, subject, issuer string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return sv.Sign(&claims)
}
