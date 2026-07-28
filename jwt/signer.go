package jwt

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/iuboy/pollux-go/internal/memsecure"
	"github.com/iuboy/pollux-go/sm2"
)

// ErrAlgorithmMismatch is returned by Verify when the token's alg header does
// not match the verifier's configured algorithm. This is the explicit
// alg-confusion defense (rejecting, say, an HS256 token presented to an SM2
// verifier).
var ErrAlgorithmMismatch = errors.New("jwt: token alg header does not match verifier")

// ErrInvalidKeySize is returned by the HMAC constructors when the symmetric
// secret is shorter than the hash output size, which would weaken the MAC below
// its advertised security level (RFC 2104 §3 requires key length ≥ HashLen).
var ErrInvalidKeySize = errors.New("jwt: secret key too short for the algorithm")

// Minimum HMAC key lengths. HS256 needs ≥256 bits (32 bytes) of key material
// to reach its full security strength; HS512 needs ≥512 bits (64 bytes). These
// match the hash output sizes per RFC 2104.
const (
	minHS256KeyLen = 32
	minHS512KeyLen = 64
)

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
//
// Returns [ErrInvalidKeySize] if secret is shorter than 32 bytes (256 bits),
// the minimum key length for HMAC-SHA-256 to reach its full security strength
// (RFC 2104 §3).
func NewHS256(secret []byte, issuer string) (SignerVerifier, error) {
	if len(secret) < minHS256KeyLen {
		return nil, fmt.Errorf("%w: HS256 needs at least %d bytes, got %d", ErrInvalidKeySize, minHS256KeyLen, len(secret))
	}
	return &hmacSignerVerifier{
		method: jwt.SigningMethodHS256,
		algo:   AlgHS256,
		secret: secret,
		issuer: issuer,
	}, nil
}

// NewHS512 constructs an HS512 SignerVerifier. See [NewHS256].
//
// Returns [ErrInvalidKeySize] if secret is shorter than 64 bytes (512 bits).
func NewHS512(secret []byte, issuer string) (SignerVerifier, error) {
	if len(secret) < minHS512KeyLen {
		return nil, fmt.Errorf("%w: HS512 needs at least %d bytes, got %d", ErrInvalidKeySize, minHS512KeyLen, len(secret))
	}
	return &hmacSignerVerifier{
		method: jwt.SigningMethodHS512,
		algo:   AlgHS512,
		secret: secret,
		issuer: issuer,
	}, nil
}

// Zeroize securely clears the HMAC secret held by the SignerVerifier. Callers
// should invoke it (typically via defer) once the SignerVerifier is no longer
// needed, to keep the secret's lifetime bounded — consistent with the
// ZeroKey/ZeroNonce helpers in the aes and sm4 packages.
func (h *hmacSignerVerifier) Zeroize() { memsecure.ZeroBytes(h.secret) }

func (h *hmacSignerVerifier) Algorithm() Algorithm { return h.algo }

func (h *hmacSignerVerifier) Sign(claims Claims) (string, error) {
	token := jwt.NewWithClaims(h.method, claims)
	return token.SignedString(h.secret)
}

func (h *hmacSignerVerifier) Verify(tokenString string, v Claims) error {
	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	if h.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(h.issuer))
	}
	parsed, err := jwt.ParseWithClaims(tokenString, v, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != h.method.Alg() {
			// Return only the sentinel — exposing the expected algorithm in a
			// wrapped error could leak the server's configured alg to an
			// attacker probing endpoints.
			return nil, ErrAlgorithmMismatch
		}
		return h.secret, nil
	}, parserOpts...)
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
	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	if s.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(s.issuer))
	}
	parsed, err := jwt.ParseWithClaims(tokenString, v, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != SigningMethodSM2SM3.Alg() {
			// See hmacSignerVerifier.Verify: do not leak the expected alg.
			return nil, ErrAlgorithmMismatch
		}
		return s.pub, nil
	}, parserOpts...)
	if err != nil {
		return err
	}
	if !parsed.Valid {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}

// Zeroize clears the SM2 private key scalar held by the SignerVerifier.
//
// NOTE: math/big.Int does not expose its internal nat words, so a fully secure
// overwrite of the backing array is not possible from outside the type. The
// previous implementation called memsecure.ZeroBytes(s.priv.D.Bytes()), but
// D.Bytes() returns a FRESH copy of the scalar — zeroing that copy left the
// actual private key intact (a silent no-op). SetInt64(0) at least zeroes the
// logical scalar value so the key is no longer usable or directly readable.
// This matches the best-effort convention Go's crypto/ecdsa itself documents
// for big.Int-backed keys. For keys requiring stronger guarantees, callers
// should keep the raw key bytes and zero those directly (see
// sm2.PrivateKeyToBytesSecure).
func (s *sm2SignerVerifier) Zeroize() {
	if s.priv != nil && s.priv.D != nil {
		s.priv.D.SetInt64(0)
	}
}

// IssueWithExpiry is a convenience helper that builds standard
// RegisteredClaims with sub, issuer, and an expiry offset, then signs with sv.
// Returned for callers that want a one-shot issue API without constructing
// claims manually.
//
// Note: the issuer argument here populates the token's iss claim directly; it
// is independent of any issuer stored on sv at construction. Callers that
// later validate with jwt.WithIssuer MUST pass the same issuer to both sites,
// or verification will reject the token.
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
