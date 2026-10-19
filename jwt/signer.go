package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"reflect"
	"sync"
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
//
// Concurrency: safe for concurrent use. Sign/Verify take a read lock and
// Zeroize takes a write lock, so Zeroize (which mutates the secret slice in
// place) cannot race a concurrent Sign/Verify and hand it a half-zeroed key.
type hmacSignerVerifier struct {
	mu       sync.RWMutex
	method   jwt.SigningMethod
	algo     Algorithm
	secret   []byte
	issuer   string
	audience string
	zeroized bool
}

// cloneSecret returns a copy of secret owned by the signer. The HMAC
// constructors deliberately do NOT retain the caller's slice: sharing the
// backing array would make Zeroize destructively clear the caller's buffer,
// and would let a caller who reuses the buffer flip the signer's key
// underneath it, silently signing with the wrong secret.
func cloneSecret(secret []byte) []byte {
	c := make([]byte, len(secret))
	copy(c, secret)
	return c
}

// NewHS256 constructs an HS256 SignerVerifier backed by the given symmetric
// secret. issuer is recorded for the verifier's iss enforcement if the
// caller wires one via jwt.WithIssuer at parse time.
//
// The secret is deep-copied into a buffer owned by the returned signer:
// [hmacSignerVerifier.Zeroize] clears only that private copy, and later
// mutations of the caller's slice (including reuse of its backing array) do
// not affect the signer. The caller's original buffer remains the caller's
// responsibility to zero.
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
		secret: cloneSecret(secret),
		issuer: issuer,
	}, nil
}

// NewHS512 constructs an HS512 SignerVerifier. See [NewHS256] — including
// the deep-copy ownership of the secret.
//
// Returns [ErrInvalidKeySize] if secret is shorter than 64 bytes (512 bits).
func NewHS512(secret []byte, issuer string) (SignerVerifier, error) {
	if len(secret) < minHS512KeyLen {
		return nil, fmt.Errorf("%w: HS512 needs at least %d bytes, got %d", ErrInvalidKeySize, minHS512KeyLen, len(secret))
	}
	return &hmacSignerVerifier{
		method: jwt.SigningMethodHS512,
		algo:   AlgHS512,
		secret: cloneSecret(secret),
		issuer: issuer,
	}, nil
}

// checkClaimsPtr guards Verify against the silent-data-loss foot-gun described
// in the [Verifier] docs: a non-nil pointer Claims is required because the JWT
// library writes the decoded claims through it. Passing a value (non-pointer)
// Claims compiles, parses, and validates successfully — but the decoded claims
// are written to a throwaway copy and the caller keeps a zero-value struct with
// no error. A nil/empty interface map (jwt.MapClaims) is also accepted, since
// map types are reference-semantic and Unmarshal writes through them correctly.
func checkClaimsPtr(v Claims) error {
	if v == nil {
		return errors.New("jwt: Verify requires a non-nil Claims pointer")
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Pointer:
		if reflect.ValueOf(v).IsNil() {
			return errors.New("jwt: Verify requires a non-nil Claims pointer")
		}
		return nil
	case reflect.Map:
		return nil // jwt.MapClaims and similar reference types are valid
	default:
		return fmt.Errorf("jwt: Verify requires a *Claims (pointer), got non-pointer %T", v)
	}
}

// Zeroize securely clears the HMAC secret held by the SignerVerifier. It
// clears only the signer's private copy made at construction (see
// [NewHS256]/[NewHS512]); the caller's original buffer is untouched and
// remains the caller's responsibility. Callers should invoke Zeroize
// (typically via defer) once the SignerVerifier is no longer needed, to keep
// the secret's lifetime bounded — consistent with the ZeroKey/ZeroNonce
// helpers in the aes and sm4 packages.
func (h *hmacSignerVerifier) Zeroize() {
	h.mu.Lock()
	defer h.mu.Unlock()
	memsecure.ZeroBytes(h.secret)
	h.zeroized = true
}

// errKeyZeroized is returned by Sign/Verify after Zeroize has cleared the key.
// Without this guard a zeroed SignerVerifier would silently sign with an
// all-zero secret or fail to verify with a zeroed scalar — both hard to spot.
var errKeyZeroized = errors.New("jwt: signer/verifier key has been zeroized")

func (h *hmacSignerVerifier) Algorithm() Algorithm { return h.algo }

// SetAudience configures the expected "aud" claim enforced during Verify. An
// empty audience (the default) disables the check; setting it makes the
// verifier reject tokens whose "aud" claim does not match, preventing a token
// issued for one service from being replayed against another. This must be set
// before any concurrent Verify call.
func (h *hmacSignerVerifier) SetAudience(aud string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.audience = aud
}

func (h *hmacSignerVerifier) Sign(claims Claims) (string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.zeroized {
		return "", errKeyZeroized
	}
	token := jwt.NewWithClaims(h.method, claims)
	return token.SignedString(h.secret)
}

func (h *hmacSignerVerifier) Verify(tokenString string, v Claims) error {
	if err := checkClaimsPtr(v); err != nil {
		return err
	}
	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.zeroized {
		return errKeyZeroized
	}
	if h.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(h.issuer))
	}
	if h.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(h.audience))
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
//
// Concurrency: safe for concurrent use (see hmacSignerVerifier). Zeroize takes
// the write lock and mutates priv.D; Sign/Verify take a read lock so they never
// observe a half-zeroed scalar concurrently.
type sm2SignerVerifier struct {
	mu       sync.RWMutex
	algo     Algorithm
	priv     *sm2.PrivateKey  // *gmsmSM2.PrivateKey (embeds ecdsa.PrivateKey)
	pub      *ecdsa.PublicKey // sm2.PublicKey is an alias for *ecdsa.PublicKey
	issuer   string
	audience string
	zeroized bool
}

// ErrInvalidSM2Curve is returned by [NewSM2SM3] when a supplied key is not on
// the SM2 P-256 curve. Signing/verifying with, say, a stdlib P-256 key would
// produce tokens that can never interoperate, so it is rejected fail-fast at
// construction instead of failing per-Sign/Verify.
var ErrInvalidSM2Curve = errors.New("jwt/sm2sm3: key is not on the SM2 P-256 curve")

// isSM2Curve reports whether c is the SM2 P-256 curve. The comparison matches
// by named curve parameters (P/N/B/Gx/Gy) rather than interface equality:
// gmsm and stdlib may expose distinct *elliptic.CurveParams-backed instances
// for the same curve, so == on the Curve interface is unreliable. This
// mirrors the comparison in https.DetectMode, kept local to avoid an import
// cycle on the https package.
func isSM2Curve(c elliptic.Curve) bool {
	want := sm2.P256().Params()
	if c == nil || want == nil {
		return false
	}
	got := c.Params()
	if got == nil {
		return false
	}
	return got.P.Cmp(want.P) == 0 &&
		got.N.Cmp(want.N) == 0 &&
		got.B.Cmp(want.B) == 0 &&
		got.Gx.Cmp(want.Gx) == 0 &&
		got.Gy.Cmp(want.Gy) == 0
}

// NewSM2SM3 constructs an SM2-SM3 SignerVerifier.
//
// For signing, priv MUST be non-nil. For verifying, pub MUST be non-nil.
// A single instance configured with both can sign and verify (typical for a
// service that issues and later validates its own tokens). An instance with
// only pub set is verify-only (a resource service validating tokens issued
// by a central auth service).
//
// Both keys MUST be on the SM2 P-256 curve; keys on any other curve (or a
// nil curve) are rejected with [ErrInvalidSM2Curve]. Use
// [github.com/iuboy/pollux-go/sm2] helpers (GenerateKey, PEM loaders) to
// obtain them.
//
// Unlike the HMAC constructors, the signer ALIASES (does not copy) the
// caller's key pointers: an EC scalar cannot be securely copied-and-cleared
// anyway (big.Int hides its backing words, see Zeroize), and duplicating it
// would only multiply non-clearable copies of the secret. Callers must
// therefore not zero or otherwise mutate the passed keys while the
// SignerVerifier is still live.
func NewSM2SM3(priv *sm2.PrivateKey, pub *ecdsa.PublicKey, issuer string) (SignerVerifier, error) {
	if priv == nil && pub == nil {
		return nil, errors.New("jwt: NewSM2SM3 requires at least one of priv/pub")
	}
	if priv != nil && !isSM2Curve(priv.Curve) {
		return nil, fmt.Errorf("%w: private key curve", ErrInvalidSM2Curve)
	}
	if pub != nil && !isSM2Curve(pub.Curve) {
		return nil, fmt.Errorf("%w: public key curve", ErrInvalidSM2Curve)
	}
	return &sm2SignerVerifier{algo: AlgSM2SM3, priv: priv, pub: pub, issuer: issuer}, nil
}

func (s *sm2SignerVerifier) Algorithm() Algorithm { return s.algo }

// SetAudience configures the expected "aud" claim enforced during Verify. See
// hmacSignerVerifier.SetAudience for semantics. Empty disables the check.
func (s *sm2SignerVerifier) SetAudience(aud string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audience = aud
}

func (s *sm2SignerVerifier) Sign(claims Claims) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.zeroized {
		return "", errKeyZeroized
	}
	if s.priv == nil {
		return "", errors.New("jwt/sm2sm3: Sign called on a verify-only instance (priv is nil)")
	}
	token := jwt.NewWithClaims(SigningMethodSM2SM3, claims)
	return token.SignedString(s.priv)
}

func (s *sm2SignerVerifier) Verify(tokenString string, v Claims) error {
	if err := checkClaimsPtr(v); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.zeroized {
		return errKeyZeroized
	}
	if s.pub == nil {
		return errors.New("jwt/sm2sm3: Verify called on a sign-only instance (pub is nil)")
	}
	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	if s.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(s.issuer))
	}
	if s.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(s.audience))
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv != nil && s.priv.D != nil {
		s.priv.D.SetInt64(0)
	}
	s.zeroized = true
}

// ErrInvalidTTL is returned by [IssueWithExpiry] when ttl is zero or
// negative: such a token would be expired (or expire the instant it is
// issued) and a zero-ttl token would render ExpiresAt meaningless under
// golang-jwt's WithExpirationRequired check.
var ErrInvalidTTL = errors.New("jwt: ttl must be positive")

// nbfLeeway is the amount IssueWithExpiry backdates the NotBefore claim to
// tolerate clock skew between the issuing host and verifying hosts. A
// verifier whose clock runs a few seconds behind the issuer would otherwise
// reject a freshly issued token as "not yet valid". 30s matches the leeway
// golang-jwt documents for jwt.WithLeeway; backdating at issuance is chosen
// over per-verifier leeway so verifiers need no extra configuration.
const nbfLeeway = 30 * time.Second

// IssueWithExpiry is a convenience helper that builds standard
// RegisteredClaims with sub, issuer, and an expiry offset, then signs with sv.
// Returned for callers that want a one-shot issue API without constructing
// claims manually.
//
// NotBefore is backdated by nbfLeeway (see its doc); ExpiresAt is now+ttl.
//
// Note: the issuer argument here populates the token's iss claim directly; it
// is independent of any issuer stored on sv at construction. Callers that
// later validate with jwt.WithIssuer MUST pass the same issuer to both sites,
// or verification will reject the token.
//
// Returns [ErrInvalidTTL] if ttl <= 0.
func IssueWithExpiry(sv Signer, subject, issuer string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("%w: got %v", ErrInvalidTTL, ttl)
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-nbfLeeway)),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return sv.Sign(&claims)
}
