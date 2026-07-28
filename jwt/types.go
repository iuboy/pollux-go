package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

// Algorithm is the name of a JWT signing algorithm, used as the JWT "alg"
// header value. Implementations are registered with [jwt.RegisterSigningMethod]
// so golang-jwt's parser can dispatch by alg.
type Algorithm string

const (
	// AlgHS256 is HMAC-SHA-256 (RFC 7519 / RFC 2104). Symmetric.
	AlgHS256 Algorithm = "HS256"
	// AlgHS512 is HMAC-SHA-512 (RFC 7519 / RFC 2104). Symmetric.
	AlgHS512 Algorithm = "HS512"
	// AlgSM2SM3 is SM2 with SM3 prehash per GM/T 0009-2012. Asymmetric.
	// Used as the JWT "alg" header value for GM tokens.
	AlgSM2SM3 Algorithm = "SM2SM3"
)

// Claims is an alias for jwt.Claims, re-exported so consumers do not need to
// import golang-jwt directly to define their claims struct.
type Claims = jwt.Claims

// RegisteredClaims is an alias for jwt.RegisteredClaims, re-exported for the
// same reason as [Claims].
type RegisteredClaims = jwt.RegisteredClaims

// Signer signs a JWT for a given set of claims and returns the encoded token
// string. The signing algorithm and key are configured on the Signer
// instance, not passed per call.
type Signer interface {
	// Algorithm returns the JWT "alg" header value this signer produces.
	Algorithm() Algorithm

	// Sign encodes claims into a signed JWT string.
	Sign(claims Claims) (tokenString string, err error)
}

// Verifier parses and validates a JWT, populating claims. The signing
// algorithm and key are configured on the Verifier instance.
//
// Verify MUST reject any token whose alg header does not match the configured
// algorithm — this is the standard JWT alg-confusion defense (rejecting
// "alg=none" or "alg=HS256" when the verifier is configured for SM2, etc.).
type Verifier interface {
	// Verify parses tokenString and writes the validated claims into v.
	// Returns an error if the signature is invalid, the alg header does not
	// match, or the token is malformed.
	Verify(tokenString string, v Claims) error
}

// SignerVerifier combines [Signer] and [Verifier]. Most concrete types in
// this package implement both (the same key can sign and verify).
type SignerVerifier interface {
	Signer
	Verifier
}
