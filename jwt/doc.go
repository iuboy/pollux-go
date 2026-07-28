// Package jwt provides JWT signing methods for both the GM regime
// (SM2-SM3, asymmetric) and the international regime (HMAC-SHA-256/512,
// symmetric), plus a uniform [Signer] / [Verifier] abstraction so callers
// can switch algorithms by configuration without touching the call site.
//
// The package wraps [github.com/golang-jwt/jwt/v5] (the de-facto Go JWT
// library) rather than implementing JWS from scratch. Two pieces are added:
//
//   - SigningMethodSM2SM3: a jwt.SigningMethod implementation that signs the
//     JWT signing-string using SM2 with SM3 as the prehash, per GM/T 0009-2012.
//     golang-jwt does not ship an SM2 method, so pollux-go registers one.
//   - HMAC signer/verifier wrappers around jwt.SigningMethodHS256/HS512 that
//     expose the uniform [Signer] / [Verifier] interface.
//
// # Why a uniform interface?
//
// cloudfile's cryptosuite needs to switch JWT backends by configuration:
// HS256 for the international default, SM2-SM3 for GM compliance. Exposing
// both behind [Signer] / [Verifier] keeps the token manager call site
// agnostic. The interface intentionally mirrors what cloudfile's
// token/manager.go does today (Sign(claims) / Parse(tokenString, claims)),
// so the migration is a constructor swap.
//
// # GM/T 0009 user ID
//
// SM2 signatures incorporate a "user ID" (ZA value derivation). GM/T 0009-2012
// fixes the default user ID as "1234567812345678". [SigningMethodSM2SM3] uses
// [github.com/iuboy/pollux-go/gmstd.DefaultSM2UserID] for both sign and verify
// so the two ends interoperate by default.
//
// # Key formats
//
//   - HS256/HS512: symmetric secret ([]byte).
//   - SM2-SM3: *sm2.PrivateKey for signing, *ecdsa.PublicKey for verifying.
//     Use [github.com/iuboy/pollux-go/sm2] PEM helpers to load keys.
package jwt
