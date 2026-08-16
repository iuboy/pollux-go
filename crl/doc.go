// Package crl provides X.509 Certificate Revocation List (CRL) generation,
// caching, fan-out and parsing.
//
// The package is built around injected abstractions so any CA backend can
// drive it:
//
//   - [Authority] supplies the revoked-certificate list, the issuer chain and
//     the signing key (an application implements it over its own storage).
//   - [CRLCache] caches the generated CRL ([NewMemoryCRLCache] provides an
//     in-process implementation).
//   - [NumberSource] supplies monotonically increasing CRL numbers across
//     restarts (RFC 5280 §5.2.3); without one the generator falls back to an
//     in-process counter, which resets on restart and is test-only.
//
// SM2 keys sign CRLs with SM2+SM3 (GM/T 0009-2012) via
// [github.com/iuboy/pollux-go/smx509].CreateRevocationList; standard keys use
// crypto/x509. Revocation reasons travel through the
// x509.RevocationListEntry.ReasonCode field — hand-appending the
// cRLReason extension is silently ignored by the Go encoder (a historical
// bug this package documents and avoids).
//
// # Fan-out
//
// In multi-issuer deployments each issuer has its own generator and cache;
// [NewFanout] aggregates them so a revocation under any issuer refreshes
// every CRL (Update fans out; Get/Generate delegate to the primary).
//
// # Parsing
//
// [ParseCRLRecords], [GetRevokedSerials], [GetCRLNumber] and [IsExpired]
// inspect CRLs read-only (no signature verification) and work for
// GM-signed CRLs as well.
package crl
