// Package cert provides a unified certificate facade for both standard X.509
// and SM2 (Chinese national cryptography) certificates.
//
// It wraps crypto/x509 and the smx509 backend, so callers do not need to
// distinguish between standard and SM2 certificates for parsing, verification,
// and pool management.
//
// # Status
//
// This is the recommended entry point for certificate operations.
// For lower-level SM2-aware X.509 operations, use the smx509 package directly.
package cert
