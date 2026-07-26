// Package cert provides a unified certificate facade for both standard X.509
// and SM2 (Chinese national cryptography) certificates.
//
// It wraps crypto/x509 and the smx509 backend, so callers do not need to
// distinguish between standard and SM2 certificates for parsing, verification,
// and pool management.
//
// # Scope
//
// This package covers:
//   - Parsing (ParseCertificate, ParseCertificatePEM, ParseCertificatesPEM)
//   - Verification (Verify, VerifyDualCerts)
//   - Pool management (NewPool, Pool.AddCert, Pool.AppendCertsFromPEM)
//   - Loading from PEM/file (LoadKeyPairPEM, LoadDualCertificatePEM, etc.)
//   - Standard/TLS config building (BuildClientTLSConfig, BuildServerTLSConfig,
//     BuildTLCPConfig)
//
// For private-key signing/decryption operations or certificate issuance, use
// the smx509 package or the relevant crypto sub-package directly.
//
// # Status
//
// This is the recommended entry point for the certificate operations listed
// above. For lower-level SM2-aware X.509 operations beyond this package's
// scope, use the smx509 package directly.
package cert
