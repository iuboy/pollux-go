// Package smx509 provides SM2-aware X.509 certificate handling,
// extending crypto/x509 with national cryptography support.
//
// It automatically selects the standard library or gmsm/smx509 backend
// based on the key type, so callers do not need to distinguish SM2 from
// standard ECDSA.
//
// Status: lower-level SM2-aware X.509 helper; for the recommended facade, use the cert package
package smx509
