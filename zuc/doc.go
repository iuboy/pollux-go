// Package zuc provides Go-idiomatic wrappers around gmsm/zuc.
//
// ZUC (祖冲之算法, GM/T 0001-2012) is a stream cipher used in 3GPP LTE.
// This package provides simplified API for ZUC-128/256, EEA3 encryption,
// and EIA3 authentication.
//
// # Security: key and IV reuse
//
// Reusing the same key and IV pair produces identical keystream output, which
// allows an attacker to recover plaintext via XOR (two-time pad attack).
// Each encryption or MAC operation must use a unique key/IV combination.
// For EEA3/EIA3, the count, bearer, and direction fields together serve as the
// IV-like diversifier — ensure count is incremented per frame.
//
// Status: wrapper around gmsm/zuc
package zuc
