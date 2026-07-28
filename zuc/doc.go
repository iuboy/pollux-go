// Package zuc provides Go-idiomatic wrappers around gmsm/zuc.
//
// ZUC (祖冲之算法, GM/T 0001-2012) is a stream cipher used in 3GPP LTE.
// This package provides simplified API for ZUC-128/256, EEA3 encryption,
// and EIA3 authentication.
//
// # Key and IV lengths
//
//   - ZUC-128: 16-byte (128-bit) key, 16-byte (128-bit) IV.
//   - ZUC-256: 32-byte (256-bit) key, 23-byte (184-bit) IV.
//
// NewCipher validates these lengths up front and returns a typed error
// naming the offending parameter.
//
// # EEA3/EIA3 diversifier fields
//
// For the 3GPP EEA3 (encryption) and EIA3 (integrity) modes, the IV is
// derived internally by gmsm from three fields per 3GPP TS 33.401:
//   - count (32-bit frame counter, MUST be incremented per frame)
//   - bearer (5-bit radio bearer identity, left-shifted into the IV)
//   - direction (1 bit: 0=uplink, 1=downlink)
//
// These are NOT passed as a raw IV; NewEEACipher/NewEIAHash accept them as
// separate parameters and gmsm assembles the 128-bit IV internally. Callers
// do not need to understand the bit layout.
//
// # Security: key and IV reuse
//
// Reusing the same key and IV pair produces identical keystream output, which
// allows an attacker to recover plaintext via XOR (two-time pad attack).
// Each encryption or MAC operation must use a unique key/IV combination.
// For EEA3/EIA3, increment count per frame and never reuse (count, bearer,
// direction) with the same key.
package zuc
