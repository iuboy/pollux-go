// Package tlcp implements the Transport Layer Cryptography Protocol (TLCP),
// the Chinese national standard for transport-layer security (GB/T 38636-2020).
//
// EXPERIMENTAL — this package has not undergone independent third-party security audit.
// It is not recommended for production use until formally audited.
// The API may change in future versions.
//
// TLCP (Transport Layer Cryptography Protocol) is the Chinese national standard
// for transport-layer cryptography, standard number: GB/T 38636-2020.
//
// This package is a wrapper around gotlcp (gitee.com/Trisia/gotlcp), providing a
// Go-idiomatic API consistent with the pollux-go ecosystem while isolating consumers
// from direct dependencies on the underlying implementation library.
//
// Differences between TLCP and RFC 8998:
//   - TLCP (GB/T 38636-2020) is a Chinese national standard that defines a TLS protocol
//     variant based on national cryptographic algorithms
//   - RFC 8998 is an IETF publication "SM2 Cipher Suites for TLS 1.3", focused on TLS 1.3
//   - This package implements TLCP 1.1 (based on TLS 1.2), not RFC 8998's TLS 1.3 national
//     cipher suites
//   - For RFC 8998 related constants, see the tls13gm package (experimental)
//
// Status: EXPERIMENTAL — pending independent security audit
package tlcp
