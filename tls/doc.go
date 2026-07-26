// Package tls provides a cipher suite ID registry for Chinese national cryptographic
// algorithms. It does NOT implement a complete TLS handshake. These suite IDs cannot
// be directly passed to crypto/tls.Config.CipherSuites — Go's standard library does
// not support these suites.
//
// # Related packages
//
//   - tls13: configures standard crypto/tls for TLS 1.3-only connections (international
//     algorithms only — AES-GCM, not GM). Use this for production TLS 1.3 without GM.
//   - tls13gm: RFC 8998 GM cipher suites (TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3) for TLS 1.3
//     over QUIC. This is the GM TLS 1.3 path.
//   - tlcp: GB/T 38636-2020 TLCP 1.1 (GM TLS 1.2 variant) with dual SM2 certificates.
//   - quicgm: RFC 8998 GM QUIC packet protection using the suite IDs defined here.
//
// Status: cipher suite registry only (not a complete TLS implementation)
package tls
