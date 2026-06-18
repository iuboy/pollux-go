// Package tls provides a cipher suite ID registry for Chinese national cryptographic
// algorithms. It does NOT implement a complete TLS handshake. These suite IDs cannot
// be directly passed to crypto/tls.Config.CipherSuites — Go's standard library does
// not support these suites. For production TLS 1.3, use the tls13 package.
// For RFC 8998 GM QUIC packet protection using these suite IDs, see quicgm.
//
// Status: cipher suite registry only (not a complete TLS implementation)
package tls
