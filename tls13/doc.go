// Package tls13 provides secure TLS 1.3 configuration builders for servers and clients.
//
// This package only configures standard Go crypto/tls with TLS 1.3 as the minimum
// version. It does not provide national cryptographic TLS (RFC 8998) or TLCP.
// For RFC 8998 GM QUIC packet protection, see quicgm.
package tls13
