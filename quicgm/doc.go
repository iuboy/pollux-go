// Package quicgm provides application-layer cryptographic protection using
// SM2/SM3/SM4 over standard QUIC/TLS 1.3 connections.
//
// This is NOT transport-layer RFC 8998. QUIC handles transport security via
// standard TLS 1.3; quicgm handles application payload protection with
// national cryptographic algorithms.
//
// Status: application-layer GM profile for QUIC
package quicgm
