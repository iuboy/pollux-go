// Package tls13gm provides the RFC 8998 TLS 1.3 GM (国密) stack — the SM4-GCM,
// curveSM2, SM2, and SM3 cipher suite (TLS_SM4_GCM_SM3, 0x00C6) that the Go
// standard library crypto/tls does not support. It is a GM complement to
// crypto/tls: standard TLS 1.3 suites still use crypto/tls, and tls13gm covers
// the GM-only peers required by Chinese compliance.
//
// The package has two layers:
//
//   - Cryptographic primitives: the RFC 8998 key schedule (early/handshake/master
//     secrets), SM4-GCM AEAD, SM4-ECB header protection, curveSM2 ECDHE,
//     CertificateVerify sign/verify, and the QUIC (RFC 9001) packet-key
//     derivation.
//   - Handshake engine: ClientHandshaker and ServerHandshaker drive a
//     transport-agnostic TLS 1.3 GM handshake. They produce and consume raw
//     handshake-message bytes and emit three levels of traffic secrets — Initial,
//     Handshake, and Application — matching crypto/tls's internal handshake
//     layer. A QUIC transport feeds these messages through CRYPTO frames
//     (RFC 9001); a TCP record layer could consume them the same way.
//     Session tickets (EncryptSessionTicket/DecryptSessionTicket) and PSK
//     derivation (DeriveResumptionMasterSecret/DeriveResumptionPSK) enable
//     resumption and 0-RTT.
//
// Transport scope. The handshake engine is transport-agnostic: it does not
// include a TLS record layer, Dial, or Listen over TCP. The QUIC connection
// state machine (ACK, retransmission, stream multiplexing, congestion control)
// is handled by quic-go; tls13gm provides the GM primitives and handshake logic
// that quic-go's crypto/tls integration normally provides.
//
// Status: RFC 8998 GM complement to crypto/tls (Route C).
package tls13gm
