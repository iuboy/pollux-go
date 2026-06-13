// Package quicgm provides QUIC packet protection using the RFC 8998 SM4-GCM
// cipher suite (TLS_SM4_GCM_SM3, 0x00C6), assembled from the cryptographic
// primitives exported by the tls13gm package.
//
// quicgm mirrors the relationship between quic-go and crypto/tls: it consumes
// the RFC 8998 key schedule, AEAD, and header-protection primitives provided by
// tls13gm and assembles the RFC 9001 §5 packet-protection operations:
//
//   - Payload protection: SM4-GCM AEAD with a packet-number-based nonce
//     (nonce = IV XOR packet_number).
//   - Header protection: an SM4-ECB mask applied to the first byte's low 4/5
//     bits and the packet number field (RFC 9001 §5.4).
//
// This package implements the packet-protection layer for the QUIC long-header
// Initial and Handshake packets and the short-header 1-RTT packet (RFC 9000
// §17), plus the minimal CRYPTO frame (RFC 9000 §19.6) that carries TLS
// handshake messages. It does not parse the full QUIC header grammar beyond the
// packet forms it builds and opens. The QUIC/TLS handshake itself is driven by
// tls13gm's ClientHandshaker/ServerHandshaker, whose HandshakeSecrets feed
// NewQUICPacketProtectorFromKeys; this package does not run the TLS key
// exchange. The QUIC connection state machine (ACK, retransmission, stream
// multiplexing, congestion control) remains the responsibility of quic-go.
//
// Status: RFC 8998 transport-level GM QUIC packet protection (Route C).
package quicgm
