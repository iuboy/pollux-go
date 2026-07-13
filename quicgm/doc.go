// Package quicgm provides QUIC over the RFC 8998 SM4-GCM cipher suite
// (TLS_SM4_GCM_SM3, 0x00C6), integrating the GM cryptographic primitives from
// the tls13gm package with the vendored quic-go fork.
//
// The package exposes two layers:
//
//   - Connection layer: Listen/Dial/DialEarly, plus Listener/Conn/ServerConfig/
//     ClientConfig, provide RFC 9001 GM QUIC endpoints (server + client,
//     including 0-RTT). AntiReplayCache guards 0-RTT against replay; the default
//     in-memory implementation (NewAntiReplayCache) is single-process only.
//     Multi-replica deployments MUST inject a shared cache (e.g. Redis) — see the
//     AntiReplayCache interface — otherwise 0-RTT replays cannot be detected
//     across replicas. The connection state machine (ACK, retransmission, stream
//     multiplexing, congestion control) is provided by the vendored quic-go fork,
//     which polls the GM handshake via an injected GMCryptoSetup.
//   - Packet-protection layer: SealInitialPacket/OpenInitialPacket,
//     SealHandshakePacket/OpenHandshakePacket, Seal1RTTPacket/Open1RTTPacket,
//     and QUICPacketProtector implement the RFC 9001 §5 payload + header
//     protection (SM4-GCM AEAD with packet-number-based nonce, SM4-ECB header
//     mask). CRYPTO frame encode/decode (RFC 9000 §19.6) carries TLS handshake
//     messages; varint and packet-number truncation primitives follow
//     RFC 9000 §16/§17.1.
//
// The TLS 1.3 GM handshake itself is driven by tls13gm's
// ClientHandshaker/ServerHandshaker; quicgm feeds the resulting
// HandshakeSecrets into the packet protectors. This package does not run the
// TLS key exchange directly.
//
// Status: RFC 8998 transport-level GM QUIC, including Listen/Dial/DialEarly
// connection layer. ("Route C" denotes the SM4-GCM-SM3 cipher suite
// TLS_SM4_GCM_SM3, as opposed to "Route A" = standard AES-128-GCM QUIC.)
package quicgm
