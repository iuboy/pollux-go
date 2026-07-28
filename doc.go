// Package pollux provides Go integration tooling for Chinese national cryptographic
// (国密/GM) algorithms and protocols.
//
// Pollux is a GM security integration toolkit — not a cryptography implementation.
// All core algorithms are provided by github.com/emmansun/gmsm; pollux adds:
//   - Protocol integration (TLCP 1.1 handshake, HTTP helpers, QUIC-GM)
//   - SM2-aware X.509 certificate handling (smx509)
//   - Ergonomic Go-idiomatic APIs wrapping gmsm primitives
//   - Secure memory operations for key material (internal/memsecure)
//
// # Sub-packages
//
//   - sm2: SM2 digital signatures and key exchange (wraps gmsm/sm2)
//   - sm3: SM3 hash function (wraps gmsm/sm3)
//   - sm4: SM4 block cipher with GCM/CBC modes (wraps gmsm/sm4)
//   - sm9: SM9 identity-based encryption (wraps gmsm/sm9)
//   - zuc: ZUC stream cipher (wraps gmsm/zuc)
//   - gmstd: GM/T standard helper functions
//   - smx509: SM2-aware X.509 certificate creation, parsing, and verification
//   - cert: High-level certificate management facade
//   - tls: TLS cipher suite registry (national suite IDs only)
//   - tls13: Standard TLS 1.3 configuration builders (Route A)
//   - tlcp: TLCP 1.1 protocol (EXPERIMENTAL — pending security audit)
//   - tls13gm: RFC 8998 TLS 1.3 GM cipher suites (interop-verified, Route C)
//   - quicgm: RFC 9001 QUIC packet protection with SM4-GCM (Route C)
//   - http: HTTP server/client helpers for TLS, TLCP, and hybrid
//
// The primitive wrappers (sm2/sm3/sm4/sm9/zuc) delegate to gmsm and inherit
// its audit status. TLCP is EXPERIMENTAL pending independent security audit.
package pollux
