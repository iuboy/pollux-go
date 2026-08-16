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
// Primitive wrappers (delegate to gmsm, inherit its audit status):
//   - sm2: SM2 digital signatures and key exchange (wraps gmsm/sm2)
//   - sm3: SM3 hash function (wraps gmsm/sm3)
//   - sm4: SM4 block cipher with GCM/CBC modes (wraps gmsm/sm4)
//   - sm9: SM9 identity-based encryption (wraps gmsm/sm9)
//   - zuc: ZUC stream cipher (wraps gmsm/zuc)
//   - aes: AES-256-GCM convenience wrappers (international counterpart to sm4)
//
// Standard helpers and derivations:
//   - gmstd: GM/T standard helper functions (hash, KDF, key generation)
//   - kdf: Hash-agnostic PBKDF2 key derivation (SM3 or SHA-256)
//   - sha: SHA-256/HKDF/HMAC wrappers (international counterpart to sm3)
//   - jwt: JWT signing (SM2-SM3 and HMAC-SHA-256/512)
//   - pwHash: PHC-format password hashing (argon2id and PBKDF2-SM3)
//   - keycrypt: encrypted private-key at-rest storage (PKCS#8 PBES2) and
//     key generators for RSA/ECDSA/Ed25519/SM2
//   - kmc: Key Management Center abstraction for the GM dual-certificate
//     model (Manager interface; LocalKMC dev placeholder; SDF/GM-T 0018
//     implementations plug in)
//
// Certificate and protocol integration:
//   - smx509: SM2-aware X.509 certificate creation, parsing, verification,
//     and OCSP responses (including the RFC 6960 §4.4.1 nonce echo)
//   - cert: High-level certificate management facade
//   - crl: X.509 CRL generation/caching/fan-out with injected Authority and
//     NumberSource abstractions (SM2 keys sign with SM2+SM3)
//   - sshca: SSH certificate authority — user/host certificate signing,
//     validation, and KRL generation (x/crypto/ssh parses KRLs but cannot
//     generate them)
//   - tls: TLS cipher suite registry (national suite IDs only)
//   - tls13: Standard TLS 1.3 configuration builders
//   - tlcp: TLCP 1.1 protocol (EXPERIMENTAL — pending security audit)
//   - tls13gm: RFC 8998 TLS 1.3 GM cipher suites
//   - quicgm: RFC 9001 QUIC packet protection with SM4-GCM
//   - https: HTTP server/client helpers for TLS, TLCP, TLS 1.3, and hybrid
//     (the deprecated `http` shim re-exports this package and will be removed)
//
// Internal:
//   - internal/memsecure: Secure memory operations for key material
//   - internal/panicsafe: Panic-to-error conversion at API boundaries
//
// The primitive wrappers (sm2/sm3/sm4/sm9/zuc) delegate to gmsm and inherit
// its audit status. TLCP is EXPERIMENTAL pending independent security audit.
package pollux
