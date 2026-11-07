// Package tlcp implements the Transport Layer Cryptography Protocol (TLCP),
// the Chinese national standard for transport-layer security (GB/T 38636-2020).
//
// # Status: EXPERIMENTAL
//
// This package has NOT undergone independent third-party security audit. It is
// not recommended for production use until formally audited. The API may
// change in future versions. (This single declaration replaces the previous
// duplicate status notes; if the audit status changes, update it here only.)
//
// TLCP (Transport Layer Cryptography Protocol) is the Chinese national standard
// for transport-layer cryptography, standard number: GB/T 38636-2020.
//
// This package provides a native, self-contained TLCP implementation (no
// external TLCP library dependency). The protocol engine — handshake state
// machines, record layer, SM2/SM3/SM4 cipher suites, and session resumption —
// is implemented in the engine_*.go files, exposed through a Go-idiomatic API
// consistent with the pollux-go ecosystem.
//
// # Differences between TLCP and RFC 8998
//
//   - TLCP (GB/T 38636-2020) is a Chinese national standard that defines a
//     TLS protocol variant based on national cryptographic algorithms.
//   - RFC 8998 is an IETF publication "SM2 Cipher Suites for TLS 1.3",
//     focused on TLS 1.3.
//   - This package implements TLCP 1.1 (based on TLS 1.2), not RFC 8998's
//     TLS 1.3 national cipher suites.
//   - For RFC 8998 related constants, see the tls13gm package. (Note:
//     unlike this package, tls13gm does NOT carry an EXPERIMENTAL marker —
//     its Status section declares it a stable RFC 8998 complement. The
//     "(experimental)" annotation that appeared here in earlier versions
//     was inaccurate and has been removed.)
//
// # 并发语义
//
// Conn 支持并发的 Read 与 Write 调用（对齐 stdlib crypto/tls）。每次 Write
// 调用是原子的：一次 Write（可能拆成多条 16KB 记录）的全部记录在 wire 上连
// 续出现，不会被另一个并发 Write 或 Close 的 close_notify 告警切开。关闭中
// 的 close_notify 亦持同一写锁排队，只会出现在所有已开始/完成的应用数据记录
// 之后。中途失败的 Write 返回已完整发出的字节数，此时连接应视为损坏并放弃
// （与 crypto/tls 一致，不存在「部分写后可继续」的恢复语义）。
package tlcp
