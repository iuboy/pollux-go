# quic-go fork — patch set relative to upstream

**Upstream**: `github.com/quic-go/quic-go` v0.60.0
**Fork location**: `third_party/quic-go/` (module name preserved as
`github.com/quic-go/quic-go`, referenced via `replace` in the repo-root
`go.mod`, so internal imports need no rewriting).
**Reason for forking**: upstream has no public TLS injection point
(`internal/handshake.CryptoSetup` is internal; `crypto/tls` cipher suites are a
closed enum that panics on RFC 8998 IDs). The fork adds a GM (RFC 8998)
`CryptoSetup` implementation backed by `github.com/iuboy/pollux-go/tls13gm`
(handshake engine) + `quicgm` (packet protection). See
`docs/design/route-c-quic-gm.md` and the approved plan at
`/Users/ycq/.claude/plans/vectorized-singing-hoare.md`.

## Patch index

| File | Change | Phase | Status |
|------|--------|-------|--------|
| (baseline — verbatim copy of v0.60.0) | — | P0a | ✅ done |

## Planned patches (not yet applied)

| File | Change | Phase |
|------|--------|-------|
| `internal/handshake/crypto_setup.go` | `NewCryptoSetupClient`/`NewCryptoSetupServer` branch to `GMCryptoSetup` when `Config.GMSM4GCM` is set (only upstream file modified). | P0d |
| `internal/handshake/gm_crypto_setup.go` (new) | `GMCryptoSetup` implementing the full `CryptoSetup` interface over `tls13gm` handshakers. | P0d |
| `internal/handshake/gm_sealer.go` (new) | 4 sealer/opener adapters + `gm1RTTAEAD`, driving `tls13gm.AEAD` + SM4-ECB header mask (not reusing upstream `longHeaderSealer` — nonce-size incompatible). | P0c |
| `interface.go` | Add `Config.GMSM4GCM` / `Config.GMHandshakeConfig` fields (config signal). | P0d |

## Upgrade procedure

1. Bump the upstream tag in the repo-root `go.mod` `require` + `replace`.
2. Re-copy the new upstream tree into `third_party/quic-go/`.
3. Re-apply every patch listed above (this file is the checklist).
4. `git diff v0.60.0 v<N> -- internal/handshake/crypto_setup.go interface.go`
   to spot new upstream conflicts in the two touched files.
5. `go build ./... && go test ./...`.
