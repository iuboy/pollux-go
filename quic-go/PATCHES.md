# quic-go fork — patch set relative to upstream

**Upstream**: `github.com/quic-go/quic-go` v0.61.0
**Fork location**: `quic-go/` at the repo root (module name preserved as
`github.com/quic-go/quic-go`, referenced via `replace` in the repo-root
`go.mod`, so internal imports need no rewriting).
**Reason for forking**: upstream has no public TLS injection point
(`internal/handshake.CryptoSetup` is internal; `crypto/tls` cipher suites are a
closed enum that panics on RFC 8998 IDs). The fork adds a GM (RFC 8998)
`CryptoSetup` implementation backed by `github.com/iuboy/pollux-go/tls13gm`
(handshake engine) + `quicgm` (packet protection). See
`docs/design/architecture.md`.

## Patch index

The fork's GM-specific code is centralized in dedicated `gm_*.go` files so the
upstream files stay as close to their original form as possible. This minimizes
`git subtree pull` conflicts on upgrade — the patched upstream files
(`interface.go`, `config.go`, `connection.go`) carry only the minimum delta
required to route into the GM hooks.

| File | Change | Phase | Status |
|------|--------|-------|--------|
| (baseline — verbatim copy of v0.60.0) | — | P0a | ✅ done |
| `internal/handshake/gm_sealer.go` (new) | 4 sealer/opener adapters driving `tls13gm.AEAD` + SM4-ECB header mask (not reusing upstream `longHeaderSealer` — nonce-size incompatible). | P0c | ✅ done |
| `internal/handshake/gm_sealer_test.go` (new) | adapter byte-consistency / round-trip tests. | P0c | ✅ done |
| `gm_config.go` (new) | `GMHandshakeConfig` type + `copyGMConfigFields` helper; keeps `config.go`'s `populateConfig` free of GM field literals (returns to near-upstream form). | P0f | ✅ done |
| `gm_hook.go` (new) | `newGMCryptoSetup{Server,Client}Hook` — the only place the fork branches on `Config.GMSM4GCM`. `connection.go`'s two call sites collapse to a single hook call each. | P0f | ✅ done |
| `gm_hook_test.go` (new) | regression tests: hook returns `(nil,false)` when GM disabled; panics when GM enabled but config missing. | P0f | ✅ done |
| `interface.go` | `Config.GMSM4GCM` + `Config.GMHandshakeConfig` + `Config.GMOnClientSessionTicket` fields (the `GMHandshakeConfig` *type* moved to `gm_config.go`). Only the 3 struct fields remain here — Go forbids splitting a struct's fields across files. | P0d/P0f | ✅ done |
| `config.go` | `populateConfig` calls `copyGMConfigFields(cfg, config)` instead of listing the GM fields in the `&Config{...}` literal — keeps the literal byte-for-byte close to upstream. | P0e/P0f | ✅ done |
| `connection.go` | Two `NewCryptoSetup{Client,Server}` call sites now call `newGMCryptoSetup{Server,Client}Hook`; the `if conf.GMSM4GCM { ... } else { ... }` blocks were replaced by `if cs, ok := ...hook(...); ok { ... } else { upstream }`. | P0d/P0f | ✅ done |
| `internal/handshake/gm_crypto_setup.go` (new) | `GMCryptoSetup` implementing the full `CryptoSetup` interface over `tls13gm` handshakers. | P0d | ✅ done |
| `internal/handshake/gm_crypto_setup_test.go` (new) | end-to-end (no-UDP) handshake + 1-RTT cross-decrypt + transport-parameter exchange. | P0d | ✅ done |

Note: `internal/handshake/crypto_setup.go` is **not** modified — the GM branch
lives in `connection.go` (the call sites), not inside the `cryptoSetup` struct.
As of P0f the call sites delegate to `gm_hook.go`, so the only upstream files
the fork touches are `interface.go` (3 struct fields), `config.go` (1 function
call), and `connection.go` (2 hook calls).

## Upgrade procedure

The fork is a git subtree, so upstream upgrades merge normally (conflicts in the
patched files are visible to git, unlike the old vendored-copy approach).

```bash
# one-time: register the upstream remote (kept in .git/config, not committed)
git remote add quic-go-upstream https://github.com/quic-go/quic-go.git

# upgrade
git subtree pull --prefix=quic-go quic-go-upstream <new-tag> --squash
```

If the merge conflicts, resolve in the patched files
(`interface.go`, `config.go`, `connection.go` — the only upstream files the
fork modifies, per the patch index above — and the `gm_*.go` additions, which
are fork-only and rarely conflict), then:

```bash
go build ./... && go test ./...
```

The upstream module name is unchanged, so the repo-root `go.mod` `replace` needs
no edit unless the upstream tag in `require` should be bumped for clarity.
