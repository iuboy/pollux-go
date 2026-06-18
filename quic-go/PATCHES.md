# quic-go fork — patch set relative to upstream

**Upstream**: `github.com/quic-go/quic-go` v0.60.0
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

| File | Change | Phase | Status |
|------|--------|-------|--------|
| (baseline — verbatim copy of v0.60.0) | — | P0a | ✅ done |
| `internal/handshake/gm_sealer.go` (new) | 4 sealer/opener adapters driving `tls13gm.AEAD` + SM4-ECB header mask (not reusing upstream `longHeaderSealer` — nonce-size incompatible). | P0c | ✅ done |
| `internal/handshake/gm_sealer_test.go` (new) | adapter byte-consistency / round-trip tests. | P0c | ✅ done |
| `interface.go` | `Config.GMSM4GCM` + `Config.GMHandshakeConfig` fields + `GMHandshakeConfig` type; import `pollux-go/tls13gm`. | P0d | ✅ done |
| `config.go` | `populateConfig` must copy `GMSM4GCM`/`GMHandshakeConfig` — without this, `Transport.Listen`/`Dial` reset them to zero and the GM branch is never taken. | P0e | ✅ done |
| `connection.go` | Branch at the two `NewCryptoSetup{Client,Server}` call sites: when `conf.GMSM4GCM`, build `handshake.NewGMCryptoSetup{Client,Server}` and ignore `*tls.Config`. | P0d | ✅ done |
| `internal/handshake/gm_crypto_setup.go` (new) | `GMCryptoSetup` implementing the full `CryptoSetup` interface over `tls13gm` handshakers. | P0d | ✅ done |
| `internal/handshake/gm_crypto_setup_test.go` (new) | end-to-end (no-UDP) handshake + 1-RTT cross-decrypt + transport-parameter exchange. | P0d | ✅ done |

Note: `internal/handshake/crypto_setup.go` is **not** modified — the GM branch
lives in `connection.go` (the call sites), not inside the `cryptoSetup` struct.

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
(`connection.go`, `config.go`, `interface.go`, and the `gm_*.go` additions —
this file is the patch checklist), then:

```bash
go build ./... && go test ./...
```

The upstream module name is unchanged, so the repo-root `go.mod` `replace` needs
no edit unless the upstream tag in `require` should be bumped for clarity.
