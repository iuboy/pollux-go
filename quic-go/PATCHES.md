# quic-go fork — patch set relative to upstream

**Upstream**: `github.com/quic-go/quic-go` v0.64.0
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
| (baseline — verbatim copy of v0.60.0, since synced to v0.62.0 via `git subtree pull`) | — | P0a | ✅ done |
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
| `internal/handshake/gm_crypto_setup.go` (v0.62.0 adaptation) | Upstream split `EventReceivedReadKeys` into `EventReceived0RTTReadKeys` / `EventReceivedHandshakeReadKeys` / `EventReceived1RTTReadKeys`; `connection.go` now keys `cryptoStreamManager.Finish` on the per-level events. `installHandshakeKeys` emits the 0-RTT event first when the server has `ClientEarlyKeys` (retry of buffered 0-RTT packets), then the Handshake event. The 1-RTT event is role-timed: the client emits it after consuming the server flight; the server defers it to after the client Finished is verified — emitting it at ClientHello time (when tls13gm's key schedule first derives the secrets) would finish the Handshake CRYPTO stream early and reject the client's Finished as a protocol violation. | v0.62.0 | ✅ done |
| `internal/handshake/gm_crypto_setup_test.go` (v0.62.0 adaptation) | Comment sync only (the new event kinds; no assertion depended on the old single event). | v0.62.0 | ✅ done |
| `internal/handshake/gm_updatable.go` (v0.64.0 adaptation) | Upstream removed `protocol.KeyUpdateInterval` (moved to a package-local `defaultKeyUpdateInterval` behind the `keyUpdateInterval` atomic). `shouldInitiateKeyUpdate` now reads `keyUpdateInterval.Load()` — which also fixes a pre-existing divergence: `SetKeyUpdateInterval` previously did not govern GM connections. | v0.64.0 | ✅ done |
| `internal/handshake/gm_updatable.go` (3rd security review) | `Open()` key-phase mismatch branch rewritten to the upstream structure: a late previous-phase packet (local update, peer not switched yet) decrypts via `prevRcvKM` WITHOUT advancing the phase — the old code rolled on every mismatch, so each late packet desynchronized the phase further until the connection died; a claimed update is trial-opened with the next-phase keys first, and the RFC 9001 §6.1 "keys updated too quickly" check runs only AFTER AEAD authentication, so a single corrupted packet with a flipped phase bit now counts toward the integrity limit instead of deterministically tearing down the connection. Also fixes `rollKeys`'s `keyPhase ^= 1` enum toggle: with the iota layout `KeyPhaseUndefined=0/KeyPhaseZero=1/KeyPhaseOne=2`, the first update produced `KeyPhaseUndefined` and `AppendShortHeader` then wrote bit 0 ("no update") forever — GM key updates had never actually worked. | 3rd review | ✅ done |
| `internal/handshake/gm_updatable_test.go` (new) | Four key-update scenarios: late packet after local update (prev-key echo), peer-initiated update (roll after authentication), update-too-quickly (KeyUpdateError only post-auth), corrupted packet with wrong phase bit (ErrDecryptionFailed, connection survives). The file previously had NO tests. | 3rd review | ✅ done |
| `gm_hook.go` + `internal/handshake/gm_crypto_setup.go` (3rd review P1) | `NewGMCryptoSetupServer` takes the transport-level `Allow0RTT` switch and ANDs it into the tls13gm-level `AllowEarlyData` (M9: a GM server can no longer accept 0-RTT the quic.Config forbids — the EncryptedExtensions early_data echo follows the same gate). The client emits `EventDiscard0RTTKeys` when the server rejects 0-RTT at EE or on an HRR (M10: the connection resets the 0-RTT streams / surfaces Err0RTTRejected instead of silently retransmitting at 1-RTT). `Get1RTTOpener` on the server returns ErrKeysNotYetAvailable until the client's Finished is verified (M13: restores the upstream "handshake complete ⇒ peer authenticated" invariant; early 1-RTT packets buffer and replay). `ConnectionState` now carries the negotiated ALPN protocol. | 3rd review P1 | ✅ done |
| `internal/handshake/gm_crypto_setup.go` + `interface.go` (3rd review M11/M12) | 0-RTT parameter plumbing, mirroring upstream crypto_setup.go: `StartHandshake` emits `EventRestoredTransportParameters` when the client holds BOTH 0-RTT keys and the server's transport parameters saved with the ticket (releases DialEarly's early connection; without saved params the 0-RTT keys are dropped, crypto/tls's "Not doing 0-RTT"); the server's 0-RTT admission additionally requires the ticket's saved parameters to pass `ourParams.ValidFor0RTT` (params changed ⇒ 0-RTT declined, resumption continues); `GetSessionTicket` embeds the server's marshaled parameters in the ticket (tls13gm v0x03 appData); `GMOnClientSessionTicket` delivers the server's EE parameters alongside the identity/PSK/age. | 3rd review M11/M12 | ✅ done |
| `internal/handshake/gm_crypto_setup.go` (3rd review M7) | `ChangeConnectionID` implemented (was a no-op): after a Retry, the Initial keys are re-derived from the NEW DCID per RFC 9001 §5.2 (`reinitInitialKeys` → `tls13gm.DeriveQUICInitialSecrets`), so post-Retry packets actually open. Previously every GM connection that received a Retry failed interop (both directions sealed/opened under the ORIGINAL DCID's keys). Derivation failure panics — the `CryptoSetup` interface has no error return, matching upstream's "cannot fail" invariant for a 32-byte destConnID. Test: `gm_retry_test.go`. | 3rd review M7 | ✅ done |
| `internal/handshake/gm_crypto_setup.go` + `gm_updatable.go` + `gm_sealer.go` (3rd review P2) | Low-severity batch: 0-RTT opener/sealer are now CACHED (`zeroRTTOpener/zeroRTTSealer`, dropped at every `DiscardEarlyKeys` site and on Close) — they were rebuilt per call, resetting the opener's `highestRcvdPN` every packet, so truncated packet numbers decoded against a zero baseline and 0-RTT packets failed AEAD once the peer's PN crossed a 2-byte epoch (upstream caches `zeroRTTOpener` likewise); `prevRcvKM` now expires after 3×(approximate PTO) via `prevRcvKMExpiry` started at both key-update commit points (RFC 9001 §6.1 — previously retained for the connection lifetime); `rollKeys` zeroes the superseded rolling traffic secrets, `gmUpdatableAEAD.Zero` exposed for explicit post-connection wipe (NOT auto-called from Close: the teardown path seals CONNECTION_CLOSE with the 1-RTT keys after CryptoSetup.Close); Close wipes the harvested resumption PSK/identity; `gmLongOpener` enforces the AEAD integrity limit (RFC 9001 §6.6) instead of an unbounded pre-1-RTT decryption oracle; `NextEvent` clears the popped slot so flight bytes stop pinning memory. | 3rd review P2 | ✅ done |
| `config.go` (v0.64.0 merge note) | Upstream dropped the `initialPacketSize` normalization block from `populateConfig` (InitialPacketSize fallback moved to the connection layer) and kept a direct `return &Config{...}`; the merge kept the fork's `cfg := / copyGMConfigFields / return cfg` wrapper over upstream's new literal body. | v0.64.0 | ✅ done |

Note: `internal/handshake/crypto_setup.go` is **not** modified — the GM branch
lives in `connection.go` (the call sites), not inside the `cryptoSetup` struct.
As of P0f the call sites delegate to `gm_hook.go`, so the only upstream files
the fork touches are `interface.go` (3 struct fields), `config.go` (1 function
call), and `connection.go` (2 hook calls).

v0.61.0→v0.62.0 merge note: the v0.60.0→v0.61.0 sync had been done by manual
copy, so this subtree pull's merge base still reflected v0.60.0 — files the
fork had never touched (workflows, framer, send_stream, capsule, …) showed
content conflicts that were resolved by verifying `git diff v0.61.0:<path>
HEAD:quic-go/<path>` was empty and taking the upstream side. From this commit
on the subtree merge base is correct, so future pulls conflict only where the
fork actually diverges.

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
