# OCR Findings — Follow-up Tracker

This document tracks the remaining findings from the open-code-review (OCR)
session `08698ef8-85f2-45aa-a067-3053bc9ccdcb` after the fix sweep on branch
`fix/ocr-findings-20260725`.

Items that have been fully resolved on the branch are NOT listed here — only
items that still require action (whether optional or scheduled). For a
complete audit history of what was done, see the git log of the branch.

## Summary

| Severity | Total | Fixed | False positive | Out-of-scope | Remaining |
|----------|-------|-------|----------------|--------------|-----------|
| Critical | 35    | 29    | 4              | 2            | 0         |
| High     | 106   | ~74   | ~7             | ~4           | ~21       |
| Medium   | 188   | ~55   | —              | —            | ~133      |
| Low      | 113   | ~30   | —              | —            | ~83       |
| **Total**| **443**| **~188** | **~11**    | **~6**       | **~237**  |

All remaining critical findings are confirmed false positives or upstream
dependencies (quic-go). The branch passes `go test -race -count=1 ./...` with
all packages green.

## Remaining Open Items

### A. CI / build configuration (optional tightening)

- **`.github/workflows/ci.yml`** — gosec excludes `G104/G304/G401/G402/G405/
  G501/G502/G505`. Each exclusion is annotated in `.gosec.json` and the
  Makefile comment. Tightening would require either per-call `//nosec`
  annotations or accepting CI noise on intentional GM-crypto call sites.
- **`Makefile`** — `test-integration` runs the full suite (Go build tags are
  additive). Documented in Round 11; further fix requires a test-naming
  convention (`TestIntegration*` prefix) across the integration suite.

### B. Optional defense-in-depth (nice-to-have, no correctness impact)

- **`cert/pool.go`** — `AppendCertsFromPEM` silently skips parse failures
  (returns only `bool`). Acceptable for a CertPool builder (matches
  `x509.CertPool.AppendCertsFromPEM`'s contract) but a sibling
  `AppendCertsFromPEMVerbose` returning the first error would aid debugging.
  Low priority — the current behavior matches the stdlib.

### C. Remaining medium/low (~240 items)

Mostly cosmetic, none affect correctness or security:

- Minor doc rewordings (most doc-accuracy findings already addressed)
- Optional bounds checks on message parsers (already cryptobyte-guarded)
- Performance nits (e.g. `bufio.Reader` 4KB/conn — accepted tradeoff)
- Style nits (constant naming, error message wording)

These can be picked off opportunistically; the branch is in a mergeable
state without them.

### D. Verified false positives (no action needed)

Kept for historical reference so the same findings are not re-investigated:

- `tls13gm/signature.go` (×2) — callers pass `transcript.Sum()`, not raw
  transcript bytes; the OCR misread the parameter name.
- `tlcp/engine_messages.go` raw cache "data race" — the TLCP handshake runs
  single-goroutine under `handshakeMutex`; documented on
  `tlcpHandshakeMessage` in Round 13.
- `quic/config.go` `MaxIncomingStreams` — already wired into `quic.Config`
  in `quic/listener.go`.
- `http/listener.go` `SetHandshakeTimeout`/`SetProtocolMask` "TOCTOU" — the
  `mu.Lock`/`mu.Unlock` in the setters and the matching critical section in
  `Accept` establish a Go memory model happens-before edge. The
  snapshot-then-release pattern is the intended hot-reload contract, not a
  TOCTOU bug. `tlsCfg`/`tlcpCfg` are set once at `NewHybridListener` and
  never mutated, so the unlocked read during the handshake is safe.
- `tlcp/engine_keyagreement.go` `sm2SharedKey` parameter order — verified
  against the sponsor/responder call sites (`sPub` is the local side's
  static public key in both directions); matches gmsm's MQV primitive.

## Scheduled Future Action: Deprecation shim removal

**Schedule: next minor release after the one that ships the `https` rename.**

When the `http` package was renamed to `https` (branch
`fix/ocr-findings-20260725`), a compatibility shim was left behind at
`http/doc.go`. The shim re-exports every public symbol of `https` via type
aliases and thin function wrappers so existing imports of
`github.com/iuboy/pollux-go/http` keep compiling, with staticcheck SA1019
flagging every use as deprecated.

The shim exists to give downstream code one minor-version migration window.
**It MUST be deleted in the next minor release** — keeping it indefinitely
defeats the rename (which exists precisely to stop colliding with `net/http`
at import sites) and the `https` package can never drop the alias-target
indirection while the shim is live.

### Removal checklist

When cutting the next minor release, do the following in a dedicated PR:

1. **Verify the migration window has elapsed.** The shim should have shipped
   in at least one tagged minor release (e.g. `v2.0` → remove in `v2.1`).
   Check `git log --oneline -- http/doc.go` for the introduction commit if
   unsure.

2. **Broadcast the removal in CHANGELOG and release notes** under a
   "Breaking Changes" section:
   ```
   - The deprecated `github.com/iuboy/pollux-go/http` shim package has been
     removed. Migrate all imports to
     `github.com/iuboy/pollux-go/https` (drop the `polluxhttp`/`polluxHttp`
     alias, change `polluxhttp.X` → `https.X`). The API surface is
     identical aside from the package name.
   ```

3. **Delete the entire `http/` directory:**
   ```
   git rm -r http/
   ```
   The directory contains only `doc.go` (the shim) — there is no other code
   to preserve. If `ls http/` shows anything other than `doc.go`, stop and
   investigate before `git rm`.

4. **Search the codebase for stray references** that may have crept in since
   the rename:
   ```
   grep -rn 'pollux-go/http"' --include='*.go' .
   grep -rn 'polluxhttp\.\|polluxHttp\.' --include='*.go' .
   ```
   Any hits are either new code written against the old name (migrate to
   `https`) or stale comments/docs (update).

5. **Run the full test suite** to confirm nothing in-tree depended on the
   shim:
   ```
   go build ./...
   go test -count=1 ./...
   ```
   The 5 test files under `test/` (`tls_http_test.go`, `tlcp_http_test.go`,
   `http_detect_test.go`, `http_cert_pool_test.go`, `hybrid_http_test.go`)
   were migrated to `https` in the rename commit; verify they have not
   regressed back to the old import path.

6. **Update documentation**: this file (`docs/ocr-followup.md`) and any
   README/architecture docs that mention the shim. The README was updated
   to `https` in the rename commit; check it has not regressed.

### Why a deprecation window rather than a hard cut

The rename is a pure ergonomics improvement (no behavior change), and
pollux-go's downstream consumers include both new and legacy codebases. A
one-minor-version window lets downstream maintainers migrate at their own
cadence without an immediate compile break, while the staticcheck SA1019
warnings make the deprecation unmissable in CI. Hard-cutting in the same
release that introduces the rename would force every consumer to do an
unplanned migration in lockstep, which is disproportionate for an
ergonomics-only change.

### Tracking

- Introduced: branch `fix/ocr-findings-20260725`, file `http/doc.go`.
- Scheduled removal: next minor release after the rename ships.
- Owner: whoever cuts the next minor release — assign during release
  planning so it is not forgotten.

## Branch State

- Branch: `fix/ocr-findings-20260725`
- Commits: see `git log --oneline fix/ocr-findings-20260725 --not main`
- Test gate: `go test -race -count=1 ./...` → all packages pass, 0 failures

## Completed Work Log (brief)

The following OCR items were resolved on this branch and are listed here
only so the work is auditable. No further action is needed on any of them.

- **Tier 1 (doc accuracy)** — all 4 doc-accuracy items fixed
  (gmstd ComputeSM2UserID, sm4/doc.go GCM nonce wording, sm2/doc.go
  key-exchange claim, kdf/doc.go example error handling).
- **Tier 2 (defense-in-depth)** — input-validation guards, DER canonical
  checks, key-hygiene cleanup on failure paths across tlcp/tls13gm/quicgm/
  smx509/jwt/http/cert.
- **Tier 3 (CI / perf / verify / test coverage)** — CI timeouts, pool batch
  add, KeyAgreement usage, base64 spec, concurrency contracts,
  HKDF/SM2KDF edge-case tests.
- **Tier 4 (breaking-change)** — all 5 Section A items resolved:
  - `http` → `https` package rename (with deprecation shim — see above).
  - `ServerOptions`/`ClientOptions` timeout API → `*time.Duration` pointer
    semantics with `Duration()`/`NoTimeout()` helpers.
  - `sm9.Verify` → returns `error`; `VerifyBool` retained for legacy
    callers; `ErrSignatureInvalid` sentinel added.
  - `pwHash.PasswordHasher` concurrency contract added to interface doc.
  - `http/listener.go` "TOCTOU" confirmed false positive (see Section D).
