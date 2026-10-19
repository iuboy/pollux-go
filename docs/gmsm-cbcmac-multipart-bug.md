# gmsm/cbcmac StreamingMAC multi-part Write bug

This document records a defect discovered in `github.com/emmansun/gmsm/cbcmac`
(v0.44.0, also present in v0.44.1 — the cbcmac.go source is byte-identical
between the two). It is kept here as a reference for pollux-go maintainers and
as a ready-to-file upstream issue draft.

## Status

- **Discovered:** during pollux-go's CMAC migration to `gmsm/cbcmac`.
- **Affects pollux-go:** mitigated — `sm4/cmac.go` buffers all writes and runs
  the correct one-shot `MAC()` path in `Sum`. No correctness impact on pollux-go.
- **Upstream status:** NOT reported to gmsm yet (as of this writing). The draft
  below can be filed at <https://github.com/emmansun/gmsm/issues>.

## Summary

`cbcmac.NewCMAC` returns a `StreamingMAC` (implements `hash.Hash`). Its `Write`
method produces a **different tag than a single `Write` of the same total
bytes** whenever the message is **not a multiple of the block size** and the
data arrives in **more than one `Write` call**. This violates the CMAC contract
(and the `hash.Hash` contract) that the digest must be independent of how the
input is chunked.

The one-shot path (`MAC(src)`, or a single `Write` + `Sum`) is **correct** on
all NIST SP 800-38B test vectors.

## Reproduction

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/emmansun/gmsm/cbcmac"
    "github.com/emmansun/gmsm/sm4"
)

func main() {
    key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
    block, _ := sm4.NewCipher(key)
    msg, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae") // 17 bytes

    // One-shot — CORRECT
    m1 := cbcmac.NewCMAC(block, 16)
    m1.Write(msg)
    fmt.Printf("one-shot:     %s\n", hex.EncodeToString(m1.Sum(nil)))
    // => af0616150eb9bd3c3c8eb903b1ae1cb2

    // Split 16+1 — WRONG
    m2 := cbcmac.NewCMAC(block, 16)
    m2.Write(msg[:16])
    m2.Write(msg[16:])
    fmt.Printf("split 16+1:   %s\n", hex.EncodeToString(m2.Sum(nil)))
    // => 0ac9018ebda82cff7702698a8d2d9446  (should equal one-shot)

    // Byte-by-byte — WRONG
    m3 := cbcmac.NewCMAC(block, 16)
    for _, b := range msg {
        m3.Write([]byte{b})
    }
    fmt.Printf("byte-by-byte: %s\n", hex.EncodeToString(m3.Sum(nil)))
    // => 0ac9018ebda82cff7702698a8d2d9446  (should equal one-shot)
}
```

### Trigger matrix (SM4, 16-byte block)

| Message length | Single `Write` | Split `Write` |
|----------------|----------------|----------------|
| 16 B (1 block) | ✅ correct | ✅ correct |
| 32 B (2 blocks) | ✅ correct | ✅ correct |
| **17 B (1 block + 1 byte)** | ✅ correct | ❌ **wrong** |
| **any non-multiple-of-16** | ✅ correct | ❌ **wrong** |

The bug only manifests when (a) the total message is not a multiple of the
block size AND (b) the data is fed via multiple `Write` calls.

## Root-cause analysis

In `cbcmac.go`, `cmac.Write` (lines ~291–326) uses a "defer one block"
buffering strategy: it keeps the most recent block in `d.x` (with `d.nx`
tracking its fill level) and only processes earlier blocks via `d.block()`.
`cmac.checkSum` (lines ~349–367) then finalizes the deferred block with
subkey k1 (if complete) or k2 + padding (if incomplete).

The defect is in how `d.nx` is managed across `Write` calls when a prior call
left an incomplete block (`0 < nx < blockSize`) and the next call both
completes it AND extends past it. In that path the completed block is
processed, but the residual bytes land in `d.x` at an `nx` value that
`checkSum`'s finalization interprets with the wrong subkey/padding position.
Concretely, the `default` case in `checkSum`:

```go
default:
    subtle.XORBytes(c.tag, c.x, c.tag)
    c.tag[c.nx] ^= 0b10000000   // padding byte position derived from nx
    subtle.XORBytes(c.tag, c.k2, c.tag)
```

applies k2 (incomplete-block subkey) and places the 0x80 padding at `c.nx`,
but `c.nx` has drifted from its correct value due to the multi-call buffering,
so the wrong bytes are padded and the wrong subkey is selected.

For block-aligned messages the final `nx` is either 0 or `blockSize`, both of
which have dedicated (correct) cases in `checkSum`, so the bug is invisible
there.

## Suggested upstream fix

Replace the incremental `Write` buffering with the simpler and obviously
correct approach used by Go's own `crypto/sha512` and similar: buffer all
written bytes and compute the full MAC in `Sum`/`checkSum`. This trades a
little memory for correctness and matches what pollux-go's `sm4/cmac.go`
wrapper now does at the caller side.

Alternatively, audit the `nx` transitions in `Write` for the
incomplete→complete→overflow case and ensure `checkSum`'s three-way switch on
`nx` (0 / blockSize / other) always receives the value that matches the true
final-block state.
