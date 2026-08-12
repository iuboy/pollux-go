package sm4

import (
	"crypto/cipher"
	"crypto/subtle"
	"hash"

	"github.com/emmansun/gmsm/cbcmac"
)

// CMAC implements the Cipher-based Message Authentication Code (CMAC)
// algorithm per NIST SP 800-38B, using SM4 as the underlying block cipher.
//
// The CMAC finalization (subkey derivation + last-block padding + tag
// computation) is delegated to github.com/emmansun/gmsm/cbcmac, a vetted
// implementation already used elsewhere in this module. The one-shot MAC()
// path of gmsm/cbcmac is correct on all NIST SP 800-38B test vectors.
//
// gmsm's StreamingMAC.Write has a known multi-part buffering defect where
// split writes can produce a different tag than a single write of the same
// bytes (verified: 17-byte message, 16+3 split, etc.). CMAC's contract
// requires the tag to be independent of how the input is chunked, so this
// wrapper does NOT forward Write calls to gmsm incrementally. Instead it
// buffers all written bytes and runs the full MAC in Sum via the correct
// one-shot path. This is slightly more memory-heavy than a true streaming
// implementation but is simple, obviously correct, and safe.
//
// Concurrency: CMAC is NOT safe for concurrent use. The Write/Sum/Reset
// methods mutate internal buffer fields without synchronization, matching
// the contract of the standard library's hash.Hash (which also does not
// require concurrency safety). Callers sharing a CMAC across goroutines must
// serialize access externally; for parallel MAC computation, construct one
// CMAC per goroutine.
type CMAC struct {
	block cipher.Block // kept so Sum can build a fresh, zero-state gmsm MAC
	buf   []byte       // accumulates all written bytes until Sum/Reset
}

// NewCMAC creates a new SM4-CMAC instance with the given 16-byte key.
func NewCMAC(key []byte) (*CMAC, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &CMAC{block: block}, nil
}

// Write absorbs data into the CMAC buffer. The bytes are not processed until
// Sum is called, so any chunking of the input produces the same tag.
func (c *CMAC) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	return len(p), nil
}

// Sum returns the CMAC tag, appending it to b. It does not change the
// underlying state (a fresh MAC is built from the buffered bytes).
func (c *CMAC) Sum(b []byte) []byte {
	// Build a fresh MAC in zero state and run the correct one-shot path.
	// cbcmac.NewCMAC is cheap (one block encrypt for subkey derivation) and
	// does not mutate c.block, so this is safe to call repeatedly.
	mac := cbcmac.NewCMAC(c.block, BlockSize)
	tag := mac.MAC(c.buf)
	return append(b, tag...)
}

// Reset resets the CMAC to its initial state, discarding all buffered bytes.
// The underlying block cipher is stateless (just a key schedule), so there is
// nothing else to clear.
func (c *CMAC) Reset() {
	c.buf = nil
}

// Size returns the CMAC tag size in bytes (16).
func (c *CMAC) Size() int { return BlockSize }

// BlockSize returns the underlying block size (16).
func (c *CMAC) BlockSize() int { return BlockSize }

// ComputeCMAC computes the SM4-CMAC of data in one shot.
func ComputeCMAC(key, data []byte) ([]byte, error) {
	h, err := NewCMAC(key)
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// VerifyCMAC reports whether the given MAC matches the computed CMAC.
// The comparison is constant-time (crypto/subtle) so the result bit does not
// leak via timing.
func VerifyCMAC(key, data, mac []byte) bool {
	expected, err := ComputeCMAC(key, data)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected, mac) == 1
}

// cmacHash adapts CMAC to the hash.Hash interface for interop with code that
// consumes a generic hash (e.g. HMAC constructions). It embeds *CMAC which
// already satisfies hash.Hash.
type cmacHash struct {
	*CMAC
}

// NewCMACHash returns a hash.Hash backed by SM4-CMAC.
func NewCMACHash(key []byte) (hash.Hash, error) {
	c, err := NewCMAC(key)
	if err != nil {
		return nil, err
	}
	return &cmacHash{CMAC: c}, nil
}
