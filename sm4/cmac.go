package sm4

import (
	"crypto/cipher"
	"crypto/subtle"
	"hash"
)

// CMAC implements the Cipher-based Message Authentication Code (CMAC)
// algorithm per NIST SP 800-38B, using SM4 as the underlying block cipher.
type CMAC struct {
	k1, k2    []byte
	buffer    []byte // accumulates incoming data (partial block)
	state     []byte // running CBC-MAC chain (X_i)
	bufSize   int
	block     cipher.Block
	processed int
}

// NewCMAC creates a new SM4-CMAC instance with the given 16-byte key.
func NewCMAC(key []byte) (*CMAC, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Step 1: Encrypt zero block to get L
	zeroBlock := make([]byte, BlockSize)
	L := make([]byte, BlockSize)
	block.Encrypt(L, zeroBlock)

	// Step 2: Derive subkey K1 from L
	k1 := make([]byte, BlockSize)
	copy(k1, L)
	leftShift(k1)
	if L[0]&0x80 != 0 {
		k1[BlockSize-1] ^= 0x87
	}

	// Step 3: Derive subkey K2 from K1
	k2 := make([]byte, BlockSize)
	copy(k2, k1)
	leftShift(k2)
	if k1[0]&0x80 != 0 {
		k2[BlockSize-1] ^= 0x87
	}

	return &CMAC{
		k1:     k1,
		k2:     k2,
		buffer: make([]byte, BlockSize),
		state:  make([]byte, BlockSize),
		block:  block,
	}, nil
}

// leftShift shifts a byte slice left by one bit in place.
func leftShift(data []byte) {
	var overflow byte
	for i := len(data) - 1; i >= 0; i-- {
		newOverflow := data[i] >> 7
		data[i] = (data[i] << 1) | overflow
		overflow = newOverflow
	}
}

// Write absorbs data into the CMAC state.
func (c *CMAC) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		todo := BlockSize - c.bufSize
		if todo > len(p) {
			todo = len(p)
		}
		copy(c.buffer[c.bufSize:], p[:todo])
		c.bufSize += todo
		p = p[todo:]

		if c.bufSize == BlockSize {
			c.processBlock(c.buffer)
			c.bufSize = 0
		}
	}
	c.processed += written
	return written, nil
}

// processBlock XORs the block with the running CBC-MAC state and encrypts.
func (c *CMAC) processBlock(data []byte) {
	for i := 0; i < BlockSize; i++ {
		c.state[i] ^= data[i]
	}
	c.block.Encrypt(c.state, c.state)
}

// Sum returns the CMAC tag, appending it to b.
// It does not change the underlying state.
func (c *CMAC) Sum(b []byte) []byte {
	// Work on a copy of state + partial buffer to preserve internal state.
	lastBlock := make([]byte, BlockSize)
	copy(lastBlock, c.state[:])
	for i := 0; i < c.bufSize; i++ {
		lastBlock[i] ^= c.buffer[i]
	}

	if c.bufSize == BlockSize {
		// Complete last block: XOR with K1
		for i := 0; i < BlockSize; i++ {
			lastBlock[i] ^= c.k1[i]
		}
	} else {
		// Incomplete last block: pad with 10* and XOR with K2
		lastBlock[c.bufSize] ^= 0x80
		for i := c.bufSize + 1; i < BlockSize; i++ {
			lastBlock[i] = 0x00
		}
		for i := 0; i < BlockSize; i++ {
			lastBlock[i] ^= c.k2[i]
		}
	}

	// Encrypt the final block.
	tag := make([]byte, BlockSize)
	c.block.Encrypt(tag, lastBlock)
	return append(b, tag...)
}

// Reset resets the CMAC to its initial state.
func (c *CMAC) Reset() {
	c.buffer = make([]byte, BlockSize)
	c.state = make([]byte, BlockSize)
	c.bufSize = 0
	c.processed = 0
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
func VerifyCMAC(key, data, mac []byte) bool {
	expected, err := ComputeCMAC(key, data)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expected, mac) == 1
}

// cmacHash wraps CMAC to implement hash.Hash for interop.
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
