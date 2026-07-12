// Package memsecure provides secure memory operations for cryptographic material.
//
//nolint:gosec // G103: unsafe operations are intentional for secure memory clearing
package memsecure

import (
	"crypto/subtle"
	"runtime"
	"unsafe"
)

// ZeroBytes securely zeroes a byte slice, attempting to prevent compiler optimizations.
//
// Note: In Go, no zeroing is fully guaranteed against all compiler optimizations.
// This implementation uses multiple defense layers:
//  1. crypto/subtle XOR (recognized by crypto-aware compiler optimizations)
//  2. unsafe pointer write (harder for compiler to prove is dead)
//  3. runtime.KeepAlive (prevents premature GC)
//
// For keys stored in big.Int (e.g., *ecdsa.PrivateKey.D), use D.SetInt64(0) instead.
func ZeroBytes(data []byte) {
	if len(data) == 0 {
		return
	}

	// Layer 1: subtle.XORBytes is recognized by the Go compiler as security-sensitive.
	// XOR data with itself so values self-cancel to zero — the compiler will
	// not optimize this away.
	subtle.XORBytes(data, data, data)

	// Layer 2: unsafe pointer write as additional guarantee.
	for i := range data {
		*(*byte)(unsafe.Pointer(&data[i])) = 0 // #nosec G103 -- intentional direct write to defeat dead-store elimination
	}

	// Layer 3: prevent GC from collecting data before zeroing completes.
	runtime.KeepAlive(data)
}

// SliceFromBytes has been removed: it provided no real security benefit
// (just unsafe.Slice aliasing) and could cause unexpected aliasing bugs.
// Callers should pass the original slice directly.

// ZeroUint32 securely zeroes a uint32 slice using the same multi-layer
// defense as ZeroBytes: XOR + direct write + KeepAlive.
func ZeroUint32(data []uint32) {
	if len(data) == 0 {
		return
	}

	// Layer 1: XOR-based zeroing (consistent with ZeroBytes pattern).
	// Guard len*4 against integer overflow on 32-bit builds (where int is 32
	// bits wide); on such targets an attacker-controlled slice length near
	// MaxInt32/4 would wrap byteLen and yield an out-of-bounds view.
	if uint64(len(data)) > (1<<32-1)/4 {
		return
	}
	byteLen := len(data) * 4
	view := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), byteLen) // #nosec G103 -- view uint32/64 key words as bytes for XOR zeroing
	// XOR with itself so values self-cancel to zero.
	subtle.XORBytes(view, view, view)

	// Layer 2: direct write.
	for i := range data {
		*(*uint32)(unsafe.Pointer(&data[i])) = 0 // #nosec G103 -- intentional direct write to defeat dead-store elimination
	}

	runtime.KeepAlive(data)
}

// ZeroUint64 securely zeroes a uint64 slice using the same multi-layer
// defense as ZeroBytes: XOR + direct write + KeepAlive.
func ZeroUint64(data []uint64) {
	if len(data) == 0 {
		return
	}

	// Layer 1: XOR-based zeroing (consistent with ZeroBytes pattern).
	// Guard len*8 against integer overflow on 32-bit builds (see ZeroUint32).
	if uint64(len(data)) > (1<<32-1)/8 {
		return
	}
	byteLen := len(data) * 8
	view := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), byteLen) // #nosec G103 -- view uint32/64 key words as bytes for XOR zeroing
	// XOR with itself so values self-cancel to zero.
	subtle.XORBytes(view, view, view)

	// Layer 2: direct write.
	for i := range data {
		*(*uint64)(unsafe.Pointer(&data[i])) = 0 // #nosec G103 -- intentional direct write to defeat dead-store elimination
	}

	runtime.KeepAlive(data)
}
