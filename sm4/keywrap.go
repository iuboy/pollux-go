package sm4

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/iuboy/pollux-go/internal/memsecure"
)

// keyWrapIV is the RFC 3394 §2.2.3.1 default IV: 0xA6 repeated 8 times.
// Promoted from a per-call []byte literal to a package-level array so
// KeyWrap/KeyUnwrap do not allocate it on every invocation.
var keyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// KeyWrap implements the AES Key Wrap algorithm (RFC 3394) adapted for SM4.
//
// SM4 has a 128-bit block size like AES, so the algorithm is identical.
// The Key Encryption Key (KEK) must be 16 bytes. The plaintext key must be
// a multiple of 8 bytes and at least 16 bytes (two 8-byte semiblocks).
//
// Implementation status: this is a self-contained implementation of RFC 3394.
// As of gmsm v0.44.0 and golang.org/x/crypto v0.54.0, no vetted Go library
// exposes a standalone RFC 3394 key-wrap API, so the construction is kept
// in-tree. The integrity check on KeyUnwrap uses crypto/subtle constant-time
// comparison. The round-trip is covered by sm4/keywrap_test.go.
func KeyWrap(kek, plaintextKey []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, errors.New("sm4/keywrap: KEK must be 16 bytes")
	}
	if len(plaintextKey)%8 != 0 || len(plaintextKey) < 16 {
		return nil, errors.New("sm4/keywrap: plaintext key must be a multiple of 8 bytes and at least 16 bytes")
	}

	block, err := NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintextKey) / 8 // number of 64-bit semiblocks

	// RFC 3394 Section 2.2.3.1
	// Set A = IV (0xA6 repeated 8 times) — use the package-level keyWrapIV
	// constant instead of a per-call loop.
	A := make([]byte, 8)
	copy(A, keyWrapIV[:])

	// Copy plaintext semiblocks into R[1..n]
	R := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], plaintextKey[(i-1)*8:i*8])
	}
	// A and R[i] carry key-derived semiblocks; zero them before returning so the
	// material does not linger on the heap (consistent with the ZeroKey
	// convention used by the GCM one-shot helpers in this package).
	defer func() {
		memsecure.ZeroBytes(A)
		for i := 1; i <= n; i++ {
			memsecure.ZeroBytes(R[i])
		}
	}()

	for j := range 6 {
		for i := 1; i <= n; i++ {
			// B = AES(KEK, A || R[i])
			var input [16]byte
			copy(input[:8], A)
			copy(input[8:], R[i])
			var output [16]byte
			block.Encrypt(output[:], input[:])

			// A = MSB(64, B) ^ t where t = (n*j + i)
			t := uint64(n*j + i)
			aInt := binary.BigEndian.Uint64(output[:8])
			aInt ^= t
			binary.BigEndian.PutUint64(A, aInt)

			// R[i] = LSB(64, B)
			copy(R[i], output[8:])
		}
	}

	// C[0] = A, C[i] = R[i]
	ciphertext := make([]byte, 0, 8+len(plaintextKey))
	ciphertext = append(ciphertext, A...)
	for i := 1; i <= n; i++ {
		ciphertext = append(ciphertext, R[i]...)
	}
	return ciphertext, nil
}

// KeyUnwrap reverses KeyWrap, recovering the plaintext key.
func KeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, errors.New("sm4/keywrap: KEK must be 16 bytes")
	}
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, errors.New("sm4/keywrap: ciphertext must be a multiple of 8 bytes and at least 24 bytes")
	}

	block, err := NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) - 8) / 8

	// A = C[0]
	A := make([]byte, 8)
	copy(A, ciphertext[:8])

	// R[i] = C[i]
	R := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], ciphertext[i*8:(i+1)*8])
	}
	// R[i] will hold the recovered plaintext key semiblocks; zero them before
	// returning so the key material does not linger on the heap.
	defer func() {
		memsecure.ZeroBytes(A)
		for i := 1; i <= n; i++ {
			memsecure.ZeroBytes(R[i])
		}
	}()

	// Reverse: j from 5 to 0, i from n to 1
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// t = n*j + i
			t := uint64(n*j + i)
			aInt := binary.BigEndian.Uint64(A)
			aInt ^= t
			binary.BigEndian.PutUint64(A, aInt)

			// B = AES-1(KEK, (A ^ t) || R[i])
			var input [16]byte
			copy(input[:8], A)
			copy(input[8:], R[i])
			var output [16]byte
			block.Decrypt(output[:], input[:])

			copy(A, output[:8])
			copy(R[i], output[8:])
		}
	}

	// Check IV (constant-time comparison to prevent timing side channels).
	// keyWrapIV is the RFC 3394 default IV — promoted to a package-level
	// var so KeyUnwrap does not allocate a fresh []byte on every call.
	if subtle.ConstantTimeCompare(A, keyWrapIV[:]) != 1 {
		return nil, errors.New("sm4/keywrap: integrity check failed")
	}

	plaintext := make([]byte, 0, n*8)
	for i := 1; i <= n; i++ {
		plaintext = append(plaintext, R[i]...)
	}
	return plaintext, nil
}
