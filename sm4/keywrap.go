package sm4

import (
	"encoding/binary"
	"errors"
)

// KeyWrap implements the AES Key Wrap algorithm (RFC 3394) adapted for SM4.
//
// SM4 has a 128-bit block size like AES, so the algorithm is identical.
// The Key Encryption Key (KEK) must be 16 bytes. The plaintext key must be
// a multiple of 8 bytes and at least 16 bytes (two 8-byte semiblocks).
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
	// Set A = IV (0xA6 repeated 8 times)
	A := make([]byte, 8)
	for i := range A {
		A[i] = 0xA6
	}

	// Copy plaintext semiblocks into R[1..n]
	R := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], plaintextKey[(i-1)*8:i*8])
	}

	for j := 0; j <= 5; j++ {
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

	// Check IV
	for _, b := range A {
		if b != 0xA6 {
			return nil, errors.New("sm4/keywrap: integrity check failed")
		}
	}

	plaintext := make([]byte, 0, n*8)
	for i := 1; i <= n; i++ {
		plaintext = append(plaintext, R[i]...)
	}
	return plaintext, nil
}
