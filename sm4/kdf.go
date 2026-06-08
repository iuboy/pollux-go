package sm4

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// maxDeriveKeyLength is the maximum allowed derived key material in bytes.
const maxDeriveKeyLength = 1024

// DeriveKey derives a key using SM4-CMAC in NIST SP 800-108 Counter Mode KDF.
//
// Input structure per round: [counter(4)] || label || 0x00 || context || [length_in_bits(4)]
// Each round's PRF is SM4-CMAC over the input, keyed by masterKey.
func DeriveKey(masterKey, label, context []byte, length int) ([]byte, error) {
	if len(masterKey) != KeySize {
		return nil, errors.New("sm4/kdf: master key must be 16 bytes")
	}
	if length <= 0 {
		return nil, errors.New("sm4/kdf: length must be positive")
	}
	if length > maxDeriveKeyLength {
		return nil, fmt.Errorf("sm4/kdf: length %d exceeds maximum %d", length, maxDeriveKeyLength)
	}

	result := make([]byte, 0, length)
	blocks := (length + BlockSize - 1) / BlockSize

	// Pre-build the fixed-input portion: label || 0x00 || context
	// This is identical across all rounds and only needs to be built once.
	fixedInput := make([]byte, 0, len(label)+1+len(context))
	fixedInput = append(fixedInput, label...)
	fixedInput = append(fixedInput, 0x00)
	fixedInput = append(fixedInput, context...)

	lBits := make([]byte, 4)
	binary.BigEndian.PutUint32(lBits, uint32(length*8))

	for i := 1; i <= blocks; i++ {
		// Build round input: [counter(4)] || fixedInput || [L in bits(4)]
		counter := make([]byte, 4)
		binary.BigEndian.PutUint32(counter, uint32(i))
		roundInput := make([]byte, 0, 4+len(fixedInput)+4)
		roundInput = append(roundInput, counter...)
		roundInput = append(roundInput, fixedInput...)
		roundInput = append(roundInput, lBits...)

		// PRF: SM4-CMAC over roundInput
		blockOut, err := ComputeCMAC(masterKey, roundInput)
		if err != nil {
			return nil, err
		}
		result = append(result, blockOut...)
	}

	return result[:length], nil
}
