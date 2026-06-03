package sm4

import (
	"encoding/binary"
	"errors"
)

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

	result := make([]byte, 0, length)
	blocks := (length + BlockSize - 1) / BlockSize

	for i := 1; i <= blocks; i++ {
		// Build the fixed-input data: label || 0x00 || context
		// so we only allocate it once.
		fixedInput := make([]byte, 0, len(label)+1+len(context)+4)
		fixedInput = append(fixedInput, label...)
		fixedInput = append(fixedInput, 0x00)
		fixedInput = append(fixedInput, context...)

		// Build round input: [i] || fixedInput || [L in bits]
		roundInput := make([]byte, 0, 4+len(fixedInput)+4)
		counter := make([]byte, 4)
		binary.BigEndian.PutUint32(counter, uint32(i))
		roundInput = append(roundInput, counter...)
		roundInput = append(roundInput, fixedInput...)
		lBits := make([]byte, 4)
		binary.BigEndian.PutUint32(lBits, uint32(length*8))
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
