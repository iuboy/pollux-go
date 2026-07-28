package smx509

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// ErrSerialZero is returned when the generated serial number happens to be
// zero, which RFC 5280 §4.1.2.2 forbids (serial must be a positive integer).
var ErrSerialZero = errors.New("smx509: generated serial number is zero")

// serialBitLen is the serial number entropy length in bits. RFC 5280 §4.1.2.2
// requires CA certificates to use at least 20 bytes (160 bits) of randomness;
// the upper bound for the encoded serial is also 20 bytes. 160 bits satisfies
// both constraints.
const serialBitLen = 160

// GenerateSerialNumber returns a cryptographically random positive integer
// suitable for an X.509 certificate serial number (RFC 5280 §4.1.2.2).
//
// The result is uniformly distributed in [1, 2^160), guaranteeing it fits in
// the 20-byte serial field while meeting the 160-bit entropy recommendation
// for CA-issued certificates. Returns ErrSerialZero if the rare zero draw
// occurs (caller should retry).
func GenerateSerialNumber() (*big.Int, error) {
	maxValue := new(big.Int).Lsh(big.NewInt(1), serialBitLen)
	serial, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return nil, ErrSerialZero
	}
	return serial, nil
}
