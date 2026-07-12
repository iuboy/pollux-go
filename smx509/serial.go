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
// the upper bound for the encoded serial is also 20 octets. We cap at 2^159
// (not 2^160) so the most-significant bit is never set — this avoids the DER
// leading-0x00 sign byte that would push the encoding to 21 octets and violate
// the 20-octet limit. 159 bits still far exceeds the CA/Browser Forum 64-bit
// entropy minimum.
const serialBitLen = 159

// GenerateSerialNumber returns a cryptographically random positive integer
// suitable for an X.509 certificate serial number (RFC 5280 §4.1.2.2).
//
// The result is uniformly distributed in [1, 2^159), guaranteeing it fits in
// the 20-byte serial field without a DER leading sign byte while meeting the
// entropy recommendation for CA-issued certificates. Returns ErrSerialZero if
// the rare zero draw occurs (caller should retry).
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
