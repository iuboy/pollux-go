package gmstd

import "github.com/iuboy/pollux-go/sm3"

// SM2KDF implements the SM3-based key derivation function (GM/T 0003.4-2012).
// z is the shared secret and MUST be non-empty; klen is the desired output
// length in bytes and MUST be positive. Returns an error if z is empty,
// klen <= 0, or klen exceeds sm3.KDF's maximum (currently 1 GiB).
func SM2KDF(z []byte, klen int) ([]byte, error) {
	return sm3.KDF(z, klen)
}
