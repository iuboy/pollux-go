package gmstd

import "github.com/ycq/pollux/sm3"

// SM2KDF implements the SM3-based key derivation function (GM/T 0003.4-2012).
// z is the shared secret, klen is the desired output length in bytes.
func SM2KDF(z []byte, klen int) ([]byte, error) {
	return sm3.KDF(z, klen)
}
