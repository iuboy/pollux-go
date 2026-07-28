package sm3

import (
	"errors"

	gmsmSM3 "github.com/emmansun/gmsm/sm3"
)

// KDF 实现 SM3-based 密钥派生函数 (GM/T 0003.4-2012)。
// z 是共享秘密，klen 是期望输出的字节长度。
func KDF(z []byte, klen int) ([]byte, error) {
	if klen <= 0 {
		return nil, errors.New("sm3/kdf: klen must be positive")
	}
	if len(z) == 0 {
		return nil, errors.New("sm3/kdf: empty input")
	}
	return gmsmSM3.Kdf(z, klen), nil
}
