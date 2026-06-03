package gmstd

import "github.com/ycq/pollux/sm3"

// SM2KDF 实现基于 SM3 的密钥派生函数 (GM/T 0003.4-2012)。
// z 是共享秘密，klen 是期望输出的字节长度。
func SM2KDF(z []byte, klen int) ([]byte, error) {
	return sm3.KDF(z, klen)
}
