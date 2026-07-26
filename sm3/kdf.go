package sm3

import (
	"errors"
	"fmt"

	gmsmSM3 "github.com/emmansun/gmsm/sm3"
)

// maxKDFLen bounds KDF output to prevent OOM on attacker-controlled klen.
// GM/T 0003.4-2012 uses a 32-bit counter (ct=1..2^32-1), so the theoretical
// maximum is (2^32-1) * 32 bytes; we cap well below that at 1 GiB, which is
// far beyond any legitimate key-derivation need.
const maxKDFLen = 1 << 30 // 1 GiB

// KDF 实现 SM3-based 密钥派生函数 (GM/T 0003.4-2012)。
// z 是共享秘密，klen 是期望输出的字节长度。
// 返回错误当 klen 非正、z 为空、或 klen 超过 maxKDFLen (1 GiB)。
func KDF(z []byte, klen int) ([]byte, error) {
	if klen <= 0 {
		return nil, errors.New("sm3/kdf: klen must be positive")
	}
	if len(z) == 0 {
		return nil, errors.New("sm3/kdf: empty input")
	}
	if klen > maxKDFLen {
		return nil, fmt.Errorf("sm3/kdf: klen %d exceeds maximum %d", klen, maxKDFLen)
	}
	return gmsmSM3.Kdf(z, klen), nil
}
