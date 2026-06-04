package gmstd

import (
	"crypto/rand"
	"errors"
)

// GenerateSM4Key 生成 16 字节随机 SM4 密钥。
func GenerateSM4Key() ([]byte, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("gmstd: key generation failed")
	}
	return key, nil
}

// GenerateNonce 生成指定长度的随机 nonce。
func GenerateNonce(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("gmstd: invalid size")
	}
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("gmstd: random generation failed")
	}
	return nonce, nil
}
