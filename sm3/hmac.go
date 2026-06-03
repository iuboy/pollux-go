package sm3

import (
	"crypto/hmac"
	"hash"
)

// NewHMAC 返回使用 SM3 的 HMAC 实例。
// HMAC-SM3 满足 GB/T 35275-2017 要求。
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(New, key)
}
