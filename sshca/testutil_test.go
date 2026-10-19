package sshca

// 测试侧密钥生成辅助。生产 CA 密钥由应用装配层生成（经 keycrypt 落盘），
// 本包不提供默认密钥对生成（避免暗示有生产调用方）。

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// GenerateKeyPair 生成 RSA-2048 测试密钥对
func GenerateKeyPair() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	return KeyPairFromRawKey(key)
}

// GenerateED25519KeyPair 生成 ED25519 测试密钥对
func GenerateED25519KeyPair() (*KeyPair, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return KeyPairFromRawKey(privKey)
}
