// See doc.go for the package documentation (godoc convention).
// This file: key-type constants and the KeyGenerator family.
package keycrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/iuboy/pollux-go/sm2"
)

// KeyType 密钥类型
type KeyType string

const (
	// KeyTypeRSA2048 RSA 2048 位
	KeyTypeRSA2048 KeyType = "rsa-2048"
	// KeyTypeRSA3072 RSA 3072 位
	KeyTypeRSA3072 KeyType = "rsa-3072"
	// KeyTypeRSA4096 RSA 4096 位
	KeyTypeRSA4096 KeyType = "rsa-4096"
	// KeyTypeECDSAP256 ECDSA P-256
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	// KeyTypeECDSAP384 ECDSA P-384
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	// KeyTypeEd25519 Ed25519
	KeyTypeEd25519 KeyType = "ed25519"
	// KeyTypeSM2 SM2 (国密)
	KeyTypeSM2 KeyType = "sm2"
)

// KeyGenerator 密钥生成器接口
type KeyGenerator interface {
	// Generate 生成新的密钥对
	Generate() (crypto.PrivateKey, error)
}

// RSAKeyGenerator RSA 密钥生成器
type RSAKeyGenerator struct {
	bits int
}

// NewRSAKeyGenerator 创建 RSA 密钥生成器。bits 下限 2048：< 2048 的 RSA
// 密钥不具现代安全强度，在生成端拦截而非产出弱密钥后由下游补救。
func NewRSAKeyGenerator(bits int) (*RSAKeyGenerator, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("keycrypt: RSA key size %d is below the 2048-bit minimum", bits)
	}
	return &RSAKeyGenerator{bits: bits}, nil
}

// Generate 生成 RSA 密钥对
func (g *RSAKeyGenerator) Generate() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, g.bits)
}

// ECDSAKeyGenerator ECDSA 密钥生成器
type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

// NewECDSAKeyGenerator 创建 ECDSA 密钥生成器。curve 为 nil 立即报错
// （历史实现延迟到 Generate 才 panic）。
func NewECDSAKeyGenerator(curve elliptic.Curve) (*ECDSAKeyGenerator, error) {
	if curve == nil {
		return nil, errors.New("keycrypt: ECDSA curve must not be nil")
	}
	return &ECDSAKeyGenerator{curve: curve}, nil
}

// Generate 生成 ECDSA 密钥对
func (g *ECDSAKeyGenerator) Generate() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(g.curve, rand.Reader)
}

// Ed25519KeyGenerator Ed25519 密钥生成器
type Ed25519KeyGenerator struct{}

// NewEd25519KeyGenerator 创建 Ed25519 密钥生成器
func NewEd25519KeyGenerator() *Ed25519KeyGenerator {
	return &Ed25519KeyGenerator{}
}

// Generate 生成 Ed25519 密钥对
func (g *Ed25519KeyGenerator) Generate() (crypto.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// Ed25519 的 PrivateKey 已经包含 PublicKey，所以只返回 PrivateKey
	return privateKey, nil
}

// SM2KeyGenerator SM2 密钥生成器（国密）
type SM2KeyGenerator struct{}

// NewSM2KeyGenerator 创建 SM2 密钥生成器
func NewSM2KeyGenerator() *SM2KeyGenerator {
	return &SM2KeyGenerator{}
}

// Generate 生成 SM2 密钥对
func (g *SM2KeyGenerator) Generate() (crypto.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// NewKeyGeneratorWithType 按类型字符串创建密钥生成器。keyType 必须是
// KeyType 常量之一（空串报错——"按模式选默认"是应用策略，不由本库决定）。
func NewKeyGeneratorWithType(keyType string) (KeyGenerator, error) {
	switch KeyType(keyType) {
	case KeyTypeRSA2048:
		return NewRSAKeyGenerator(2048)
	case KeyTypeRSA3072:
		return NewRSAKeyGenerator(3072)
	case KeyTypeRSA4096:
		return NewRSAKeyGenerator(4096)
	case KeyTypeECDSAP256:
		return NewECDSAKeyGenerator(elliptic.P256())
	case KeyTypeECDSAP384:
		return NewECDSAKeyGenerator(elliptic.P384())
	case KeyTypeEd25519:
		return NewEd25519KeyGenerator(), nil
	case KeyTypeSM2:
		return NewSM2KeyGenerator(), nil
	default:
		return nil, fmt.Errorf("keycrypt: unsupported key type: %s", keyType)
	}
}

// GenerateKeyPairWithType 生成指定类型的密钥对
func GenerateKeyPairWithType(keyType KeyType) (crypto.PrivateKey, crypto.PublicKey, error) {
	generator, err := NewKeyGeneratorWithType(string(keyType))
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := generator.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("keycrypt: generate key pair: %w", err)
	}

	publicKey, err := extractPublicKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// extractPublicKey 从私钥提取公钥（覆盖 RSA/ECDSA/Ed25519/SM2）。
// 收敛到此一处，避免每个调用点重复 type switch。
func extractPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *sm2.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("keycrypt: unknown private key type: %T", privateKey)
	}
}
