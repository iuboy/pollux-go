package sm2

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
	gmsmSMX509 "github.com/emmansun/gmsm/smx509"
)

var (
	// ErrNotSM2Key is returned by ParsePrivateKeyFromPEM when the PEM block
	// parses successfully but the encoded key is not on the SM2 P256 curve.
	// It is the sentinel smx509 uses to decide whether to fall through to the
	// standard-library private-key parsers.
	ErrNotSM2Key  = errors.New("sm2: key is not SM2")
	errPEMDecode  = errors.New("sm2: failed to decode PEM block")
	errNoKeyInPEM = errors.New("sm2: no key found in PEM data")
)

// errNotSM2Key preserved as an alias for internal callers; new code should
// prefer the exported ErrNotSM2Key for errors.Is compatibility.
var errNotSM2Key = ErrNotSM2Key

// ParsePrivateKeyFromPEM 解析 PEM 编码的 SM2 私钥。
// 支持 PKCS#8 和 EC PRIVATE KEY 格式。
func ParsePrivateKeyFromPEM(pemData []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errPEMDecode
	}

	// 检测加密的 PEM 并提供明确的错误提示
	if block.Type == "ENCRYPTED PRIVATE KEY" ||
		strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errors.New("sm2: PEM key is encrypted; use smx509.DecryptPEMPrivateKey to decrypt first")
	}

	// 尝试 PKCS#8（优先使用 smx509 以支持 SM2 OID）
	if key, err := gmsmSMX509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if sm2Key, ok := key.(*gmsmSM2.PrivateKey); ok {
			return sm2Key, nil
		}
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok && ecdsaKey.Curve == P256() {
			sm2Priv := new(gmsmSM2.PrivateKey)
			if _, err := sm2Priv.FromECPrivateKey(ecdsaKey); err != nil {
				return nil, err
			}
			return sm2Priv, nil
		}
		return nil, errNotSM2Key
	}

	// 尝试 EC PRIVATE KEY
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		if key.Curve == P256() {
			sm2Priv := new(gmsmSM2.PrivateKey)
			if _, err := sm2Priv.FromECPrivateKey(key); err != nil {
				return nil, err
			}
			return sm2Priv, nil
		}
		return nil, errNotSM2Key
	}

	return nil, errNoKeyInPEM
}

// ParsePublicKeyFromPEM 解析 PEM 编码的 SM2 公钥。
// 仅接受 "PUBLIC KEY" 块类型；拒绝其他类型（如 PRIVATE KEY）以防误用。
func ParsePublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errPEMDecode
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("sm2: unexpected PEM block type %q, want PUBLIC KEY", block.Type)
	}

	pub, err := gmsmSMX509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errNotSM2Key
	}
	if ecdsaPub.Curve != P256() {
		return nil, errNotSM2Key
	}
	return ecdsaPub, nil
}

// WritePrivateKeyToPEM 将 SM2 私钥序列化为 PEM 格式 (PKCS#8)。
func WritePrivateKeyToPEM(key *PrivateKey) ([]byte, error) {
	der, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}

// MarshalPKCS8PrivateKey 将 SM2 私钥序列化为 PKCS#8 DER（含 SM2 OID）。
// 经 gmsm/smx509 派发——直接调 stdlib x509.MarshalPKCS8PrivateKey 不会写入
// SM2 OID，反序列化时会被识别为普通 ECDSA。与 WritePrivateKeyToPEM 共用底层，
// 供需要原始 DER（非 PEM）的调用方使用。
func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
	return gmsmSMX509.MarshalPKCS8PrivateKey(key)
}

// WritePublicKeyToPEM 将 SM2 公钥序列化为 PEM 格式。
func WritePublicKeyToPEM(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := gmsmSMX509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}
