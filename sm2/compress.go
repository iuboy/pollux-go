package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
)

var (
	errInvalidCompressedKey = errors.New("sm2: invalid compressed public key")
	errNotOnCurve           = errors.New("sm2: point not on SM2 curve")
)

// CompressPublicKey 将 SM2 公钥压缩为 33 字节（02/03 前缀 + X 坐标）。
func CompressPublicKey(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	curve := P256()
	return elliptic.MarshalCompressed(curve, pub.X, pub.Y)
}

// DecompressPublicKey 将压缩格式的 SM2 公钥（33 字节）解压为完整公钥。
func DecompressPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	curve := P256()
	if len(data) != 33 {
		return nil, errInvalidCompressedKey
	}

	x, y := elliptic.UnmarshalCompressed(curve, data)
	if x == nil || y == nil {
		return nil, errInvalidCompressedKey
	}

	// 验证点在曲线上
	if !curve.IsOnCurve(x, y) {
		return nil, errNotOnCurve
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// MarshalUncompressed 将 SM2 公钥序列化为未压缩格式（65 字节：04 + X + Y）。
func MarshalUncompressed(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return elliptic.Marshal(P256(), pub.X, pub.Y) //nolint:staticcheck
}

// UnmarshalUncompressed 从未压缩格式解析 SM2 公钥。
func UnmarshalUncompressed(data []byte) (*ecdsa.PublicKey, error) {
	curve := P256()
	x, y := elliptic.Unmarshal(curve, data) //nolint:staticcheck
	if x == nil {
		return nil, errInvalidCompressedKey
	}
	if !curve.IsOnCurve(x, y) {
		return nil, errNotOnCurve
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// PublicKeyToBytes 将 SM2 公钥转为未压缩字节序列。
// Deprecated: 使用 MarshalUncompressed 代替。
func PublicKeyToBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil {
		return nil
	}
	return elliptic.Marshal(P256(), pub.X, pub.Y) //nolint:staticcheck
}

// BytesToPublicKey 从字节序列解析 SM2 公钥。
// Deprecated: 使用 UnmarshalUncompressed 代替。
func BytesToPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	return UnmarshalUncompressed(data)
}

// Equal 报告两个 SM2 公钥是否相等。
func Equal(x, y *ecdsa.PublicKey) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.X.Cmp(y.X) == 0 && x.Y.Cmp(y.Y) == 0
}

// PrivateKeyToBytes 将 SM2 私钥序列化为 32 字节大端整数。
//
// Security: the returned bytes contain sensitive key material.
// Callers MUST zero the returned slice after use via memsecure.ZeroBytes
// or by overwriting with zeros. Do not leave copies in memory.
func PrivateKeyToBytes(key *PrivateKey) []byte {
	return key.D.Bytes()
}

// BytesToPrivateKey 从 32 字节大端整数恢复 SM2 私钥。
func BytesToPrivateKey(data []byte) (*PrivateKey, error) {
	curve := sm2ec.P256()
	d := new(big.Int).SetBytes(data)
	n := curve.Params().N
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("sm2: private key scalar out of range")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	sm2Priv := new(gmsmSM2.PrivateKey)
	_, err := sm2Priv.FromECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return sm2Priv, nil
}
