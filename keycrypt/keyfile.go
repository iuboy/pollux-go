// See doc.go for the package documentation (godoc convention).
// This file: encrypted private-key marshal/load (PKCS#8 PBES2).
package keycrypt

import (
	"crypto"
	"errors"
	"fmt"

	"encoding/pem"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs8"
	"github.com/iuboy/pollux-go/internal/memsecure"
	"github.com/iuboy/pollux-go/smx509"
)

// 密钥派生参数。迭代数对齐本仓库 smx509 自定的策略（"Callers creating new
// encrypted keys MUST use at least 600,000 iterations"，引据 OWASP 2023
// PBKDF2-HMAC-SHA256 指南）——此前 100k 与该标准自相矛盾，且 CA/SSH CA
// 私钥是高价值长期资产，弱口令离线暴破面必须按上界设防。单次派生约
// 0.2s，对一次性密钥落盘操作可接受。
const (
	pbkdf2SaltSize   = 16
	pbkdf2Iterations = 600_000
	encryptedPEMType = "ENCRYPTED PRIVATE KEY"
)

// pbes2Encrypter 预构造的 PBES2 加密器：AES-256-GCM + PBKDF2-SHA256。
// 模块级变量避免每次加密重新构造。
var pbes2Encrypter = pkcs.NewPBESEncrypter(
	pkcs.AES256GCM,
	pkcs.NewPBKDF2Opts(pkcs.SHA256, pbkdf2SaltSize, pbkdf2Iterations),
)

// ErrPasswordRequired 未提供密钥加密密码。
var ErrPasswordRequired = errors.New("私钥加密密码不能为空（安全策略：私钥禁止明文落盘）")

// ErrPlaintextKeyRejected 加载时遇到明文（非加密）私钥 PEM。
var ErrPlaintextKeyRejected = errors.New("拒绝加载明文私钥（安全策略：仅接受加密 PKCS#8 PEM）")

// MarshalEncryptedPrivateKey 将私钥加密序列化为 PKCS#8 PBES2 PEM（AES-256-GCM + PBKDF2-SHA256）。
//
// password 为空返回 ErrPasswordRequired（破坏性：不允许明文落盘）。
// 支持 SM2/ECDSA(所有曲线)/RSA/Ed25519（pkcs8.MarshalPrivateKey 通过标准 PKCS#8 编码）。
//
// 安全局限：password 以 Go string 传入，string 不可变且无法可靠清零，口令的
// string 副本会存活至 GC；[]byte 副本已 best-effort 清零。高安全场景请从受控
// 缓冲区构造口令并接受此残留风险。
func MarshalEncryptedPrivateKey(key crypto.Signer, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}
	// 密码的堆副本用后即清（gmsm 只读取不持有引用，清同一底层数组有效），
	// 避免口令在堆上残留到 GC——内存取证可直接取口令，削弱 KDF 的意义。
	pw := []byte(password)
	defer memsecure.ZeroBytes(pw)
	der, err := pkcs8.MarshalPrivateKey(key, pw, pbes2Encrypter)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: encryptedPEMType, Bytes: der}), nil
}

// LoadEncryptedPrivateKey 从加密 PKCS#8 PEM 加载私钥。
//
// password 为空返回 ErrPasswordRequired。
// 若 PEM 为明文（类型不是 ENCRYPTED PRIVATE KEY），返回 ErrPlaintextKeyRejected（破坏性）。
// 返回解密后的原始私钥 DER，由调用方根据算法（SM2/ECDSA/RSA/Ed25519）解析。
//
// 安全局限：与 MarshalEncryptedPrivateKey 相同——password 的 string 副本
// 不可变且无法可靠清零，会存活至 GC。高安全场景请从受控缓冲区构造口令并
// 接受此残留风险。
func LoadEncryptedPrivateKey(pemData []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("无效的 PEM 数据")
	}
	// 破坏性：明文私钥一律拒绝（含 legacy "Proc-Type: ENCRYPTED" 之外的明文 PEM）
	if block.Type != encryptedPEMType {
		return nil, fmt.Errorf("%w: PEM 类型 %q", ErrPlaintextKeyRejected, block.Type)
	}
	// DecryptPEMPrivateKeyDER 接受完整 PEM 字节，返回解密后的原始 PKCS#8 DER。
	der, err := smx509.DecryptPEMPrivateKeyDER(pemData, password)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}
	return der, nil
}
