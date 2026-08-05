package sm2

import (
	"errors"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// AdjustCipherOrder 在不改变密文编码（ASN.1 或 Plain）的前提下，把 SM2 密文的
// C2/C3 拼接顺序从 from 转为 to。
//
// 典型用途：从遗留 C1C2C3 系统收到密文后，转为国标 C1C3C2 再用 Decrypt 解密：
//
//	ctC1C3C2, err := sm2.AdjustCipherOrder(ct, sm2.OrderC1C2C3, sm2.OrderC1C3C2)
//	plaintext, err := sm2.Decrypt(priv, ctC1C3C2)
//
// 注意：ASN.1 编码的密文其内部 C3/C2 字段顺序固定为 C1C3C2（标准），对其调用
// 本函数仅在 from==to 时为恒等操作；from!=to 时对 ASN.1 密文会返回解析错误。
// 要在 Plain 与 ASN.1 编码间互转，请用 ASN1ToPlain / PlainToASN1。
func AdjustCipherOrder(ciphertext []byte, from, to CipherOrder) ([]byte, error) {
	if err := validateOrder(from); err != nil {
		return nil, err
	}
	if err := validateOrder(to); err != nil {
		return nil, err
	}
	if from == to {
		return ciphertext, nil
	}

	// gmsm 的 ciphertextSplicingOrder 类型非导出；常量 C1C3C2/C1C2C3 已导出，
	// 在调用点内联（无法在外部包声明该类型的中间变量）。
	switch {
	case from == OrderC1C3C2 && to == OrderC1C2C3:
		return gmsmSM2.AdjustCiphertextSplicingOrder(ciphertext, gmsmSM2.C1C3C2, gmsmSM2.C1C2C3)
	case from == OrderC1C2C3 && to == OrderC1C3C2:
		return gmsmSM2.AdjustCiphertextSplicingOrder(ciphertext, gmsmSM2.C1C2C3, gmsmSM2.C1C3C2)
	default:
		// validateOrder 已保证分支完备；此处不可达。
		return nil, errors.New("sm2: unreachable cipher order")
	}
}

// ASN1ToPlain 将 ASN.1 编码的 SM2 密文转为 Plain（裸拼接）编码。
//
// opts 决定输出 Plain 密文的拼接顺序与点压缩格式。opts == nil 等价于国标默认
// （未压缩点 + C1C3C2）。输出可直接用 DecryptWithOpts 配合对应 Plain 选项解密。
func ASN1ToPlain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	return gmsmSM2.ASN1Ciphertext2Plain(ciphertext, opts)
}

// PlainToASN1 将 Plain（裸拼接）编码的 SM2 密文转为标准 ASN.1 编码。
//
// from 指明输入 Plain 密文的拼接顺序（C1C3C2 或 C1C2C3），用于正确切分 C2/C3。
// 输出恒为 ASN.1 + C1C3C2（标准固定顺序），可直接用 Decrypt 解密。
func PlainToASN1(ciphertext []byte, from CipherOrder) ([]byte, error) {
	if err := validateOrder(from); err != nil {
		return nil, err
	}
	switch from {
	case OrderC1C3C2:
		return gmsmSM2.PlainCiphertext2ASN1(ciphertext, gmsmSM2.C1C3C2)
	case OrderC1C2C3:
		return gmsmSM2.PlainCiphertext2ASN1(ciphertext, gmsmSM2.C1C2C3)
	default:
		return nil, errors.New("sm2: unreachable cipher order")
	}
}
