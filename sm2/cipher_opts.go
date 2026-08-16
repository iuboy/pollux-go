package sm2

import (
	"errors"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// CipherOrder 是 SM2 密文中 C2（密文数据）与 C3（SM3 摘要）分量的拼接顺序。
//
// 国标 GB/T 32918.4-2016 规定默认顺序为 C1C3C2（OrderC1C3C2）；
// 早期 GM/T 0003-2012 草案使用 C1C2C3（OrderC1C2C3），部分老系统
// （旧版 GmSSL、部分 Java BC 配置、金融 IC 卡）仍采用该顺序。
// 与这类系统互通时需显式选择 OrderC1C2C3，或用 AdjustCipherOrder 转换。
type CipherOrder int

const (
	// OrderC1C3C2 是国标 GB/T 32918.4-2016 默认顺序：C1 || C3 || C2。
	// EncryptASN1 / Decrypt / 本包所有信封函数均默认使用此顺序。
	OrderC1C3C2 CipherOrder = iota
	// OrderC1C2C3 是 GM/T 0003-2012 旧顺序：C1 || C2 || C3。
	// 仅在与遗留系统互通时使用；新协议请用 OrderC1C3C2。
	OrderC1C2C3
)

// CipherEncoding 是 SM2 密文的编码格式。
type CipherEncoding int

const (
	// EncodingASN1 将密文编码为 ASN.1 SEQUENCE
	// （INTEGER x1 || INTEGER y1 || OCTET STRING C3 || OCTET STRING C2）。
	// GB/T 32918.4-2016 标准格式；EncryptASN1 / Decrypt 默认输出与消费此格式。
	EncodingASN1 CipherEncoding = iota
	// EncodingPlain 将密文以裸拼接形式输出：C1(点) || C3 || C2（或 C1 || C2 || C3），
	// 无 ASN.1 包裹。部分遗留系统使用此格式。
	EncodingPlain
)

// EncrypterOpts 配置 SM2 加密的密文编码、点序列化方式与拼接顺序。
// 类型别名到 gmsmSM2.EncrypterOpts，与 sm9.EncrypterOpts 的别名风格一致；
// 调用方通过 NewEncrypterOpts 或预设变量（如 ASN1EncrypterOpts）构造。
type EncrypterOpts = gmsmSM2.EncrypterOpts

// DecrypterOpts 配置 SM2 解密的密文编码与拼接顺序。
// 类型别名到 gmsmSM2.DecrypterOpts。
type DecrypterOpts = gmsmSM2.DecrypterOpts

// 预设加密/解密选项（国标默认：ASN.1 + 未压缩点 + C1C3C2）。
// 直接转发到 gmsm 既有的导出变量，保证与 EncryptASN1 / Decrypt 的默认行为完全一致。
var (
	// ASN1EncrypterOpts：ASN.1 编码 + 未压缩点 + C1C3C2。
	ASN1EncrypterOpts = gmsmSM2.ASN1EncrypterOpts
	// ASN1DecrypterOpts：ASN.1 编码 + C1C3C2。
	ASN1DecrypterOpts = gmsmSM2.ASN1DecrypterOpts
)

// gmsm 的 ciphertextSplicingOrder 与 pointMarshalMode 类型非导出，但其常量
// （C1C3C2/C1C2C3/MarshalUncompressed/MarshalCompressed）已导出。Go 允许把导出
// 常量作为实参传给接受该非导出类型的函数，但不能在外部包声明该类型的变量或返回值。
// 因此下面的构造函数把 CipherOrder 映射成对 gmsm 构造函数的直接调用，常量在调用点内联。

// NewEncrypterOpts 构造一个加密选项。
//
//   - encoding：选择 ASN.1 或 Plain 编码。
//   - order：选择 C1C3C2（国标）或 C1C2C3（legacy）拼接顺序。
//   - compress：true 使用压缩点格式（C1 占 33 字节），false 使用未压缩点（65 字节）。
//     ASN.1 编码忽略 compress（标准固定使用未压缩点）。
//
// 未知取值返回错误；调用方应检查。返回的 *EncrypterOpts 可直接传给 Encrypt。
func NewEncrypterOpts(encoding CipherEncoding, order CipherOrder, compress bool) (*EncrypterOpts, error) {
	if err := validateOrder(order); err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingASN1:
		// ASN.1 编码固定使用未压缩点，忽略 compress；其字段序固定为 C1C3C2
		// （标准结构自描述，不存在 C1C2C3 的 ASN.1 形态）。历史实现静默忽略
		// order 并产出 C1C3C2——调用方按参数预期得到的格式与实际不符，
		// 遗留互操作场景最易踩中，故显式拒绝。
		if order == OrderC1C2C3 {
			return nil, errors.New("sm2: ASN.1 encoding has fixed C1C3C2 field order; C1C2C3 exists only in Plain encoding (use EncodingPlain)")
		}
		opts := *gmsmSM2.ASN1EncrypterOpts // 复制默认值，避免共享可变状态
		return &opts, nil
	case EncodingPlain:
		// gmsm 常量在调用点内联（其类型非导出，无法在外部包声明中间变量）。
		if compress {
			switch order {
			case OrderC1C3C2:
				return gmsmSM2.NewPlainEncrypterOpts(gmsmSM2.MarshalCompressed, gmsmSM2.C1C3C2), nil
			case OrderC1C2C3:
				return gmsmSM2.NewPlainEncrypterOpts(gmsmSM2.MarshalCompressed, gmsmSM2.C1C2C3), nil
			}
		}
		switch order {
		case OrderC1C3C2:
			return gmsmSM2.NewPlainEncrypterOpts(gmsmSM2.MarshalUncompressed, gmsmSM2.C1C3C2), nil
		case OrderC1C2C3:
			return gmsmSM2.NewPlainEncrypterOpts(gmsmSM2.MarshalUncompressed, gmsmSM2.C1C2C3), nil
		}
		// validateOrder 已保证分支完备；此处不可达。
		return nil, errors.New("sm2: unreachable cipher order")
	default:
		return nil, errors.New("sm2: unknown cipher encoding")
	}
}

// NewDecrypterOpts 构造一个解密选项。
//
// encoding 必须与密文实际编码匹配；order 必须与密文实际拼接顺序匹配。
// 既有 Decrypt 函数会自动探测 ASN.1 vs Plain，但其默认顺序固定 C1C3C2——
// 要解 C1C2C3 密文必须用本函数构造 OrderC1C2C3 选项并经 DecryptWithOpts 调用。
func NewDecrypterOpts(encoding CipherEncoding, order CipherOrder) (*DecrypterOpts, error) {
	if err := validateOrder(order); err != nil {
		return nil, err
	}

	switch encoding {
	case EncodingASN1:
		opts := *gmsmSM2.ASN1DecrypterOpts
		return &opts, nil
	case EncodingPlain:
		switch order {
		case OrderC1C3C2:
			return gmsmSM2.NewPlainDecrypterOpts(gmsmSM2.C1C3C2), nil
		case OrderC1C2C3:
			return gmsmSM2.NewPlainDecrypterOpts(gmsmSM2.C1C2C3), nil
		}
		return nil, errors.New("sm2: unreachable cipher order")
	default:
		return nil, errors.New("sm2: unknown cipher encoding")
	}
}

// validateOrder 校验 CipherOrder 取值合法。
func validateOrder(order CipherOrder) error {
	switch order {
	case OrderC1C3C2, OrderC1C2C3:
		return nil
	default:
		return errors.New("sm2: unknown cipher order")
	}
}
