package tlcp

// TLCP 密码套件 ID（GB/T 38636-2020 表2）
// 与 gotlcp 的 TLCP_ECDHE_SM4_GCM_SM3 等常量值完全相同。
const (
	SuiteECDHE_SM2_SM4_GCM_SM3 uint16 = 0xE051
	SuiteECDHE_SM2_SM4_CBC_SM3 uint16 = 0xE011
	SuiteECC_SM2_SM4_GCM_SM3   uint16 = 0xE053
	SuiteECC_SM2_SM4_CBC_SM3   uint16 = 0xE013
)

// defaultCipherSuites 默认支持的密码套件（GCM-only，ECDHE-only，提供前向安全）
var defaultCipherSuites = []uint16{
	SuiteECDHE_SM2_SM4_GCM_SM3,
}

// DefaultCipherSuites 返回默认的 TLCP 密码套件（GCM-only，ECDHE-only，提供前向安全）。
// 这是新连接的推荐配置，提供最佳安全性。
// 如需包含非 PFS 的静态 ECC 套件，请使用 LegacyCipherSuites()。
func DefaultCipherSuites() []uint16 {
	return []uint16{
		SuiteECDHE_SM2_SM4_GCM_SM3,
	}
}

// LegacyCipherSuites 返回包含 CBC 的完整密码套件列表。
// CBC 模式存在 padding oracle 等已知风险，仅用于遗留系统兼容，
// 新协议应使用 GCM-only 默认配置。
func LegacyCipherSuites() []uint16 {
	return []uint16{
		SuiteECDHE_SM2_SM4_GCM_SM3,
		SuiteECDHE_SM2_SM4_CBC_SM3,
		SuiteECC_SM2_SM4_GCM_SM3,
		SuiteECC_SM2_SM4_CBC_SM3,
	}
}

// isTLCPCipherSuite 检查是否为 TLCP 密码套件
func isTLCPCipherSuite(id uint16) bool {
	switch id {
	case SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3,
		SuiteECDHE_SM2_SM4_GCM_SM3, SuiteECDHE_SM2_SM4_CBC_SM3:
		return true
	}
	return false
}
