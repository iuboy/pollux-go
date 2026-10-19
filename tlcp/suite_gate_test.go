package tlcp

// 遗留项:configToNative 套件校验——垃圾/非 TLCP 套件 ID 此前静默入引擎,
// 只在握手的套件选择处以模糊错误失败;静态 ECC 套件(遗留互通)仍接受。

import (
	"testing"
)

func TestConfigToNative_RejectsUnknownSuite(t *testing.T) {
	for _, bad := range []uint16{0x1301, 0x009C, 0xFFFF} {
		cfg := &Config{
			Version:      Version11,
			CipherSuites: []uint16{bad},
		}
		if _, err := configToNative(cfg, true); err == nil {
			t.Errorf("套件 %#04x 应在 configToNative 被拒绝", bad)
		}
	}
	// 静态 ECC(遗留互通)与默认列表仍接受。
	for _, ok := range [][]uint16{
		LegacyCipherSuites(),
		DefaultCipherSuites(),
		{SuiteECC_SM2_SM4_GCM_SM3},
	} {
		cfg := &Config{Version: Version11, CipherSuites: ok}
		if _, err := configToNative(cfg, true); err != nil {
			t.Errorf("合法套件列表 %v 不应被拒绝: %v", ok, err)
		}
	}
	// 空列表回退默认(既有行为)。
	nc, err := configToNative(&Config{Version: Version11}, true)
	if err != nil {
		t.Fatalf("空套件应回退默认: %v", err)
	}
	_ = nc
}
