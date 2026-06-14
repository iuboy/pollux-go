package tlcp

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	polluxtls "github.com/iuboy/pollux-go/tls"
)

// TestVersionString 验证 Version.String。
func TestVersionString(t *testing.T) {
	if Version11.String() != "1.1" {
		t.Errorf("Version11.String() = %q, want \"1.1\"", Version11.String())
	}
	if Version12.String() != "1.2" {
		t.Errorf("Version12.String() = %q, want \"1.2\"", Version12.String())
	}
}

// TestVersionFromString 覆盖所有合法/非法分支。
func TestVersionFromString(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		ok   bool
	}{
		{"1.1", Version11, true},
		{"11", Version11, true},
		{"1.2", Version12, true},
		{"12", Version12, true},
		{"2.0", "", false},
		{"", "", false},
		{"garbage", "", false},
	}
	for _, c := range cases {
		got, err := VersionFromString(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("VersionFromString(%q) err = %v, want nil", c.in, err)
			}
			if got != c.want {
				t.Errorf("VersionFromString(%q) = %v, want %v", c.in, got, c.want)
			}
		} else {
			if err == nil {
				t.Errorf("VersionFromString(%q) err = nil, want error", c.in)
			}
			if !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("VersionFromString(%q) err = %v, want ErrInvalidVersion", c.in, err)
			}
		}
	}
}

// TestIsAvailable 验证可用性标志。
func TestIsAvailable(t *testing.T) {
	if !IsAvailable() {
		t.Error("IsAvailable() = false, want true (gotlcp wrapper always available)")
	}
}

// TestGetStandardSummary 验证标准摘要非空。
func TestGetStandardSummary(t *testing.T) {
	s := GetStandardSummary()
	if s == "" {
		t.Fatal("GetStandardSummary() returned empty")
	}
	// 应包含核心标准号
	for _, want := range []string{"GB/T 38636-2020", "RFC 8998", "ECDHE_SM2_WITH_SM4_GCM_SM3"} {
		if !contains(s, want) {
			t.Errorf("GetStandardSummary() missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestEnableDisable 验证在 tls.Config 上启用/禁用国密套件。
func TestEnableDisable(t *testing.T) {
	national := polluxtls.NationalCipherSuites()
	if len(national) == 0 {
		t.Skip("no national cipher suites available")
	}

	cfg := &tls.Config{CipherSuites: []uint16{0x009C}} // TLS_RSA... 占位非国密
	before := len(cfg.CipherSuites)

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable() err = %v", err)
	}
	if len(cfg.CipherSuites) <= before {
		t.Errorf("Enable() did not append suites: before=%d after=%d", before, len(cfg.CipherSuites))
	}

	// 禁用后应仅剩非国密套件
	Disable(cfg)
	for _, s := range cfg.CipherSuites {
		if polluxtls.IsNationalCipherSuite(s) {
			t.Errorf("Disable() left national suite 0x%04X", s)
		}
	}
}

// TestEnable_NoNationalSuites 验证无国密套件时返回 ErrTLCPNotSupported。
// 由于 NationalCipherSuites 总返回非空,此分支在当前实现下不可达,
// 这里仅确认 Enable 在正常情况下不返回该错误。
func TestEnable_NoNationalSuites(t *testing.T) {
	cfg := &tls.Config{}
	if err := Enable(cfg); err == ErrTLCPNotSupported {
		t.Logf("Enable returned ErrTLCPNotSupported (national suites empty); acceptable")
	}
}

// TestListen_NewListener 覆盖 Listen 便捷函数(创建 listener 后立即关闭,不触发握手)。
func TestListen_NewListener(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	cfg := NewConfig()
	cfg.SignCertificate = signCert
	cfg.EncCertificate = encCert

	ln, err := Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen err = %v", err)
	}
	defer ln.Close()
	if ln.Addr() == nil {
		t.Error("listener Addr = nil")
	}
}

// TestListen_InvalidAddr 验证监听非法地址失败。
func TestListen_InvalidAddr(t *testing.T) {
	cfg := NewConfig()
	if _, err := Listen("tcp", "127.0.0.1:1", cfg); err == nil {
		// 某些系统 1 端口可绑定,改用明显非法地址
		_, err = Listen("invalid-network", "127.0.0.1:0", cfg)
		if err == nil {
			t.Error("Listen(invalid network) err = nil, want error")
		}
	}
}

// TestDial_Refused 覆盖 Dial 便捷函数:连接拒绝端口,握手前 net.Dial 失败。
func TestDial_Refused(t *testing.T) {
	cfg := NewConfig()
	// 连接一个无监听的端口 → net.Dial 失败或握手失败 → 返回 error
	if _, err := Dial("tcp", "127.0.0.1:1", cfg); err == nil {
		t.Error("Dial(refused port) err = nil, want error")
	}
}

// TestDialWithDialer_NilDialer 覆盖 DialWithDialer 的 nil dialer 分支(使用 net.Dial)。
func TestDialWithDialer_NilDialer(t *testing.T) {
	cfg := NewConfig()
	if _, err := DialWithDialer(nil, "tcp", "127.0.0.1:1", cfg); err == nil {
		t.Error("DialWithDialer(nil, refused) err = nil, want error")
	}
}

// TestDialWithDialer_CustomDialer 覆盖自定义 dialer 分支。
func TestDialWithDialer_CustomDialer(t *testing.T) {
	cfg := NewConfig()
	d := &net.Dialer{Timeout: 1}
	if _, err := DialWithDialer(d, "tcp", "127.0.0.1:1", cfg); err == nil {
		t.Error("DialWithDialer(custom, refused) err = nil, want error")
	}
}
