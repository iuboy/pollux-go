package https

// 第三轮审查 P2:C3 标准 TLS 密码套件白名单、C7 NewTLS13Client 信任门。

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/iuboy/pollux-go/tlcp"
)

// TestBuildTLSConfig_CipherSuiteGate 锁定 C3 服务端:显式套件列表必须是
// AEAD+PFS——CBC 套件与 RSA 密钥交换套件拒绝;GM(TLCP)套件 ID 因字段
// 共享被剔除而非报错(hybrid 模式两族套件共存于一个字段);全 GM 列表
// 回落 stdlib 默认组。
func TestBuildTLSConfig_CipherSuiteGate(t *testing.T) {
	base := func(suites []uint16) *ServerOptions {
		return &ServerOptions{
			Mode:         ModeTLS,
			Addr:         ":0",
			CipherSuites: suites,
			Certificates: []tls.Certificate{{}}, // 套件校验后的证书检查只需非空
		}
	}

	for _, bad := range []uint16{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,   // 3DES/CBC(stdlib 常量,可能已移除编译支持但常量仍在)
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,    // CBC + RSA kx
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // 非 PFS 密钥交换
		0x00FF,                              // 未知 ID
	} {
		if bad == 0 {
			continue
		}
		if _, err := base([]uint16{bad}).buildTLSConfig(); err == nil {
			t.Errorf("套件 %#04x 应被拒绝", bad)
		}
	}

	// GM 套件 ID 被剔除,不报错。
	cfg, err := base(tlcp.DefaultCipherSuites()).buildTLSConfig()
	if err != nil {
		t.Fatalf("纯 GM 列表(hybrid 字段共享)应通过并被剔除: %v", err)
	}
	if cfg == nil || len(cfg.CipherSuites) != 0 {
		t.Fatalf("剔除后应回落 stdlib 默认组, got %v", cfg.CipherSuites)
	}

	// AEAD+PFS 套件直接通过。
	if _, err := base([]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}).buildTLSConfig(); err != nil {
		t.Fatalf("ECDHE AEAD 套件应通过: %v", err)
	}
}

// TestBuildTLSClientConfig_CipherSuiteGate 锁定 C3 客户端。
func TestBuildTLSClientConfig_CipherSuiteGate(t *testing.T) {
	mk := func(suites []uint16) *ClientOptions {
		return &ClientOptions{
			Mode:                  ModeTLS,
			TLSInsecureSkipVerify: true, // 信任门不相关项
			TLSCipherSuites:       suites,
		}
	}
	if _, err := mk([]uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}).buildTLSClientConfig(); err == nil {
		t.Fatal("CBC 套件应被拒绝")
	}
	if _, err := mk([]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}).buildTLSClientConfig(); err != nil {
		t.Fatalf("ECDHE AEAD 套件应通过: %v", err)
	}
}

// TestNewTLS13Client_TrustGate 锁定 C7:与 NewClient 标准 TLS 路径一致的
// fail-closed 信任门(证书/根池/显式跳过三者必居其一)。
func TestNewTLS13Client_TrustGate(t *testing.T) {
	if _, err := NewTLS13Client(TLS13ClientOptions{ServerName: "example.com"}); err == nil {
		t.Fatal("无证书、无根池、未显式跳过验证应被拒绝")
	}
	if _, err := NewTLS13Client(TLS13ClientOptions{ServerName: "example.com", InsecureSkipVerify: true}); err != nil {
		t.Fatalf("显式 InsecureSkipVerify 应通过: %v", err)
	}
	if _, err := NewTLS13Client(TLS13ClientOptions{ServerName: "example.com", RootCAs: x509.NewCertPool()}); err != nil {
		t.Fatalf("提供根池应通过: %v", err)
	}
}

// TestBuildTLSConfig_SessionTicketControls 锁定遗留项 C8:票据键长度在配置期
// 校验(stdlib SetSessionTicketKeys 对非 32 字节键 panic),禁用开关可接线。
func TestBuildTLSConfig_SessionTicketControls(t *testing.T) {
	base := func(keys [][]byte, disable bool) *ServerOptions {
		return &ServerOptions{
			Mode:                  ModeTLS,
			Addr:                  ":0",
			Certificates:          []tls.Certificate{{}},
			SessionTicketKeys:     keys,
			DisableSessionTickets: disable,
		}
	}
	if _, err := base([][]byte{make([]byte, 16)}, false).buildTLSConfig(); err == nil {
		t.Fatal("非 32 字节票据键必须在配置期报错(stdlib 会 panic)")
	}
	cfg, err := base([][]byte{make([]byte, 32)}, true).buildTLSConfig()
	if err != nil {
		t.Fatalf("32 字节键应通过: %v", err)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("DisableSessionTickets 应接线到 tls.Config")
	}
	if _, err := base(nil, false).buildTLSConfig(); err != nil {
		t.Fatalf("无票据键(默认自动轮换)应通过: %v", err)
	}
}
