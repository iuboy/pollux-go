package https

// 第三轮安全审查 M4 回归测试:标准 TLS 服务端请求客户端证书验证但未配
// ClientCAs 时必须报错,而不是静默回退系统根(任何公共 CA 签发的客户端
// 证书都能通过 mTLS)。

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestBuildTLSConfig_RequiresClientCAsForVerify(t *testing.T) {
	for _, auth := range []tls.ClientAuthType{tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert} {
		_, err := (&ServerOptions{TLSClientAuth: auth}).buildTLSConfig()
		if err == nil {
			t.Fatalf("TLSClientAuth=%d without ClientCAs must fail", auth)
		}
		if !strings.Contains(err.Error(), "TLSClientCAs") {
			t.Fatalf("TLSClientAuth=%d error should name TLSClientCAs, got: %v", auth, err)
		}
	}
	// NoClientCert / RequestClientCert do not verify and stay allowed.
	for _, auth := range []tls.ClientAuthType{tls.NoClientCert, tls.RequestClientCert} {
		if _, err := (&ServerOptions{TLSClientAuth: auth}).buildTLSConfig(); err == nil || !strings.Contains(err.Error(), "TLS certificate is required") {
			t.Fatalf("TLSClientAuth=%d should pass the CA gate and hit the certificate check instead, got: %v", auth, err)
		}
	}
}
