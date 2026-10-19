package sshca

// 第三轮安全审查 M5 回归测试:maxDuration 非正值会使 SignCertificate 的
// 有效期上限守卫短路,可签出 ValidBefore=MaxInt64(约 2262 年)的证书。

import (
	"strings"
	"testing"
	"time"
)

func TestNewCertificateSigner_RejectsNonPositiveMaxDuration(t *testing.T) {
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, -time.Hour} {
		if _, err := NewCertificateSigner(kp, UserCert, d); err == nil {
			t.Fatalf("maxDuration=%v must be rejected", d)
		} else if !strings.Contains(err.Error(), "maxDuration") {
			t.Fatalf("error should name maxDuration, got: %v", err)
		}
		if _, err := NewAuthority(kp, kp, d); err == nil {
			t.Fatalf("NewAuthority with maxDuration=%v must be rejected", d)
		}
	}
}
