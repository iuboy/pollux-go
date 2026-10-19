package tlcp

// 第三轮安全审查 H2 回归测试:客户端验证开启但 ServerName 为空时必须
// fail-closed(空 DNSName 会让主机名校验静默跳过)。

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDial_RequiresServerNameWhenVerifying(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := DialContext(context.Background(), "tcp", ln.Addr().String(), NewConfig())
	if err == nil {
		conn.Close()
		t.Fatal("dial with empty ServerName and verification enabled must fail")
	}
	if !strings.Contains(err.Error(), "either ServerName or InsecureSkipVerify") {
		t.Fatalf("unexpected error: %v", err)
	}
}
