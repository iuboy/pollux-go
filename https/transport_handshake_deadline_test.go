package https

// 第四轮安全审计（批 D）Fix 6 回归测试：NewTLCPTransport 的 DialTLSContext
// 在 ctx 未携带 deadline 时补 defaultTLSHandshakeTimeout（10s）握手时长
// 上界——此前直用无上界 ctx，僵死服务器可无限拖延握手；已有 deadline 不
// 覆盖。

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/tlcp"
)

// blackHoleListener 返回一个只接受连接、不回任何字节的监听器：客户端
// ClientHello 发出后握手读取将一直阻塞，直到 deadline（或其缺失）生效。
func blackHoleListener(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // 吞掉连接：不读、不回、不关
		}
	}()
	return ln.Addr()
}

// TestNewTLCPTransport_DefaultHandshakeDeadline 锁定 Fix 6 主路径：ctx 无
// deadline 时，黑洞服务器上的握手在默认 10s 上界附近失败——修复前该调用
// 会无限期挂起（本用例因此标注长耗时，短模式跳过）。
func TestNewTLCPTransport_DefaultHandshakeDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("默认握手超时需等待 ~10s，短模式跳过")
	}
	addr := blackHoleListener(t)
	tr, err := NewTLCPTransport(&tlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	conn, err := tr.DialTLSContext(context.Background(), "tcp", addr.String())
	elapsed := time.Since(start)
	if err == nil {
		_ = conn.Close()
		t.Fatal("黑洞服务器上的握手应超时失败")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("无 deadline 的握手 %v 才失败，默认 10s 上界未生效", elapsed)
	}
	if elapsed < 5*time.Second {
		t.Fatalf("握手 %v 即失败，过早——似乎不是默认握手超时在起作用", elapsed)
	}
}

// TestNewTLCPTransport_DeadlineNotOverridden 锁定 Fix 6 的不覆盖分支：ctx
// 已带 1s deadline 时应按调用方的 1s 失效（而非 10s 默认值）。
func TestNewTLCPTransport_DeadlineNotOverridden(t *testing.T) {
	addr := blackHoleListener(t)
	tr, err := NewTLCPTransport(&tlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := tr.DialTLSContext(ctx, "tcp", addr.String())
	elapsed := time.Since(start)
	if err == nil {
		_ = conn.Close()
		t.Fatal("deadline 内无法完成握手应失败")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("调用方 1s deadline 应先生效，实际 %v 后失败——默认值覆盖了调用方 deadline", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("应返回 context.DeadlineExceeded，got: %v", err)
	}
}
