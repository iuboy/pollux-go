package tlcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// silentServer 启动一个「接受连接、读走 ClientHello 后保持沉默」的 TCP 服务：
// 客户端发出 ClientHello 后将阻塞在等待 ServerHello 的读上。返回监听地址和
// clientHelloSeen 通道（服务端读到 ClientHello 首字节后关闭），用于让测试
// 确定性地知道客户端握手已推进到阻塞点。测试结束（close done）后服务端
// 连接才被关闭，避免在取消前自行打断客户端。
func silentServer(t *testing.T) (addr string, clientHelloSeen <-chan struct{}, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	seen := make(chan struct{})
	release := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// 读到 ClientHello 首字节即认为客户端已发出 ClientHello、即将阻塞
		// 在等待 ServerHello 上（内核会缓冲整个 ClientHello，写不会卡住）。
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err == nil {
			close(seen)
		}
		// 保持连接存活且不写任何字节，直到测试释放。
		<-release
	}()
	// ln 的生命周期由测试通过 done 关闭（含 Accept 退出）。
	return ln.Addr().String(), seen, func() {
		close(release)
		_ = ln.Close()
	}
}

// awaitHandshakeErr 等待握手 goroutine 返回，并断言错误为 ctx 的取消错误且
// 及时返回（backstop 超时只为失败时给出可读报错，不是对性能的断言）。
func awaitHandshakeErr(t *testing.T, errCh <-chan error, ctx context.Context, what string) {
	t.Helper()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("%s: err = nil, want context error", what)
		}
		if !errors.Is(err, ctx.Err()) {
			t.Fatalf("%s: err = %v, want %v", what, err, ctx.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: did not return within 5s after cancel — mid-handshake cancellation is stuck", what)
	}
}

// TestHandshakeContext_CancelMidHandshake 验证握手阻塞中取消 ctx：取消经
// 关闭底层 conn 生效（与 stdlib crypto/tls.Conn.HandshakeContext 同一模型），
// HandshakeContext 及时返回 ctx 错误，而不是挂死或只能靠 conn deadline 兜底。
func TestHandshakeContext_CancelMidHandshake(t *testing.T) {
	_, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})

	addr, seen, done := silentServer(t)
	defer done()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := Client(raw, clientConfig)
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.HandshakeContext(ctx)
	}()

	// 等服务端确认收到 ClientHello，保证取消发生在握手阻塞中途。
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("server never received ClientHello; test setup broken")
	}

	cancel()
	awaitHandshakeErr(t, errCh, ctx, "HandshakeContext(mid-handshake cancel)")
}

// TestDialContext_CancelMidHandshake 验证 DialContext 在握手阶段可被取消：
// cancel 后及时返回 ctx 错误（取消经 HandshakeContext 关闭底层 conn 生效）。
func TestDialContext_CancelMidHandshake(t *testing.T) {
	_, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})

	addr, seen, done := silentServer(t)
	defer done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, "tcp", addr, clientConfig)
		errCh <- err
	}()

	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("server never received ClientHello; test setup broken")
	}

	cancel()
	awaitHandshakeErr(t, errCh, ctx, "DialContext(mid-handshake cancel)")
}
