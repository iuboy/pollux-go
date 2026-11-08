package https

// 第四轮安全审计（批 D）Fix 5 回归测试：hybridConn.Close 不得被 ensure 的
// 握手互斥锁阻塞。此前 ensure 全程持 c.mu（sniff+Handshake 最长 30s/无限），
// Close 先取 c.mu——Slowloris 场景下 http.Server.Close 会挂在每一条慢握手
// 连接上。修复后 Close 锁内快速快照（sec/raw）锁外关闭 raw 中断握手，且
// sync.Once 幂等。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/tlcp"
)

// TestHybridConnCloseDuringSlowHandshake 验证三件事：
//  1. 慢握手进行中 Close 及时返回（不等到握手超时）；
//  2. 握手随后因底层连接被 Close 关闭而失败（Read 返回该连接错误）；
//  3. Close 幂等：重复调用立即返回首次结果。
func TestHybridConnCloseDuringSlowHandshake(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer baseLn.Close()

	// GetCertificate 卡在 release 通道上：握手确定性地停在证书选择阶段
	// （已读完 ClientHello，互斥区内的 Handshake 无法推进也无法结束）。
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	tlsCfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			enterOnce.Do(func() { close(entered) })
			<-release
			return nil, errors.New("pollux/https: handshake aborted by test")
		},
	}
	hln := NewHybridListener(baseLn, &tlcp.Config{}, tlsCfg)
	defer hln.Close()

	clientRaw, err := net.Dial("tcp", baseLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	clientErr := make(chan error, 1)
	go func() { clientErr <- client.Handshake() }()

	serverConn, err := hln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	hc, ok := serverConn.(*hybridConn)
	if !ok {
		t.Fatalf("Accept 返回 %T, want *hybridConn", serverConn)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := hc.Read(buf) // 首个 Read 触发 sniff + handshake
		readErr <- err
	}()

	// 确定性等待握手进入卡点（而非靠时序猜测）。
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("服务器握手未在预期时间内进入证书选择阶段")
	}

	// Close 必须及时返回：不等待握手（默认上界 30s）。
	closeStarted := time.Now()
	closeErrCh := make(chan error, 1)
	go func() { closeErrCh <- hc.Close() }()
	var firstCloseErr error
	select {
	case firstCloseErr = <-closeErrCh:
		if elapsed := time.Since(closeStarted); elapsed > 5*time.Second {
			t.Fatalf("Close 耗时 %v，不应被慢握手阻塞（上界 30s）", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close 被进行中的握手阻塞，未及时返回")
	}

	// 握手随后因底层连接关闭而失败。
	close(release)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("被 Close 中断的握手应让 Read 返回错误")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close(raw) 之后握手未失败（Read 未返回）")
	}

	// 幂等：再次 Close 立即返回首次结果（errors.Is 判别——Close 可能返回
	// 包装错误，!= 比较在 wrapped 错误上恒假）。
	if second := hc.Close(); !errors.Is(second, firstCloseErr) {
		t.Fatalf("重复 Close 应返回首次结果 %v, got %v", firstCloseErr, second)
	}

	// 客户端侧握手也应因服务器关闭而失败（清理 goroutine）。
	select {
	case err := <-clientErr:
		if err == nil {
			t.Fatal("服务器中断后客户端握手应失败")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("客户端握手未随服务器关闭而失败")
	}
}

// TestHybridConnCloseAfterHandshake 锁定既有行为不回归：握手完成后的 Close
// 关闭协商后的安全连接（sec 快照非 nil 路径），并保持幂等。
func TestHybridConnCloseAfterHandshake(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer baseLn.Close()

	srvTLS := &tls.Config{InsecureSkipVerify: true}
	clientTLS := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}
	// 服务器侧需要一张证书；用自签证书让握手完整走通。
	cert := selfSignedTLSCert(t)
	srvTLS.Certificates = []tls.Certificate{cert}

	hln := NewHybridListener(baseLn, &tlcp.Config{}, srvTLS)
	defer hln.Close()

	clientRaw, err := net.Dial("tcp", baseLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	client := tls.Client(clientRaw, clientTLS)
	clientErr := make(chan error, 1)
	go func() { clientErr <- client.Handshake() }()

	hc, err := hln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := hc.Read(buf)
		readErr <- err
	}()

	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("客户端握手应成功: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("客户端握手未完成")
	}

	// 握手完成后 sec 已缓存：Close 走 sec.Close 路径。
	if err := hc.Close(); err != nil {
		t.Fatalf("握手完成后 Close 应成功: %v", err)
	}
	if err := hc.Close(); err != nil {
		t.Fatalf("重复 Close 应幂等返回首次（nil）结果: %v", err)
	}
}

// selfSignedTLSCert 生成一张自签 RSA 证书供 TLS 服务器握手使用。
func selfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
