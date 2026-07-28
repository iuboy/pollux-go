package tlcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
)

// TestConvertConnectionState 验证 gotlcp.ConnectionState → pollux ConnectionState 转换:
// 普通字段、peer 证书拆分(sign/enc)、verified chains。
func TestConvertConnectionState(t *testing.T) {
	// 直接调用内部转换函数,构造一个空状态
	empty := convertConnectionState(gotlcp.ConnectionState{})
	if empty.HandshakeComplete != false {
		t.Error("empty state HandshakeComplete not false")
	}

	// 构造带 peer 证书的状态需要 gmsm 证书对象;此处通过 Client/Server 初始化
	// 失败路径间接覆盖转换入口,并验证 PeerSign/EncCert 拆分逻辑的边界。
	// 用一个无证书的状态:sign/enc 字段应为 nil。
	cs := convertConnectionState(gotlcp.ConnectionState{
		Version:           gotlcp.VersionTLCP,
		HandshakeComplete: true,
		CipherSuite:       SuiteECDHE_SM2_SM4_GCM_SM3,
		ServerName:        "test",
	})
	if cs.Version != gotlcp.VersionTLCP {
		t.Errorf("Version = %v", cs.Version)
	}
	if cs.CipherSuite != SuiteECDHE_SM2_SM4_GCM_SM3 {
		t.Errorf("CipherSuite = 0x%04X", cs.CipherSuite)
	}
	if cs.PeerSignCert != nil || cs.PeerEncCert != nil {
		t.Error("empty peer certs should yield nil sign/enc")
	}
}

// TestConn_NilInner_InitError 覆盖配置转换失败(initErr)路径:
// Handshake 返回 initErr,Read/Write/ConnectionState 等优雅降级。
func TestConn_NilInner_InitError(t *testing.T) {
	// nil config → configToGotlcp 返回错误,inner 为 nil,initErr 被记录
	c := Client(&netPipeConn{}, nil)

	// Handshake 应返回 initErr 而非 panic
	if err := c.Handshake(); err == nil {
		t.Error("Handshake() err = nil, want initErr")
	}
	// HandshakeContext 同样
	if err := c.HandshakeContext(context.Background()); err == nil {
		t.Error("HandshakeContext() err = nil, want initErr")
	}

	// Read/Write 在 inner==nil 时返回 initErr
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Error("Read() err = nil, want initErr")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("Write() err = nil, want initErr")
	}

	// ConnectionState 在 inner==nil 时返回零值
	if got := c.ConnectionState(); got.HandshakeComplete {
		t.Error("ConnectionState() on nil inner returned HandshakeComplete=true")
	}

	// NetConn 在 inner==nil 时返回 rawConn
	if c.NetConn() == nil {
		t.Error("NetConn() = nil, want rawConn")
	}

	// Close 不应 panic
	if err := c.Close(); err != nil {
		t.Errorf("Close() err = %v", err)
	}
}

// TestConn_NilInner_AddrAndDeadline 验证 nil-inner 时地址/deadline 回退到 rawConn。
func TestConn_NilInner_AddrAndDeadline(t *testing.T) {
	raw := &netPipeConn{}
	c := Client(raw, nil)

	if c.LocalAddr() == nil {
		t.Error("LocalAddr() = nil, want rawConn addr")
	}
	if c.RemoteAddr() == nil {
		t.Error("RemoteAddr() = nil, want rawConn addr")
	}
	// SetDeadline 委托给 rawConn
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline() err = %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline() err = %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline() err = %v", err)
	}
}

// TestServer_NilConfig 验证服务端连接的 initErr 路径。
func TestServer_NilConfig(t *testing.T) {
	c := Server(&netPipeConn{}, nil)
	if err := c.Handshake(); err == nil {
		t.Error("Server(nil config) Handshake err = nil, want error")
	}
}

// TestConn_NotInitialized 验证 inner==nil 且 rawConn==nil 时
// 各方法返回 "connection not initialized" 错误(守护分支)。
// 正常 Client/Server 路径总会设置 rawConn,此分支防御内部误构造。
func TestConn_NotInitialized(t *testing.T) {
	c := &Conn{} // inner==nil, rawConn==nil, initErr==nil

	if err := c.SetDeadline(time.Now()); err == nil {
		t.Error("SetDeadline() err = nil, want not-initialized error")
	}
	if err := c.SetReadDeadline(time.Now()); err == nil {
		t.Error("SetReadDeadline() err = nil, want not-initialized error")
	}
	if err := c.SetWriteDeadline(time.Now()); err == nil {
		t.Error("SetWriteDeadline() err = nil, want not-initialized error")
	}

	// Close 在两者皆 nil 时返回 nil(无资源可释放)
	if err := c.Close(); err != nil {
		t.Errorf("Close() err = %v, want nil", err)
	}
	// LocalAddr/RemoteAddr 在两者皆 nil 时返回 nil
	if c.LocalAddr() != nil || c.RemoteAddr() != nil {
		t.Error("LocalAddr/RemoteAddr should be nil when uninitialized")
	}
	// NetConn 返回 nil(rawConn 为 nil)
	if c.NetConn() != nil {
		t.Error("NetConn() should be nil when rawConn is nil")
	}
}

// netPipeConn 是一个最小 net.Conn 实现,用于测试 rawConn 回退路径。
type netPipeConn struct {
	deadline time.Time
}

func (n *netPipeConn) Read(b []byte) (int, error)         { return 0, errors.New("closed") }
func (n *netPipeConn) Write(b []byte) (int, error)        { return 0, errors.New("closed") }
func (n *netPipeConn) Close() error                       { return nil }
func (n *netPipeConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (n *netPipeConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (n *netPipeConn) SetDeadline(t time.Time) error      { n.deadline = t; return nil }
func (n *netPipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (n *netPipeConn) SetWriteDeadline(t time.Time) error { return nil }
