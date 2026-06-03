package tlcp

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/ycq/pollux/internal/panicsafe"
)

// Conn 表示一个 TLCP 安全连接，实现 net.Conn 接口。
// 底层委托给 gotlcp.Conn 实现 TLCP 协议。
type Conn struct {
	inner    *gotlcp.Conn
	config   *Config
	rawConn  net.Conn
	isClient bool
	initErr  error // config 转换失败时暂存错误，延迟到 Handshake 时返回
}

// Client 返回一个 TLCP 客户端连接。
// 参照 tls.Client(conn, config)。
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: true}
	gc, err := configToGotlcp(config)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = gotlcp.Client(conn, gc)
	return c
}

// Server 返回一个 TLCP 服务端连接。
// 参照 tls.Server(conn, config)。
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: false}
	gc, err := configToGotlcp(config)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = gotlcp.Server(conn, gc)
	return c
}

// Handshake 执行 TLCP 握手。
func (c *Conn) Handshake() error {
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.Handshake()
	})
}

// HandshakeContext 使用 context 执行 TLCP 握手。
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.HandshakeContext(ctx)
	})
}

// Read 从连接读取应用数据。
func (c *Conn) Read(b []byte) (int, error) {
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			return 0, c.initErr
		}
		return c.inner.Read(b)
	})
}

// Write 向连接写入应用数据。
func (c *Conn) Write(b []byte) (int, error) {
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			return 0, c.initErr
		}
		return c.inner.Write(b)
	})
}

// Close 关闭连接。
func (c *Conn) Close() error {
	if c.inner != nil {
		return c.inner.Close()
	}
	if c.rawConn != nil {
		return c.rawConn.Close()
	}
	return nil
}

// LocalAddr 返回本地地址。
func (c *Conn) LocalAddr() net.Addr {
	if c.inner != nil {
		return c.inner.LocalAddr()
	}
	if c.rawConn != nil {
		return c.rawConn.LocalAddr()
	}
	return nil
}

// RemoteAddr 返回远端地址。
func (c *Conn) RemoteAddr() net.Addr {
	if c.inner != nil {
		return c.inner.RemoteAddr()
	}
	if c.rawConn != nil {
		return c.rawConn.RemoteAddr()
	}
	return nil
}

// SetDeadline 设置读写截止时间。
func (c *Conn) SetDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetDeadline(t)
	}
	return c.rawConn.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间。
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetReadDeadline(t)
	}
	return c.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间。
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetWriteDeadline(t)
	}
	return c.rawConn.SetWriteDeadline(t)
}

// ConnectionState 返回连接的安全参数。
// 将 gotlcp 的 gmsm 证书类型转换为 stdlib 证书类型。
func (c *Conn) ConnectionState() ConnectionState {
	if c.inner == nil {
		return ConnectionState{}
	}
	return convertConnectionState(c.inner.ConnectionState())
}

// NetConn 返回底层连接。
func (c *Conn) NetConn() net.Conn {
	if c.inner != nil {
		return c.inner.NetConn()
	}
	return c.rawConn
}

// convertConnectionState 将 gotlcp.ConnectionState 转换为 pollux ConnectionState。
// 主要工作是将 gmsm/smx509.Certificate 转换为 crypto/x509.Certificate。
func convertConnectionState(cs gotlcp.ConnectionState) ConnectionState {
	result := ConnectionState{
		Version:           cs.Version,
		HandshakeComplete: cs.HandshakeComplete,
		CipherSuite:       cs.CipherSuite,
		ServerName:        cs.ServerName,
	}

	// 转换对端证书：gmsm smx509.Certificate → stdlib x509.Certificate
	for _, cert := range cs.PeerCertificates {
		result.PeerCertificates = append(result.PeerCertificates, cert.ToX509())
	}

	// TLCP 约定：PeerCertificates[0]=签名证书, [1]=加密证书
	if len(result.PeerCertificates) > 0 {
		result.PeerSignCert = result.PeerCertificates[0]
	}
	if len(result.PeerCertificates) > 1 {
		result.PeerEncCert = result.PeerCertificates[1]
	}

	// 转换验证链
	for _, chain := range cs.VerifiedChains {
		var stdChain []*x509.Certificate
		for _, cert := range chain {
			stdChain = append(stdChain, cert.ToX509())
		}
		result.VerifiedChains = append(result.VerifiedChains, stdChain)
	}

	return result
}
