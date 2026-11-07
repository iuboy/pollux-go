package tlcp

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/iuboy/pollux-go/internal/panicsafe"
)

// Conn represents a TLCP secure connection, implements net.Conn interface.
// It wraps the native pollux TLCP engine (tlcpConn).
type Conn struct {
	inner    *tlcpConn
	config   *Config
	rawConn  net.Conn
	isClient bool
	initErr  error // stores error from config conversion, deferred to Handshake
}

// errNilConn 是 nil 接收者上调用 Conn 方法的失败哨兵：(*Conn)(nil) 存入
// net.Conn 等接口字段后接口值非 nil（typed-nil 陷阱），下游据「接口非 nil」
// 判定调用 Close/Read/Write 会命中 nil 接收者——无守卫时解引用 c.inner 即
// panic（https 侧曾因此 panic，触发点已在彼处归一化；此处是引擎侧的最后防
// 线）。守卫把 panic 转为可归因错误。
var errNilConn = errors.New("tlcp: use of nil Conn")

// Client returns a TLCP client connection.
// Follows the pattern of tls.Client(conn, config).
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: true}
	nc, err := configToNative(config, true)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = newTLCPConn(conn, nc, true)
	return c
}

// Server returns a TLCP server connection.
// Follows the pattern of tls.Server(conn, config).
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: false}
	nc, err := configToNative(config, false)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = newTLCPConn(conn, nc, false)
	return c
}

// Handshake 执行 TLCP 握手；nil 接收者返回 errNilConn（typed-nil 接口陷阱
// 防御，见 errNilConn）。
func (c *Conn) Handshake() error {
	if c == nil {
		return errNilConn
	}
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.Handshake()
	})
}

// HandshakeContext performs the TLCP handshake with context. Cancellation
// mirrors crypto/tls.Conn.HandshakeContext: a canceled or deadline-exceeded
// ctx interrupts an in-flight handshake by closing the underlying conn, and
// this call returns promptly with the context error.
//
// nil 接收者返回 errNilConn（typed-nil 接口陷阱防御，见 errNilConn）。
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c == nil {
		return errNilConn
	}
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.HandshakeContext(ctx)
	})
}

// Read 读取解密后的应用数据；nil 接收者返回 errNilConn（typed-nil 接口陷阱
// 防御，见 errNilConn）。
func (c *Conn) Read(b []byte) (int, error) {
	if c == nil {
		return 0, errNilConn
	}
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			// net.Conn convention: (0, nil) is ambiguous (could mean EOF).
			// Return an explicit error so callers never mistake an uninitialized
			// connection for a clean close. When the constructor recorded a
			// config-conversion failure we surface that; otherwise this is a
			// programming error (Conn used before/without Handshake success).
			if c.initErr != nil {
				return 0, c.initErr
			}
			return 0, errors.New("tlcp: connection not initialized")
		}
		return c.inner.Read(b)
	})
}

// Write 写入应用数据；nil 接收者返回 errNilConn（typed-nil 接口陷阱防御，
// 见 errNilConn）。
func (c *Conn) Write(b []byte) (int, error) {
	if c == nil {
		return 0, errNilConn
	}
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			// See Read: never return (0, nil) for an uninitialized connection.
			if c.initErr != nil {
				return 0, c.initErr
			}
			return 0, errors.New("tlcp: connection not initialized")
		}
		return c.inner.Write(b)
	})
}

// Close 关闭连接（先尽力发 close_notify 告警再关底层传输，见引擎侧
// tlcpConn.Close）；nil 接收者返回 errNilConn——typed-nil 接口陷阱下
// (*Conn)(nil) 流入 net.Conn 字段后接口值非 nil，下游的防御性 Close 必须
// 报错而非 panic。
func (c *Conn) Close() error {
	if c == nil {
		return errNilConn
	}
	if c.inner != nil {
		return c.inner.Close()
	}
	if c.rawConn != nil {
		if c.initErr != nil {
			_ = c.rawConn.Close()
			return c.initErr
		}
		return c.rawConn.Close()
	}
	return nil
}

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr {
	if c == nil {
		return nil // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.LocalAddr()
	}
	// When uninitialized, return nil rather than rawConn's address to
	// avoid misleading callers into believing the connection is valid.
	return nil
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil {
		return nil // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.RemoteAddr()
	}
	// When uninitialized, return nil rather than rawConn's address to
	// avoid misleading callers into believing the connection is valid.
	return nil
}

// SetDeadline sets the read/write deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil {
		return errNilConn // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.SetDeadline(t)
	}
	if c.initErr != nil {
		return c.initErr
	}
	if c.rawConn != nil {
		return c.rawConn.SetDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return errNilConn // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.SetReadDeadline(t)
	}
	if c.initErr != nil {
		return c.initErr
	}
	if c.rawConn != nil {
		return c.rawConn.SetReadDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return errNilConn // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.SetWriteDeadline(t)
	}
	if c.initErr != nil {
		return c.initErr
	}
	if c.rawConn != nil {
		return c.rawConn.SetWriteDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// NegotiatedProtocol 返回握手协商的 ALPN 协议（RFC 7301）；未协商时为空串。
// 命名对齐 tls13gm 的 Handshaker.NegotiatedProtocol，取值与
// ConnectionState().NegotiatedProtocol 一致。任一侧未配置 NextProtos、
// 客户端未提议、或服务端未回 ALPN 扩展均视为未协商。连接未初始化
// （构造期配置错误）或 nil 接收者（typed-nil 接口陷阱防御，见 errNilConn）
// 时返回空串。
func (c *Conn) NegotiatedProtocol() string {
	if c == nil || c.inner == nil {
		return ""
	}
	return c.inner.ConnectionState().NegotiatedProtocol
}

// ConnectionState returns the connection's security parameters.
func (c *Conn) ConnectionState() ConnectionState {
	if c == nil || c.inner == nil {
		return ConnectionState{}
	}
	es := c.inner.ConnectionState()
	result := ConnectionState{
		Version:            es.Version,
		HandshakeComplete:  es.HandshakeComplete,
		CipherSuite:        es.CipherSuite,
		ServerName:         es.ServerName,
		PeerCertificates:   es.PeerCertificates,
		DidResume:          es.DidResume,
		NegotiatedProtocol: es.NegotiatedProtocol,
	}
	// TLCP convention: [0]=signing, [1]=encryption.
	// Defensively validate certificate count before indexing.
	if len(result.PeerCertificates) >= 1 {
		result.PeerSignCert = result.PeerCertificates[0]
	}
	if len(result.PeerCertificates) >= 2 {
		result.PeerEncCert = result.PeerCertificates[1]
	}
	return result
}

// NetConn returns the underlying connection.
func (c *Conn) NetConn() net.Conn {
	if c == nil {
		return nil // typed-nil 接口陷阱防御（见 errNilConn）
	}
	if c.inner != nil {
		return c.inner.NetConn()
	}
	return c.rawConn
}
