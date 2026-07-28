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

// Handshake performs the TLCP handshake.
func (c *Conn) Handshake() error {
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.Handshake()
	})
}

// HandshakeContext performs the TLCP handshake with context.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return panicsafe.Do(func() error {
		if c.initErr != nil {
			return c.initErr
		}
		return c.inner.HandshakeContext(ctx)
	})
}

// Read reads application data from the connection.
func (c *Conn) Read(b []byte) (int, error) {
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			return 0, c.initErr
		}
		return c.inner.Read(b)
	})
}

// Write writes application data to the connection.
func (c *Conn) Write(b []byte) (int, error) {
	return panicsafe.Do1(func() (int, error) {
		if c.inner == nil {
			return 0, c.initErr
		}
		return c.inner.Write(b)
	})
}

// Close closes the connection.
func (c *Conn) Close() error {
	if c.inner != nil {
		return c.inner.Close()
	}
	if c.rawConn != nil {
		return c.rawConn.Close()
	}
	return nil
}

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr {
	if c.inner != nil {
		return c.inner.LocalAddr()
	}
	if c.rawConn != nil {
		return c.rawConn.LocalAddr()
	}
	return nil
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	if c.inner != nil {
		return c.inner.RemoteAddr()
	}
	if c.rawConn != nil {
		return c.rawConn.RemoteAddr()
	}
	return nil
}

// SetDeadline sets the read/write deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetDeadline(t)
	}
	if c.rawConn != nil {
		return c.rawConn.SetDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetReadDeadline(t)
	}
	if c.rawConn != nil {
		return c.rawConn.SetReadDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.inner != nil {
		return c.inner.SetWriteDeadline(t)
	}
	if c.rawConn != nil {
		return c.rawConn.SetWriteDeadline(t)
	}
	return errors.New("tlcp: connection not initialized")
}

// ConnectionState returns the connection's security parameters.
func (c *Conn) ConnectionState() ConnectionState {
	if c.inner == nil {
		return ConnectionState{}
	}
	es := c.inner.ConnectionState()
	result := ConnectionState{
		Version:           es.Version,
		HandshakeComplete: es.HandshakeComplete,
		CipherSuite:       es.CipherSuite,
		ServerName:        es.ServerName,
		PeerCertificates:  es.PeerCertificates,
	}
	// TLCP convention: [0]=signing, [1]=encryption.
	if len(result.PeerCertificates) > 0 {
		result.PeerSignCert = result.PeerCertificates[0]
	}
	if len(result.PeerCertificates) > 1 {
		result.PeerEncCert = result.PeerCertificates[1]
	}
	return result
}

// NetConn returns the underlying connection.
func (c *Conn) NetConn() net.Conn {
	if c.inner != nil {
		return c.inner.NetConn()
	}
	return c.rawConn
}
