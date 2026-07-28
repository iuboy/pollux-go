package quic

import (
	"context"
	"net"

	"github.com/quic-go/quic-go"
)

// Listener wraps a QUIC listener.
type Listener struct {
	inner *quic.Listener
	cfg   *ServerConfig
}

// Listen creates a QUIC listener on the given address.
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error) {
	tlsCfg, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	qln, err := quic.ListenAddr(cfg.Addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:     cfg.idleTimeout(),
		MaxIncomingStreams: cfg.MaxIncomingStreams,
		Allow0RTT:          false,
	})
	if err != nil {
		return nil, err
	}
	return &Listener{inner: qln, cfg: &cfg}, nil
}

// Accept waits for and returns the next connection.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{inner: qc}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}

// Conn wraps a QUIC connection.
type Conn struct {
	inner *quic.Conn
}

// Dial establishes a QUIC connection to the given address.
// On success, the underlying UDP connection ownership is transferred to
// the returned quic.Conn; callers must not close or use the UDP connection
// directly. The UDP connection is only cleaned up on error.
func Dial(ctx context.Context, cfg ClientConfig) (*Conn, error) {
	tlsCfg, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	qc, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout: cfg.idleTimeout(),
	})
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	return &Conn{inner: qc}, nil
}

// OpenStream opens a new bidirectional stream.
func (c *Conn) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.inner.OpenStreamSync(ctx)
}

// AcceptStream accepts an incoming stream.
func (c *Conn) AcceptStream(ctx context.Context) (*quic.Stream, error) {
	return c.inner.AcceptStream(ctx)
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.inner.CloseWithError(0, "done")
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.inner.RemoteAddr()
}
