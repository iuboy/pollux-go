package quic

import (
	"context"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// Listener wraps a QUIC listener.
type Listener struct {
	inner *quic.Listener
	cfg   *ServerConfig
}

// Listen creates a QUIC listener on the given address.
//
// ctx is accepted for API symmetry with ListenAndServe-style helpers and with
// quic-go's Accept(ctx) loop; quic.ListenAddr itself does not take a context,
// so cancelling ctx after a successful Listen does NOT close the listener.
// Callers that need cancellation must defer Listener.Close() themselves.
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error) {
	_ = ctx // accepted for symmetry; see doc comment above
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
	// Accepted (server-side) connections have no caller-owned UDP socket:
	// the listener's single Transport owns it and tears it down on
	// Listener.Close. udpConn stays nil here.
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

	// udpConn is the caller-owned UDP socket on the Dial path. quic.Dial's
	// internal Transport sets createdConn=false for caller-supplied packet
	// conns, so Transport.Close() only calls SetReadDeadline on the UDP
	// socket — it does NOT close it. We retain the *net.UDPConn so Conn.Close
	// can release the fd explicitly. nil for server-side (Accept) connections.
	udpConn *net.UDPConn

	closeOnce sync.Once
	closeErr  error
}

// Dial establishes a QUIC connection to the given address.
//
// Resource ownership: pollux-go owns the UDP socket because quic.Dial's
// internal Transport sets createdConn=false for caller-supplied packet
// conns (see quic-go transport.go Close: only the createdConn=true branch
// calls Conn.Close()). Conn.Close() therefore closes both the QUIC session
// and the underlying UDP socket to prevent fd leaks across many Dial calls.
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
	return &Conn{inner: qc, udpConn: udpConn}, nil
}

// OpenStream opens a new bidirectional stream.
//
// Note: this wraps quic-go's OpenStreamSync (synchronous — blocks until the
// peer permits the stream or ctx expires), NOT its non-blocking OpenStream.
// The method name keeps the shorter form for ergonomics; callers that need
// non-blocking semantics must use c.inner.OpenStream() directly.
func (c *Conn) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.inner.OpenStreamSync(ctx)
}

// AcceptStream accepts an incoming stream.
func (c *Conn) AcceptStream(ctx context.Context) (*quic.Stream, error) {
	return c.inner.AcceptStream(ctx)
}

// Close is idempotent and safe for concurrent invocation. It closes the QUIC
// session first (which signals the peer and stops the transport's read loop),
// then closes the underlying UDP socket on the Dial path. On the Accept path
// udpConn is nil and only the QUIC session is closed.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		// CloseWithError triggers transport shutdown; the QUIC layer's
		// background goroutine stops reading from udpConn once the session
		// is torn down, so closing the UDP socket afterwards is safe.
		c.closeErr = c.inner.CloseWithError(0, "done")
		if c.udpConn != nil {
			// Best-effort: UDP Close errors are not actionable to callers,
			// and Conn close semantics are dominated by the QUIC session.
			_ = c.udpConn.Close()
		}
	})
	return c.closeErr
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.inner.RemoteAddr()
}
