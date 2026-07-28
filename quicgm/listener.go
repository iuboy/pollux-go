package quicgm

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

// Listener wraps a QUIC listener running the RFC 8998 GM stack (Route C).
type Listener struct {
	inner *quic.Listener
}

// Listen creates a QUIC listener on addr using the SM4-GCM-SM3 GM cipher suite.
// The handshake is driven by pollux-go's tls13gm engine (via the fork's
// GMCryptoSetup); crypto/tls is not used.
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error) {
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, errNoServerCert
	}
	// tls.Config is unused in GM mode (GMCryptoSetup ignores it), but a non-nil
	// placeholder avoids any nil-check in quic.ListenAddr before the GM branch.
	qln, err := quic.ListenAddr(cfg.Addr, &tls.Config{}, &quic.Config{
		GMSM4GCM:           true,
		GMHandshakeConfig:  &quic.GMHandshakeConfig{Server: cfg.tls13ServerConfig()},
		MaxIdleTimeout:     cfg.idleTimeout(),
		MaxIncomingStreams: cfg.MaxIncomingStreams,
	})
	if err != nil {
		return nil, err
	}
	return &Listener{inner: qln}, nil
}

// Accept waits for and returns the next GM QUIC connection.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{inner: qc}, nil
}

// Close closes the listener.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Conn wraps a GM QUIC connection.
type Conn struct {
	inner *quic.Conn
}

// Dial establishes a GM QUIC connection to cfg.Addr. On success the underlying
// UDP connection is owned by the returned Conn; it is only closed on error.
func Dial(ctx context.Context, cfg ClientConfig) (*Conn, error) {
	clientCfg, err := cfg.tls13ClientConfig()
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
	qc, err := quic.Dial(ctx, udpConn, udpAddr, &tls.Config{}, &quic.Config{
		GMSM4GCM:          true,
		GMHandshakeConfig: &quic.GMHandshakeConfig{Client: clientCfg},
		MaxIdleTimeout:    cfg.idleTimeout(),
	})
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	return &Conn{inner: qc}, nil
}

// DialEarly establishes a GM QUIC connection and returns it before the
// handshake completes, enabling 0-RTT. The client must carry a ResumptionPSK
// (from a prior connection's NewSessionTicket) to attempt 0-RTT; data written
// before the handshake completes is sent as 0-RTT and accepted only if the
// server is configured with AllowEarlyData + a valid AntiReplayCache.
func DialEarly(ctx context.Context, cfg ClientConfig) (*Conn, error) {
	clientCfg, err := cfg.tls13ClientConfig()
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
	qc, err := quic.DialEarly(ctx, udpConn, udpAddr, &tls.Config{}, &quic.Config{
		GMSM4GCM:          true,
		GMHandshakeConfig: &quic.GMHandshakeConfig{Client: clientCfg},
		MaxIdleTimeout:    cfg.idleTimeout(),
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
func (c *Conn) Close() error { return c.inner.CloseWithError(0, "done") }

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }
