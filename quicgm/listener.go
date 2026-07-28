package quicgm

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// Listener wraps a QUIC listener running the RFC 8998 GM stack (Route C).
type Listener struct {
	inner    *quic.Listener
	issuedPSK *pskStore
}

// Listen creates a QUIC listener on addr using the SM4-GCM-SM3 GM cipher suite.
// The handshake is driven by pollux-go's tls13gm engine (via the fork's
// GMCryptoSetup); crypto/tls is not used.
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error) {
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, errNoServerCert
	}
	// The PSK store is shared across all server connections this Listener
	// accepts, so a ticket issued on one connection can drive resumption / 0-RTT
	// on another. Single-process only.
	store := newPSKStore()
	// tls.Config is unused in GM mode (GMCryptoSetup ignores it), but a non-nil
	// placeholder avoids any nil-check in quic.ListenAddr before the GM branch.
	qln, err := quic.ListenAddr(cfg.Addr, &tls.Config{}, &quic.Config{
		GMSM4GCM:          true,
		GMHandshakeConfig: &quic.GMHandshakeConfig{Server: cfg.tls13ServerConfig(store)},
		MaxIdleTimeout:    cfg.idleTimeout(),
		MaxIncomingStreams: cfg.MaxIncomingStreams,
	})
	if err != nil {
		return nil, err
	}
	return &Listener{inner: qln, issuedPSK: store}, nil
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

	ticketMu     sync.Mutex
	sessionPSK   []byte
	ticketAgeAdd uint32
}

// withTicketCollector wires a quic.Config callback so that a NewSessionTicket
// received on the client is captured for later reuse as a resumption PSK
// (0-RTT). It returns a shallow-cloned *quic.Config carrying the callback.
func withTicketCollector(qcfg *quic.Config, conn *Conn) *quic.Config {
	clone := *qcfg
	clone.GMOnClientSessionTicket = func(psk []byte, ticketAgeAdd uint32) {
		conn.ticketMu.Lock()
		conn.sessionPSK = append(conn.sessionPSK[:0], psk...)
		conn.ticketAgeAdd = ticketAgeAdd
		conn.ticketMu.Unlock()
	}
	return &clone
}

// SessionTicket returns the resumption PSK and ticket_age_add from the most
// recent NewSessionTicket received from the server (client side). The PSK can be
// fed back as ClientConfig.ResumptionPSK and the ticket_age_add as
// ResumptionObfuscatedTicketAge (for a ticket age of ~0) on a subsequent
// DialEarly to attempt 0-RTT. ok is false until a ticket has arrived; tickets
// arrive post-handshake, so callers must allow time after Dial returns.
func (c *Conn) SessionTicket() (psk []byte, ticketAgeAdd uint32, ok bool) {
	c.ticketMu.Lock()
	defer c.ticketMu.Unlock()
	return c.sessionPSK, c.ticketAgeAdd, len(c.sessionPSK) > 0
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
	conn := &Conn{}
	qc, err := quic.Dial(ctx, udpConn, udpAddr, &tls.Config{}, withTicketCollector(&quic.Config{
		GMSM4GCM:          true,
		GMHandshakeConfig: &quic.GMHandshakeConfig{Client: clientCfg},
		MaxIdleTimeout:    cfg.idleTimeout(),
	}, conn))
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	conn.inner = qc
	return conn, nil
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
	conn := &Conn{}
	qc, err := quic.DialEarly(ctx, udpConn, udpAddr, &tls.Config{}, withTicketCollector(&quic.Config{
		GMSM4GCM:          true,
		GMHandshakeConfig: &quic.GMHandshakeConfig{Client: clientCfg},
		MaxIdleTimeout:    cfg.idleTimeout(),
	}, conn))
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	conn.inner = qc
	return conn, nil
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

// ConnectionState returns the connection state. Used0RTT is true on the client
// when it offered 0-RTT (derived early traffic keys), and on the server when it
// accepted the client's 0-RTT (echoed early_data in EncryptedExtensions).
func (c *Conn) ConnectionState() quic.ConnectionState { return c.inner.ConnectionState() }
