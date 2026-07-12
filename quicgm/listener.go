package quicgm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// defaultTicketKeyRotation is how often a Listener rotates its session-ticket
// encryption key. RFC 8446 §4.6.1 recommends rotating at ticket_lifetime/2;
// pollux-go issues 2-hour tickets, so 1 hour is the natural cadence.
const defaultTicketKeyRotation = time.Hour

// Listener wraps a QUIC listener running the RFC 8998 GM stack (Route C).
type Listener struct {
	inner      *quic.Listener
	ticketKeys *ticketKeyRotator
}

// Listen creates a QUIC listener on addr using the SM4-GCM-SM3 GM cipher suite.
// The handshake is driven by pollux-go's tls13gm engine (via the fork's
// GMCryptoSetup); crypto/tls is not used.
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error) {
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, errNoServerCert
	}
	// ClientCAs is declared on ServerConfig but the GM handshake layer does
	// not yet support mutual TLS. Fail loudly rather than silently ignoring
	// the field — a caller who sets ClientCAs expects client-cert enforcement.
	if cfg.ClientCAs != nil {
		return nil, errors.New("quicgm: ClientCAs is not yet supported by the GM handshake layer")
	}
	// Stateless RFC 8446 tickets: the Listener owns the TEK rotator (current +
	// previous) shared by every accepted connection, so a ticket issued on one
	// connection is resumable on another.
	rotator, err := newTicketKeyRotator(cfg.SessionTicketKey, defaultTicketKeyRotation)
	if err != nil {
		return nil, err
	}
	// tls.Config is unused in GM mode (GMCryptoSetup ignores it), but a non-nil
	// placeholder avoids any nil-check in quic.ListenAddr before the GM branch.
	qln, err := quic.ListenAddr(cfg.Addr, &tls.Config{}, &quic.Config{
		GMSM4GCM:           true,
		GMHandshakeConfig:  &quic.GMHandshakeConfig{Server: cfg.tls13ServerConfig(rotator.keys)},
		MaxIdleTimeout:     cfg.idleTimeout(),
		MaxIncomingStreams: cfg.MaxIncomingStreams,
	})
	if err != nil {
		return nil, err
	}
	return &Listener{inner: qln, ticketKeys: rotator}, nil
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

	ticketMu        sync.Mutex
	sessionIdentity []byte
	sessionPSK      []byte
	ticketAgeAdd    uint32
}

// withTicketCollector wires a quic.Config callback so that a NewSessionTicket
// received on the client is captured for later reuse (resumption / 0-RTT). It
// returns a shallow-cloned *quic.Config carrying the callback.
func withTicketCollector(qcfg *quic.Config, conn *Conn) *quic.Config {
	clone := *qcfg
	clone.GMOnClientSessionTicket = func(identity, psk []byte, ticketAgeAdd uint32) {
		conn.ticketMu.Lock()
		conn.sessionIdentity = append(conn.sessionIdentity[:0], identity...)
		conn.sessionPSK = append(conn.sessionPSK[:0], psk...)
		conn.ticketAgeAdd = ticketAgeAdd
		conn.ticketMu.Unlock()
	}
	return &clone
}

// SessionTicket returns the opaque ticket identity, the derived resumption PSK,
// and ticket_age_add from the most recent NewSessionTicket received from the
// server (client side). Feed them back as ClientConfig.ResumptionIdentity /
// ResumptionPSK / ResumptionObfuscatedTicketAge on a subsequent Dial(Early) to
// resume. ok is false until a ticket has arrived; tickets arrive
// post-handshake, so callers must allow time after Dial returns.
func (c *Conn) SessionTicket() (identity, psk []byte, ticketAgeAdd uint32, ok bool) {
	c.ticketMu.Lock()
	defer c.ticketMu.Unlock()
	// Return defensive copies so internal buffers never escape — the ticket
	// collector callback reuses the same backing arrays for the next ticket.
	identity = append([]byte(nil), c.sessionIdentity...)
	psk = append([]byte(nil), c.sessionPSK...)
	return identity, psk, c.ticketAgeAdd, len(c.sessionPSK) > 0
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
