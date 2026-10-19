package https

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/iuboy/pollux-go/tlcp"
)

var (
	errNotHandshake       = errors.New("pollux/https: not a TLS/TLCP handshake")
	errProtocolNotAllowed = errors.New("pollux/https: protocol version not allowed by ProtocolMask")
	errUnknownProtocol    = errors.New("pollux/https: unknown protocol version in record header")
)

const (
	recordHeaderLen = 5
	recordHandshake = 22
	tlcpVersion11   = 0x0101
	// TLS record header versions (used for protocol detection only)
	// Note: Go TLS clients use 0x0301 (TLS 1.0) as the legacy record version
	// in ClientHello, even when negotiating TLS 1.2 or TLS 1.3. Therefore,
	// we accept all TLS versions during protocol detection and rely on
	// tls.Config.MinVersion/MaxVersion for actual version control.
	minTLSVersion           = 0x0301
	maxTLSVersion           = 0x0303
	defaultHandshakeTimeout = 30 * time.Second
)

// ProtocolMask specifies which protocol versions are allowed.
// For TLS, the record header version is only used for coarse-grained
// protocol detection (TLCP vs TLS). Actual TLS version control is
// delegated to tls.Config.MinVersion/MaxVersion.
type ProtocolMask struct {
	// AllowTLCP enables TLCP (any version, detected by 0x0101 record header)
	AllowTLCP bool
	// AllowTLS enables TLS (any version, detected by 0x03xx record header)
	// The actual TLS version range is controlled by tls.Config.MinVersion/MaxVersion.
	AllowTLS bool
}

// DefaultProtocolMask returns a conservative protocol mask.
// Both TLCP and TLS are enabled by default. Use SetProtocolMask to customize.
func DefaultProtocolMask() ProtocolMask {
	return ProtocolMask{
		AllowTLCP: true,
		AllowTLS:  true,
	}
}

// HybridListener accepts both TLS and TLCP connections on the same port.
// It peeks the record header version field to distinguish protocols:
//   - TLCP 1.1: version = 0x0101
//   - TLS:      version = 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), or 0x0303 (TLS 1.2)
//
// Accept returns immediately with a lazy connection: the protocol sniff and
// the handshake run on the connection's first Read/Write, in the goroutine
// serving that connection. This mirrors crypto/tls.Listener (which also never
// handshakes inside Accept) and is load-bearing for two attack classes:
//
//  1. Accept must never return a client-triggerable error. http.Server.Serve
//     exits its accept loop on any non-temporary Accept error, so an Accept
//     that surfaced sniff/handshake failures let a single TCP connection that
//     closes immediately (io.EOF from Peek), sends one byte of plaintext, or
//     fails a handshake, permanently stop the whole server.
//  2. No per-connection work may run on the accept goroutine: a client that
//     connects and stalls would otherwise serialize every later connection
//     behind its handshake timeout.
//
// Security considerations:
//   - Protocol detection is based on the ClientHello record header version:
//     TLCP uses 0x0101, TLS uses 0x03xx. Go TLS clients send 0x0301 as the
//     legacy record version even when negotiating TLS 1.2/1.3; all 0x03xx are
//     accepted as TLS and the underlying tls.Config negotiates the version.
//   - For production use, consider using separate listeners for TLS and TLCP
//     to eliminate protocol ambiguity and reduce attack surface.
//
// SECURITY WARNING: Protocol detection relies on the unauthenticated record
// header version field. An active network attacker can craft a ClientHello
// that mimics TLCP (version 0x0101) or TLS (version 0x03xx) to trigger
// the wrong protocol handler. ProtocolMask provides coarse filtering only
// and is NOT a security boundary. Deployments that can dedicate one port
// per protocol should use two separate listeners to avoid this.
type HybridListener struct {
	net.Listener
	tlcpCfg          *tlcp.Config
	tlsCfg           *tls.Config
	mu               sync.Mutex
	handshakeTimeout time.Duration
	protocolMask     ProtocolMask
}

// NewHybridListener creates a listener that accepts both TLS and TLCP connections.
// Default handshake timeout is 30 seconds. Use SetHandshakeTimeout to customize.
// Default protocol mask allows both TLCP and TLS. Use SetProtocolMask to customize.
//
// This is a protocol multiplexing facade: it peeks the record header version
// field to route each connection to the TLCP or TLS handshake. For deployments
// that can dedicate one port per protocol, two separate listeners remove the
// protocol-detection step entirely; see the HybridListener security notes above
// for the trade-offs (protocol detection relies on the unauthenticated record
// header version field).
func NewHybridListener(inner net.Listener, tlcpCfg *tlcp.Config, tlsCfg *tls.Config) *HybridListener {
	return &HybridListener{
		Listener:         inner,
		tlcpCfg:          tlcpCfg,
		tlsCfg:           tlsCfg,
		handshakeTimeout: defaultHandshakeTimeout,
		protocolMask:     DefaultProtocolMask(),
	}
}

// SetHandshakeTimeout sets the maximum time to wait for handshake completion.
// A zero or negative value disables the timeout (not recommended for production).
//
// Concurrency: the field is read under l.mu, so the call itself is data-race
// safe. The timeout and mask are snapshotted into each accepted connection at
// Accept time, so a SetHandshakeTimeout call only affects connections accepted
// afterwards.
func (l *HybridListener) SetHandshakeTimeout(d time.Duration) {
	l.mu.Lock()
	l.handshakeTimeout = d
	l.mu.Unlock()
}

// SetProtocolMask sets which protocol versions are allowed.
//
// Concurrency: see SetHandshakeTimeout — the field write is race-safe; each
// connection uses the mask snapshotted when it was accepted.
func (l *HybridListener) SetProtocolMask(mask ProtocolMask) {
	l.mu.Lock()
	l.protocolMask = mask
	l.mu.Unlock()
}

// Accept returns the next raw connection wrapped in a lazy hybridConn.
// It never performs I/O and never fails for client-side reasons — see the
// HybridListener doc comment. The protocol sniff and handshake happen on the
// returned conn's first Read or Write.
func (l *HybridListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	timeout := l.handshakeTimeout
	mask := l.protocolMask
	l.mu.Unlock()
	return &hybridConn{
		raw:     conn,
		tlcpCfg: l.tlcpCfg,
		tlsCfg:  l.tlsCfg,
		mask:    mask,
		timeout: timeout,
	}, nil
}

// hybridConn is the lazy connection returned by HybridListener.Accept. The
// first Read or Write performs: set handshake deadline → sniff the record
// header → construct the TLCP or TLS server conn → drive the handshake.
// All later operations delegate to the negotiated conn. Negotiation runs at
// most once per connection; its result (conn or error) is cached.
type hybridConn struct {
	raw     net.Conn
	tlcpCfg *tlcp.Config
	tlsCfg  *tls.Config
	mask    ProtocolMask
	timeout time.Duration

	mu   sync.Mutex
	done bool
	sec  net.Conn // negotiated *tlcp.Conn or *tls.Conn; nil until done
	nerr error    // cached negotiation failure
}

var _ net.Conn = (*hybridConn)(nil)

// handshaker is the common surface of *tlcp.Conn and *tls.Conn used here.
type handshaker interface {
	net.Conn
	Handshake() error
}

// ensure negotiates the secure conn on first use (see hybridConn). The
// handshake deadline applies to the sniff + handshake phase and is cleared
// on success, so post-handshake I/O is unbounded by this mechanism ( callers
// set their own deadlines / http.Server timeouts).
func (c *hybridConn) ensure() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		if c.nerr != nil {
			return nil, c.nerr
		}
		return c.sec, nil
	}
	c.done = true

	if c.timeout > 0 {
		// Both read+write deadline: a read-only deadline does not protect
		// against clients that stall reads during the server's handshake
		// writes (ServerHello, Certificate, etc.).
		if err := c.raw.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			_ = c.raw.Close()
			c.nerr = err
			return nil, err
		}
	}

	// bufio wraps raw so Peek can inspect the record-header version without
	// consuming bytes the subsequent handshake needs. The 4096-byte buffer is
	// held for the connection's lifetime via the readerConn wrapper.
	br := bufio.NewReader(c.raw)
	header, err := br.Peek(recordHeaderLen)
	if err != nil {
		_ = c.raw.Close()
		c.nerr = err
		return nil, err
	}
	if header[0] != recordHandshake {
		_ = c.raw.Close()
		c.nerr = errNotHandshake
		return nil, c.nerr
	}

	version := binary.BigEndian.Uint16(header[1:3])

	// Coarse-grained protocol detection based on record header version.
	var useTLCP bool
	switch version {
	case tlcpVersion11:
		if !c.mask.AllowTLCP {
			_ = c.raw.Close()
			c.nerr = errProtocolNotAllowed
			return nil, c.nerr
		}
		useTLCP = true
	default:
		if version >= minTLSVersion && version <= maxTLSVersion {
			if !c.mask.AllowTLS {
				_ = c.raw.Close()
				c.nerr = errProtocolNotAllowed
				return nil, c.nerr
			}
			useTLCP = false
		} else {
			// Unknown version - reject to avoid protocol confusion attacks.
			// Distinct from errProtocolNotAllowed so a debugger can tell a
			// ProtocolMask-filtered rejection (operator policy) from a
			// genuinely unknown version (e.g. 0x0200, SSLv3 0x0300).
			_ = c.raw.Close()
			c.nerr = fmt.Errorf("%w: 0x%04x", errUnknownProtocol, version)
			return nil, c.nerr
		}
	}

	rconn := &readerConn{Conn: c.raw, reader: br}
	var sec handshaker
	if useTLCP {
		sec = tlcp.Server(rconn, c.tlcpCfg)
	} else {
		sec = tls.Server(rconn, c.tlsCfg)
	}
	if err := sec.Handshake(); err != nil {
		// Handshake failures are the connection's error, never the listener's
		// (see HybridListener doc). raw.Close also aborts any pending I/O.
		_ = c.raw.Close()
		c.nerr = err
		return nil, err
	}
	if c.timeout > 0 {
		if err := sec.SetDeadline(time.Time{}); err != nil {
			_ = sec.Close()
			c.nerr = err
			return nil, err
		}
	}
	c.sec = sec
	return sec, nil
}

func (c *hybridConn) Read(b []byte) (int, error) {
	sec, err := c.ensure()
	if err != nil {
		return 0, err
	}
	return sec.Read(b)
}

func (c *hybridConn) Write(b []byte) (int, error) {
	sec, err := c.ensure()
	if err != nil {
		return 0, err
	}
	return sec.Write(b)
}

func (c *hybridConn) Close() error {
	c.mu.Lock()
	sec := c.sec
	c.mu.Unlock()
	if sec != nil {
		return sec.Close()
	}
	return c.raw.Close()
}

func (c *hybridConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *hybridConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *hybridConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *hybridConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *hybridConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// readerConn wraps a bufio.Reader + net.Conn so buffered bytes are
// consumed before reading from the underlying connection.
type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (rc *readerConn) Read(b []byte) (int, error) {
	return rc.reader.Read(b)
}
