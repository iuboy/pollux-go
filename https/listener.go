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
	// in ClientHello, even when negotiating TLS 1.2 or 1.3. Therefore,
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

// hybridListener accepts both TLS and TLCP connections on the same port.
// It peeks the record header version field to distinguish protocols:
//   - TLCP 1.1: version = 0x0101
//   - TLS:      version = 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), or 0x0303 (TLS 1.2)
//
// Security considerations:
//  1. The TLS/TLCP handshake runs synchronously inside Accept. A slow or
//     malicious client can block the accept loop, preventing other connections from
//     being served. HandshakeTimeout mitigates this risk.
//  2. Protocol detection is based on the ClientHello record header version:
//     - TLCP uses 0x0101
//     - TLS uses 0x03xx (0x0301, 0x0302, 0x0303 for TLS 1.0/1.1/1.2)
//     Note: Go TLS clients send 0x0301 as the legacy record version even when
//     negotiating TLS 1.2 or 1.3. We accept all 0x03xx as TLS and let the
//     underlying tls.Config handle version negotiation.
//  3. For production use, consider using separate listeners for TLS and TLCP
//     to eliminate protocol ambiguity and reduce attack surface.
//
// SECURITY WARNING: Protocol detection relies on the unauthenticated record
// header version field. An active network attacker can craft a ClientHello
// that mimics TLCP (version 0x0101) or TLS (version 0x03xx) to trigger
// the wrong protocol handler. ProtocolMask provides coarse filtering only
// and is NOT a security boundary. Deployments that can dedicate one port
// per protocol should use two separate listeners to avoid this.
type hybridListener struct {
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
// protocol-detection step entirely; see the hybridListener security notes above
// for the trade-offs (protocol detection relies on the unauthenticated record
// header version field).
func NewHybridListener(inner net.Listener, tlcpCfg *tlcp.Config, tlsCfg *tls.Config) *hybridListener {
	return &hybridListener{
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
// safe. However, Accept snapshots handshakeTimeout into a local under l.mu and
// then uses that snapshot without re-checking — so a SetHandshakeTimeout call
// made AFTER Accept has released the lock only takes effect on the NEXT Accept.
// This is the intended hot-reload contract: in-flight handshakes use the
// timeout that was current when they started. Callers that need to abort an
// in-flight handshake should close the underlying listener instead.
func (l *hybridListener) SetHandshakeTimeout(d time.Duration) {
	l.mu.Lock()
	l.handshakeTimeout = d
	l.mu.Unlock()
}

// SetProtocolMask sets which protocol versions are allowed.
//
// Concurrency: see SetHandshakeTimeout — the field write is race-safe, but
// Accept uses a snapshot, so a change only takes effect on the next Accept.
func (l *hybridListener) SetProtocolMask(mask ProtocolMask) {
	l.mu.Lock()
	l.protocolMask = mask
	l.mu.Unlock()
}

func (l *hybridListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Apply both read+write deadline for the handshake phase. A read-only
	// deadline does not protect against clients that stall reads during the
	// server's handshake writes (ServerHello, Certificate, etc.).
	l.mu.Lock()
	timeout := l.handshakeTimeout
	mask := l.protocolMask
	l.mu.Unlock()
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			return nil, err
		}
	}

	// bufio.NewReader wraps conn so Peek can inspect the record-header version
	// without consuming bytes the subsequent TLS/TLCP handshake needs. The
	// default 4096-byte buffer is held for the connection's lifetime via the
	// readerConn wrapper, even though only the first 5 bytes are needed post-
	// Peek. For long-lived connections (WebSocket, gRPC) this 4KB/conn is an
	// accepted tradeoff — the alternative (reading 5 bytes into a fixed buffer
	// and prepending them via a custom net.Conn) would re-implement
	// bufio.Reader's framing. If a deployment with very high conn counts
	// needs to claw back the 4KB, switch to a manual 5-byte read + prepend.
	br := bufio.NewReader(conn)
	header, err := br.Peek(recordHeaderLen)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if header[0] != recordHandshake {
		conn.Close()
		return nil, errNotHandshake
	}

	version := binary.BigEndian.Uint16(header[1:3])

	// Coarse-grained protocol detection based on record header version.
	// TLCP: 0x0101
	// TLS: 0x03xx (any TLS version - actual version control via tls.Config)
	var useTLCP bool
	switch version {
	case tlcpVersion11:
		if !mask.AllowTLCP {
			conn.Close()
			return nil, errProtocolNotAllowed
		}
		useTLCP = true
	default:
		// Accept all 0x03xx as TLS (covers TLS 1.0/1.1/1.2/1.3 record headers)
		if version >= minTLSVersion && version <= maxTLSVersion {
			if !mask.AllowTLS {
				conn.Close()
				return nil, errProtocolNotAllowed
			}
			useTLCP = false
		} else {
			// Unknown version - reject to avoid protocol confusion attacks.
			// Distinct from errProtocolNotAllowed so a debugger can tell a
			// ProtocolMask-filtered rejection (operator policy) from a genuinely
			// unknown version (e.g. 0x0200, SSLv3 0x0300) that never matched
			// any expected protocol family.
			conn.Close()
			return nil, fmt.Errorf("%w: 0x%04x", errUnknownProtocol, version)
		}
	}

	rconn := &readerConn{Conn: conn, reader: br}

	var resultConn net.Conn
	if useTLCP {
		tc := tlcp.Server(rconn, l.tlcpCfg)
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		resultConn = tc
	} else {
		tc := tls.Server(rconn, l.tlsCfg)
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		resultConn = tc
	}

	// Clear the deadline after successful handshake.
	if timeout > 0 {
		if err := resultConn.SetDeadline(time.Time{}); err != nil {
			resultConn.Close()
			return nil, err
		}
	}

	return resultConn, nil
}

// readerConn wraps a bufio.Reader + net.Conn so buffered bytes are
// consumed before reading from the underlying connection.
type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (rc *readerConn) Read(b []byte) (int, error) {
	return rc.reader.Read(b)
}
