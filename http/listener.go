package http

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/ycq/pollux/tlcp"
)

var (
	errNotHandshake       = errors.New("pollux/http: not a TLS/TLCP handshake")
	errProtocolNotAllowed = errors.New("pollux/http: protocol version not allowed")
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
// and is NOT a security boundary.
//
// This listener is DEPRECATED. Use separate ports for TLS and TLCP to
// eliminate protocol confusion risk.
type hybridListener struct {
	net.Listener
	tlcpCfg          *tlcp.Config
	tlsCfg           *tls.Config
	handshakeTimeout time.Duration
	protocolMask     ProtocolMask
}

// NewHybridListener creates a listener that accepts both TLS and TLCP connections.
// Default handshake timeout is 30 seconds. Use SetHandshakeTimeout to customize.
// Default protocol mask allows both TLCP and TLS. Use SetProtocolMask to customize.
//
// Deprecated: HybridListener shares state between two independent protocol stacks
// (TLS and TLCP) on the same port. This increases attack surface and makes it
// harder to reason about security properties. Use separate ports for TLS and TLCP
// instead. This function will be removed in a future release.
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
func (l *hybridListener) SetHandshakeTimeout(d time.Duration) {
	l.handshakeTimeout = d
}

// SetProtocolMask sets which protocol versions are allowed.
func (l *hybridListener) SetProtocolMask(mask ProtocolMask) {
	l.protocolMask = mask
}

func (l *hybridListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Apply read deadline for handshake phase
	if l.handshakeTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(l.handshakeTimeout)); err != nil {
			conn.Close()
			return nil, err
		}
	}

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
		if !l.protocolMask.AllowTLCP {
			conn.Close()
			return nil, errProtocolNotAllowed
		}
		useTLCP = true
	default:
		// Accept all 0x03xx as TLS (covers TLS 1.0/1.1/1.2/1.3 record headers)
		if version >= minTLSVersion && version <= maxTLSVersion {
			if !l.protocolMask.AllowTLS {
				conn.Close()
				return nil, errProtocolNotAllowed
			}
			useTLCP = false
		} else {
			// Unknown version - reject to avoid protocol confusion attacks
			conn.Close()
			return nil, errProtocolNotAllowed
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

	// Clear the read deadline after successful handshake
	if l.handshakeTimeout > 0 {
		if err := resultConn.SetReadDeadline(time.Time{}); err != nil {
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
