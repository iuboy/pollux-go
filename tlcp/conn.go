package tlcp

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/iuboy/pollux-go/internal/panicsafe"
	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// Conn represents a TLCP secure connection, implements net.Conn interface.
// Delegates to gotlcp.Conn internally for the TLCP protocol.
type Conn struct {
	inner    *gotlcp.Conn
	config   *Config
	rawConn  net.Conn
	isClient bool
	initErr  error // stores error from config conversion, deferred to Handshake
}

// Client returns a TLCP client connection.
// Follows the pattern of tls.Client(conn, config).
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: true}
	gc, err := configToGotlcp(config)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = gotlcp.Client(conn, gc)
	return c
}

// Server returns a TLCP server connection.
// Follows the pattern of tls.Server(conn, config).
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{config: config, rawConn: conn, isClient: false}
	gc, err := configToGotlcp(config)
	if err != nil {
		c.initErr = err
		return c
	}
	c.inner = gotlcp.Server(conn, gc)
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
// Converts gotlcp gmsm certificate types to stdlib certificate types.
func (c *Conn) ConnectionState() ConnectionState {
	if c.inner == nil {
		return ConnectionState{}
	}
	return convertConnectionState(c.inner.ConnectionState())
}

// NetConn returns the underlying connection.
func (c *Conn) NetConn() net.Conn {
	if c.inner != nil {
		return c.inner.NetConn()
	}
	return c.rawConn
}

// convertConnectionState converts gotlcp.ConnectionState to pollux ConnectionState.
//
// gotlcp aliases gmsm/smx509 as x509, so PeerCertificates/VerifiedChains are
// []*smx509.Certificate. pollux exposes stdlib *x509.Certificate, so each cert
// is converted via a DER round-trip (gmsm v0.44 removed the ToX509() bridge).
func convertConnectionState(cs gotlcp.ConnectionState) ConnectionState {
	result := ConnectionState{
		Version:           cs.Version,
		HandshakeComplete: cs.HandshakeComplete,
		CipherSuite:       cs.CipherSuite,
		ServerName:        cs.ServerName,
	}

	// Convert peer certificates: gmsm smx509.Certificate -> stdlib x509.Certificate.
	// Use pollux's ParseCertificate (field copy) — stdlib cannot parse SM2 DER.
	for _, cert := range cs.PeerCertificates {
		if stdCert, err := polluxsmx509.ParseCertificate(cert.Raw); err == nil {
			result.PeerCertificates = append(result.PeerCertificates, stdCert)
		}
	}

	// TLCP convention: PeerCertificates[0]=signing certificate, [1]=encryption certificate
	if len(result.PeerCertificates) > 0 {
		result.PeerSignCert = result.PeerCertificates[0]
	}
	if len(result.PeerCertificates) > 1 {
		result.PeerEncCert = result.PeerCertificates[1]
	}

	// Convert verification chains (gmsm smx509 -> stdlib via field copy).
	for _, chain := range cs.VerifiedChains {
		var stdChain []*x509.Certificate
		for _, cert := range chain {
			if stdCert, err := polluxsmx509.ParseCertificate(cert.Raw); err == nil {
				stdChain = append(stdChain, stdCert)
			}
		}
		result.VerifiedChains = append(result.VerifiedChains, stdChain)
	}

	return result
}
