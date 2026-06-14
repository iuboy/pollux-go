package quicgm

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
)

const defaultIdleTimeout = 30 * time.Second

var (
	errNoServerCert = errors.New("quicgm: server Certificate and PrivateKey are required")
	errNoServerName = errors.New("quicgm: ServerName is required when not skipping verify")
)

// ServerConfig holds QUIC server configuration for the RFC 8998 GM stack
// (Route C). The server certificate must be an SM2 certificate; its private key
// signs CertificateVerify.
type ServerConfig struct {
	Addr               string
	Certificate        *x509.Certificate
	PrivateKey         *sm2.PrivateKey
	ClientCAs          *smx509.CertPool
	MaxIdleTimeout     time.Duration
	MaxIncomingStreams int64
}

// ClientConfig holds QUIC client configuration for the RFC 8998 GM stack.
type ClientConfig struct {
	Addr               string
	ServerName         string
	Roots              *smx509.CertPool
	InsecureSkipVerify bool
	MaxIdleTimeout     time.Duration
}

func (c *ServerConfig) idleTimeout() time.Duration {
	if c.MaxIdleTimeout > 0 {
		return c.MaxIdleTimeout
	}
	return defaultIdleTimeout
}

func (c *ClientConfig) idleTimeout() time.Duration {
	if c.MaxIdleTimeout > 0 {
		return c.MaxIdleTimeout
	}
	return defaultIdleTimeout
}

// tls13ServerConfig builds the tls13gm server handshaker config. DCID and
// TransportParameters are filled by the QUIC transport (GMCryptoSetup), not here.
func (c *ServerConfig) tls13ServerConfig() *tls13gm.ServerConfig {
	return &tls13gm.ServerConfig{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
	}
}

// tls13ClientConfig builds the tls13gm client handshaker config.
func (c *ClientConfig) tls13ClientConfig() (*tls13gm.ClientConfig, error) {
	if c.ServerName == "" && !c.InsecureSkipVerify {
		return nil, errNoServerName
	}
	return &tls13gm.ClientConfig{
		ServerName:         c.ServerName,
		Roots:              c.Roots,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}, nil
}
