package quic

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	tls13 "github.com/iuboy/pollux-go/tls13"
)

var (
	errEmptyALPN    = errors.New("quic: at least one NextProto (ALPN) is required")
	errNoServerName = errors.New("quic: ServerName is required when not skipping verify")
)

const defaultIdleTimeout = 30 * time.Second

// resolveIdleTimeout returns the effective idle timeout for a QUIC config,
// shared by ServerConfig.idleTimeout and ClientConfig.idleTimeout. A zero or
// negative MaxIdleTimeout falls back to defaultIdleTimeout — the negative case
// is treated as "unset" (Go's time.Duration is int64, so a negative value
// almost always indicates an arithmetic overflow or default-zero arithmetic
// mistake rather than a deliberate "no timeout" intent, which QUIC does not
// support anyway).
func resolveIdleTimeout(max time.Duration) time.Duration {
	if max <= 0 {
		return defaultIdleTimeout
	}
	return max
}

// ServerConfig holds QUIC server configuration.
type ServerConfig struct {
	Addr               string
	Certificates       []tls.Certificate
	ClientCAs          *x509.CertPool
	ClientAuth         tls.ClientAuthType
	NextProtos         []string
	MaxIdleTimeout     time.Duration
	MaxIncomingStreams int64
}

// ClientConfig holds QUIC client configuration.
type ClientConfig struct {
	Addr               string
	ServerName         string
	RootCAs            *x509.CertPool
	Certificates       []tls.Certificate
	NextProtos         []string
	InsecureSkipVerify bool
	MaxIdleTimeout     time.Duration
}

func (c *ServerConfig) tlsConfig() (*tls.Config, error) {
	if len(c.NextProtos) == 0 {
		return nil, errEmptyALPN
	}
	return tls13.ServerConfig(tls13.ServerOptions{
		Certificates: c.Certificates,
		ClientCAs:    c.ClientCAs,
		ClientAuth:   c.ClientAuth,
		NextProtos:   c.NextProtos,
	})
}

func (c *ClientConfig) tlsConfig() (*tls.Config, error) {
	if len(c.NextProtos) == 0 {
		return nil, errEmptyALPN
	}
	if c.ServerName == "" && !c.InsecureSkipVerify {
		return nil, errNoServerName
	}
	return tls13.ClientConfig(tls13.ClientOptions{
		ServerName:         c.ServerName,
		RootCAs:            c.RootCAs,
		Certificates:       c.Certificates,
		NextProtos:         c.NextProtos,
		InsecureSkipVerify: c.InsecureSkipVerify,
	})
}

func (c *ServerConfig) idleTimeout() time.Duration {
	return resolveIdleTimeout(c.MaxIdleTimeout)
}

func (c *ClientConfig) idleTimeout() time.Duration {
	return resolveIdleTimeout(c.MaxIdleTimeout)
}
