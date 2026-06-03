package quic

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	tls13 "github.com/ycq/pollux/tls13"
)

var (
	errEmptyALPN    = errors.New("quic: at least one NextProto (ALPN) is required")
	errNoServerName = errors.New("quic: ServerName is required when not skipping verify")
)

const defaultIdleTimeout = 30 * time.Second

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
