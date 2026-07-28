package tls13

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var errNoCertificates = errors.New("tls13: at least one certificate is required")
var errClientCAsRequired = errors.New("tls13: ClientCAs is required when client certificate verification is enabled")

// ServerOptions holds TLS 1.3 server configuration parameters.
type ServerOptions struct {
	Certificates []tls.Certificate
	ClientCAs    *x509.CertPool
	ClientAuth   tls.ClientAuthType
	NextProtos   []string
}

// ClientOptions holds TLS 1.3 client configuration parameters.
type ClientOptions struct {
	ServerName         string
	RootCAs            *x509.CertPool
	Certificates       []tls.Certificate
	NextProtos         []string
	InsecureSkipVerify bool
}

// ServerConfig returns a *tls.Config enforcing TLS 1.3 for server use.
func ServerConfig(opts ServerOptions) (*tls.Config, error) {
	if len(opts.Certificates) == 0 {
		return nil, errNoCertificates
	}
	if (opts.ClientAuth == tls.VerifyClientCertIfGiven || opts.ClientAuth == tls.RequireAndVerifyClientCert) && opts.ClientCAs == nil {
		return nil, errClientCAsRequired
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: opts.Certificates,
		NextProtos:   opts.NextProtos,
		ClientAuth:   opts.ClientAuth,
	}
	if opts.ClientCAs != nil {
		cfg.ClientCAs = opts.ClientCAs
	}
	return cfg, nil
}

// ClientConfig returns a *tls.Config enforcing TLS 1.3 for client use.
func ClientConfig(opts ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         opts.ServerName,
		RootCAs:            opts.RootCAs,
		Certificates:       opts.Certificates,
		NextProtos:         opts.NextProtos,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	return cfg, nil
}
