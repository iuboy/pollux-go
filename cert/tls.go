package cert

import (
	"crypto/tls"
	"errors"
)

// TLSClientOptions holds parameters for building a standard TLS client config.
type TLSClientOptions struct {
	ServerName         string
	Roots              *Pool
	Certificates       []tls.Certificate
	NextProtos         []string
	InsecureSkipVerify bool
	MinVersion         uint16
}

// TLSProxyServerOptions holds parameters for building a standard TLS server config.
type TLSProxyServerOptions struct {
	Certificates []tls.Certificate
	ClientCAs    *Pool
	ClientAuth   tls.ClientAuthType
	NextProtos   []string
	MinVersion   uint16
}

// BuildClientTLSConfig builds a *tls.Config for a standard TLS client.
// If MinVersion is zero it defaults to TLS 1.2.
func BuildClientTLSConfig(opts TLSClientOptions) (*tls.Config, error) {
	if len(opts.Certificates) == 0 && opts.Roots == nil && !opts.InsecureSkipVerify {
		return nil, errors.New("cert: at least one certificate, root pool, or InsecureSkipVerify is required")
	}

	cfg := &tls.Config{
		ServerName:         opts.ServerName,
		Certificates:       copyCertificates(opts.Certificates),
		NextProtos:         copyStrings(opts.NextProtos),
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	if opts.MinVersion != 0 {
		cfg.MinVersion = opts.MinVersion
	} else {
		cfg.MinVersion = tls.VersionTLS12
	}
	if opts.Roots != nil {
		// ToStandardPool already adds every certificate by its raw DER.
		// Re-parsing the raw DER with the standard library would only duplicate
		// RSA/ECDSA roots and silently drop SM2 roots (stdlib rejects the SM2
		// curve), masking misconfiguration. Standard crypto/tls cannot validate
		// SM2 chains regardless; SM2 verification must go through the pollux
		// smx509 / tls13gm path, not a *tls.Config.
		cfg.RootCAs = opts.Roots.ToStandardPool()
	}
	return cfg, nil
}

// BuildServerTLSConfig builds a *tls.Config for a standard TLS server.
// If MinVersion is zero it defaults to TLS 1.2.
func BuildServerTLSConfig(opts TLSProxyServerOptions) (*tls.Config, error) {
	if len(opts.Certificates) == 0 {
		return nil, ErrNoCertificates
	}

	cfg := &tls.Config{
		Certificates: copyCertificates(opts.Certificates),
		NextProtos:   copyStrings(opts.NextProtos),
		ClientAuth:   opts.ClientAuth,
	}
	if opts.MinVersion != 0 {
		cfg.MinVersion = opts.MinVersion
	} else {
		cfg.MinVersion = tls.VersionTLS12
	}
	if opts.ClientCAs != nil {
		cfg.ClientCAs = opts.ClientCAs.ToStandardPool()
	}
	return cfg, nil
}

// copyCertificates returns a shallow copy of a []tls.Certificate slice: a new
// backing array is allocated (the returned config never aliases the caller's
// slice for append/re-slice purposes), but the tls.Certificate elements
// themselves are shared — the underlying DER and PrivateKey are NOT duplicated.
func copyCertificates(in []tls.Certificate) []tls.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]tls.Certificate, len(in))
	copy(out, in)
	return out
}

// copyStrings returns a shallow copy of a []string slice (new backing array;
// string elements are immutable and shared).
func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
