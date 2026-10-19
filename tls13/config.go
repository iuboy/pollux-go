package tls13

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

var errNoCertificates = errors.New("tls13: at least one certificate is required")
var errClientCAsRequired = errors.New("tls13: ClientCAs is required when client certificate verification is enabled")
var errInvalidCipherSuite = errors.New("tls13: cipher suite is not a TLS 1.3 suite")

// tls13CipherSuites is the allowlist for the optional CipherSuites override:
// with MinVersion=MaxVersion=TLS 1.3 only these three suites are negotiable,
// so an explicit list containing anything else (e.g. a TLS 1.2 suite ID)
// silently yields an EMPTY preference set — rejected here instead.
var tls13CipherSuites = map[uint16]bool{
	tls.TLS_AES_128_GCM_SHA256:       true,
	tls.TLS_AES_256_GCM_SHA384:       true,
	tls.TLS_CHACHA20_POLY1305_SHA256: true,
}

// validateCipherSuites returns nil for an empty list (stdlib defaults apply).
func validateCipherSuites(ids []uint16) error {
	for _, id := range ids {
		if !tls13CipherSuites[id] {
			return fmt.Errorf("%w: %#04x", errInvalidCipherSuite, id)
		}
	}
	return nil
}

// ServerOptions holds TLS 1.3 server configuration parameters.
type ServerOptions struct {
	Certificates []tls.Certificate
	ClientCAs    *x509.CertPool
	ClientAuth   tls.ClientAuthType
	NextProtos   []string
	// CipherSuites optionally restricts the TLS 1.3 suite preference (all
	// three are AEAD; empty = stdlib default order). Non-TLS-1.3 suite IDs
	// are rejected — they would silently empty the preference set.
	CipherSuites []uint16
}

// ClientOptions holds TLS 1.3 client configuration parameters.
//
// Trust model: when RootCAs is nil and InsecureSkipVerify is false, the
// returned config verifies against the SYSTEM root store — the standard
// crypto/tls semantics this thin builder intentionally mirrors (the quic
// wrapper relies on it for public-CA servers). Deployments that must not
// trust public CAs (GM/internal) should set RootCAs explicitly, or use the
// https package, whose client gate rejects the system-root fallback.
type ClientOptions struct {
	ServerName         string
	RootCAs            *x509.CertPool
	Certificates       []tls.Certificate
	NextProtos         []string
	InsecureSkipVerify bool
	// CipherSuites optionally restricts the TLS 1.3 suite preference
	// (see ServerOptions.CipherSuites).
	CipherSuites []uint16
}

// ServerConfig returns a *tls.Config enforcing TLS 1.3 for server use.
// Both MinVersion and MaxVersion are pinned to TLS 1.3 so the config
// rejects both downgrade attempts (MinVersion floor) and future-version
// negotiation (MaxVersion ceiling) — the function name's "TLS 1.3"
// contract is enforced regardless of caller configuration.
func ServerConfig(opts ServerOptions) (*tls.Config, error) {
	if len(opts.Certificates) == 0 {
		return nil, errNoCertificates
	}
	if (opts.ClientAuth == tls.VerifyClientCertIfGiven || opts.ClientAuth == tls.RequireAndVerifyClientCert) && opts.ClientCAs == nil {
		return nil, errClientCAsRequired
	}
	if err := validateCipherSuites(opts.CipherSuites); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: opts.Certificates,
		NextProtos:   opts.NextProtos,
		ClientAuth:   opts.ClientAuth,
		CipherSuites: opts.CipherSuites,
	}
	if opts.ClientCAs != nil {
		cfg.ClientCAs = opts.ClientCAs
	}
	return cfg, nil
}

// ClientConfig returns a *tls.Config enforcing TLS 1.3 for client use.
// Both MinVersion and MaxVersion are pinned to TLS 1.3 — see ServerConfig
// for the rationale.
func ClientConfig(opts ClientOptions) (*tls.Config, error) {
	if err := validateCipherSuites(opts.CipherSuites); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         opts.ServerName,
		RootCAs:            opts.RootCAs,
		Certificates:       opts.Certificates,
		NextProtos:         opts.NextProtos,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		CipherSuites:       opts.CipherSuites,
	}
	return cfg, nil
}
