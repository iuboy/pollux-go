package cert

import (
	"crypto/tls"
	"errors"

	polluxTLCP "github.com/iuboy/pollux-go/tlcp"
)

// TLCPProxyOptions holds parameters for building a TLCP config.
type TLCPProxyOptions struct {
	Certificates *DualCertificate
	SignRoots    *Pool
	EncRoots     *Pool
	CipherSuites []uint16
	ServerName   string
	ClientAuth   polluxTLCP.ClientAuthType
	ClientCAs    *Pool
	MinVersion   uint16
}

// BuildTLCPConfig builds a *tlcp.Config for TLCP (Transport Layer Cryptography Protocol).
func BuildTLCPConfig(opts TLCPProxyOptions) (*polluxTLCP.Config, error) {
	if opts.Certificates == nil {
		return nil, errors.New("cert: dual certificate is required for TLCP")
	}
	// Validate the dual certificate pair's internal fields before handing them
	// to tlcp.Config — zero-value tls.Certificate fields would surface as opaque
	// handshake failures deep in the TLCP engine.
	if len(opts.Certificates.Sign.Certificate) == 0 || opts.Certificates.Sign.PrivateKey == nil {
		return nil, errors.New("cert: TLCP sign certificate is missing cert chain or private key")
	}
	if len(opts.Certificates.Enc.Certificate) == 0 || opts.Certificates.Enc.PrivateKey == nil {
		return nil, errors.New("cert: TLCP encrypt certificate is missing cert chain or private key")
	}

	cfg := &polluxTLCP.Config{
		CipherSuites: opts.CipherSuites,
		ServerName:   opts.ServerName,
		ClientAuth:   opts.ClientAuth,
	}

	if opts.MinVersion != 0 {
		cfg.MinVersion = opts.MinVersion
	}

	cfg.SignCertificate = &opts.Certificates.Sign
	cfg.EncCertificate = &opts.Certificates.Enc

	if opts.SignRoots != nil {
		cfg.SignRootCAs = opts.SignRoots.ToStandardPool()
		cfg.SignRootCertificates = opts.SignRoots.Certificates()
	}

	if opts.EncRoots != nil {
		cfg.EncRootCAs = opts.EncRoots.ToStandardPool()
		cfg.EncRootCertificates = opts.EncRoots.Certificates()
	}

	if opts.ClientCAs != nil {
		cfg.ClientCACertificates = opts.ClientCAs.Certificates()
	}

	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = polluxTLCP.DefaultCipherSuites()
	}

	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}

	return cfg, nil
}
