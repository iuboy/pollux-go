package http

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"time"

	polluxCert "github.com/iuboy/pollux-go/cert"
	polluxSm2 "github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/tlcp"
)

var (
	errMissingAddr        = errors.New("pollux/http: addr is required")
	errMissingCertificate = errors.New("pollux/http: certificate is required")
)

// defaultTLSCurvePreferences restricts the (key-exchange) curves negotiated by
// the standard-TLS path only (buildTLSConfig / buildTLSClientConfig →
// tls.Config.CurvePreferences). The GM paths (tlcp, tls13gm) do their own
// curve negotiation and are NOT governed by this list — they use SM2 per
// RFC 8998 regardless of CurvePreferences.
var defaultTLSCurvePreferences = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}

// ServerOptions configures an HTTP server for TLS or TLCP.
type ServerOptions struct {
	// Mode selects the protocol. If zero, auto-detected from certificates.
	Mode Mode

	// Addr is the listen address (e.g. ":443").
	Addr string

	// Handler is the HTTP handler. If nil, http.DefaultServeMux is used.
	Handler http.Handler

	// --- 国密双证书（ModeTLCP / ModeHybrid）---

	SignCert *tls.Certificate // 签名证书
	EncCert  *tls.Certificate // 加密证书

	SignRootCAs *polluxCert.Pool // 签名根 CA
	EncRootCAs  *polluxCert.Pool // 加密根 CA

	// --- 国际证书（ModeTLS / ModeHybrid）---

	Certificates []tls.Certificate // 标准 TLS 证书链
	RootCAs      *polluxCert.Pool

	// --- 通用 ---

	CipherSuites       []uint16
	ClientAuth         tlcp.ClientAuthType
	InsecureSkipVerify bool

	// TLS 客户端认证（标准 TLS 服务端）
	TLSClientAuth tls.ClientAuthType
	ClientCAs     *polluxCert.Pool

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// LoadTLCPCertificates loads a TLCP dual certificate pair from files.
func (o *ServerOptions) LoadTLCPCertificates(signCertFile, signKeyFile, encCertFile, encKeyFile string) error {
	signCert, err := loadSM2KeyPairFromFile(signCertFile, signKeyFile)
	if err != nil {
		return err
	}
	encCert, err := loadSM2KeyPairFromFile(encCertFile, encKeyFile)
	if err != nil {
		return err
	}
	o.SignCert = signCert
	o.EncCert = encCert
	return nil
}

// LoadTLCPCertificatesFromPEM loads a TLCP dual certificate pair from PEM bytes.
func (o *ServerOptions) LoadTLCPCertificatesFromPEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) error {
	signCert, err := loadSM2KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return err
	}
	encCert, err := loadSM2KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return err
	}
	o.SignCert = signCert
	o.EncCert = encCert
	return nil
}

// LoadTLSCertificate loads a standard TLS certificate from files.
func (o *ServerOptions) LoadTLSCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	o.Certificates = []tls.Certificate{cert}
	return nil
}

// DetectMode returns the effective mode, auto-detecting if needed.
func (o *ServerOptions) DetectMode() Mode {
	if o.Mode != 0 {
		return o.Mode
	}
	return DetectMode(o.SignCert)
}

// buildTLCPConfig converts options into a tlcp.Config.
func (o *ServerOptions) buildTLCPConfig() (*tlcp.Config, error) {
	if o.SignCert == nil || o.EncCert == nil {
		return nil, errMissingCertificate
	}
	cfg := &tlcp.Config{
		SignCertificate:    o.SignCert,
		EncCertificate:     o.EncCert,
		CipherSuites:       o.CipherSuites,
		ClientAuth:         o.ClientAuth,
		InsecureSkipVerify: o.InsecureSkipVerify,
	}
	if o.SignRootCAs != nil {
		cfg.SignRootCAs = o.SignRootCAs.ToStandardPool()
		cfg.SignRootCertificates = o.SignRootCAs.Certificates()
	}
	if o.EncRootCAs != nil {
		cfg.EncRootCAs = o.EncRootCAs.ToStandardPool()
		cfg.EncRootCertificates = o.EncRootCAs.Certificates()
	}
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = tlcp.DefaultCipherSuites()
	}
	return cfg, nil
}

// buildTLSConfig converts options into a tls.Config.
func (o *ServerOptions) buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		Certificates:       o.Certificates,
		ClientAuth:         o.TLSClientAuth,
		CipherSuites:       o.CipherSuites,
		InsecureSkipVerify: o.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   defaultTLSCurvePreferences,
	}
	if o.RootCAs != nil {
		cfg.RootCAs = o.RootCAs.ToStandardPool()
	}
	if o.ClientCAs != nil {
		cfg.ClientCAs = o.ClientCAs.ToStandardPool()
	}
	if len(cfg.Certificates) == 0 {
		return nil, errMissingCertificate
	}
	return cfg, nil
}

func loadSM2KeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("pollux/http: failed to decode cert PEM")
	}
	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  key,
	}, nil
}

func loadSM2KeyPairFromFile(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return loadSM2KeyPair(certPEM, keyPEM)
}

// ClientOptions configures an HTTP client transport.
type ClientOptions struct {
	Mode Mode

	// TLCP client config.
	SignCert           *tls.Certificate
	EncCert            *tls.Certificate
	SignRootCAs        *polluxCert.Pool
	EncRootCAs         *polluxCert.Pool
	ServerName         string
	CipherSuites       []uint16
	InsecureSkipVerify bool

	// TLS client config.
	Certificates          []tls.Certificate
	RootCAs               *polluxCert.Pool
	TLSServerName         string
	TLSCipherSuites       []uint16
	TLSInsecureSkipVerify bool

	Timeout      time.Duration
	MaxRedirects int // Maximum number of HTTP redirects (default: 10). Set to -1 to disable redirect following.
}

// buildTLCPClientConfig builds a tlcp.Config for client use.
func (o *ClientOptions) buildTLCPClientConfig() (*tlcp.Config, error) {
	// Fail-closed: a TLCP client without any root CAs, client certificates,
	// or explicit InsecureSkipVerify would fall back to the system cert store
	// (non-deterministic across environments) — effectively unauthenticated
	// by accident. Require at least one trust anchor or explicit opt-in.
	if o.SignRootCAs == nil && o.EncRootCAs == nil && len(o.Certificates) == 0 && !o.InsecureSkipVerify {
		return nil, errors.New("pollux/http: at least one certificate, root pool, or InsecureSkipVerify is required")
	}
	cfg := &tlcp.Config{
		SignCertificate:    o.SignCert,
		EncCertificate:     o.EncCert,
		ServerName:         o.ServerName,
		CipherSuites:       o.CipherSuites,
		InsecureSkipVerify: o.InsecureSkipVerify,
	}
	if o.SignRootCAs != nil {
		cfg.SignRootCAs = o.SignRootCAs.ToStandardPool()
		cfg.SignRootCertificates = o.SignRootCAs.Certificates()
	}
	if o.EncRootCAs != nil {
		cfg.EncRootCAs = o.EncRootCAs.ToStandardPool()
		cfg.EncRootCertificates = o.EncRootCAs.Certificates()
	}
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = tlcp.DefaultCipherSuites()
	}
	return cfg, nil
}

// buildTLSClientConfig builds a tls.Config for client use.
//
// Fail-closed: a client MUST configure server authentication — either a root
// pool, a client certificate chain, or an explicit InsecureSkipVerify opt-in.
// Without it, the returned config would carry InsecureSkipVerify=false but
// RootCAs=nil, leaving verification to fall back to the host's system cert
// store (non-deterministic across environments, silently skipped in some
// dial paths). This mirrors cert.BuildClientTLSConfig's gate and makes
// "unauthenticated by accident" a build-time error instead of a runtime
// behavior.
func (o *ClientOptions) buildTLSClientConfig() (*tls.Config, error) {
	if len(o.Certificates) == 0 && o.RootCAs == nil && !o.TLSInsecureSkipVerify {
		return nil, errors.New("pollux/http: at least one certificate, root pool, or TLSInsecureSkipVerify is required")
	}

	cfg := &tls.Config{
		Certificates:       o.Certificates,
		ServerName:         o.TLSServerName,
		CipherSuites:       o.TLSCipherSuites,
		InsecureSkipVerify: o.TLSInsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   defaultTLSCurvePreferences,
	}
	if o.RootCAs != nil {
		cfg.RootCAs = o.RootCAs.ToStandardPool()
	}
	return cfg, nil
}
