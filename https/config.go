package https

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	polluxCert "github.com/iuboy/pollux-go/cert"
	polluxSm2 "github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/tlcp"
)

var (
	errMissingAddr = errors.New("pollux/https: addr is required")
	// Distinct sentinels per config path so a caller can tell from the error
	// message WHICH certificate is missing (TLCP needs a sign+enc pair; TLS
	// needs a standard cert chain). The previous single errMissingCertificate
	// was reused across all three paths and gave no diagnostic signal.
	errMissingTLCPCertificate = errors.New("pollux/https: TLCP sign and enc certificates are required")
	errMissingTLSCertificate  = errors.New("pollux/https: TLS certificate is required")
	errUnsupportedMode        = errors.New("pollux/https: unsupported or undetected crypto mode")
)

// defaultTLSCurvePreferences restricts the (key-exchange) curves negotiated by
// the standard-TLS path only (buildTLSConfig / buildTLSClientConfig →
// tls.Config.CurvePreferences). The GM paths (tlcp, tls13gm) do their own
// curve negotiation and are NOT governed by this list — they use SM2 per
// RFC 8998 regardless of CurvePreferences.
//
// An explicit CurvePreferences list REPLACES the standard library's default
// set, so this list must track the stdlib hardening baseline: since Go 1.24
// the default includes the X25519MLKEM768 post-quantum hybrid, and Go 1.26
// added SecP256r1MLKEM768 — pinning only the classic groups would silently
// opt this path out of quantum-resistant key exchange. The two hybrid groups
// pair with the classic groups offered below them as negotiation fallbacks.
// SecP384r1MLKEM1024 stays out because this list deliberately does not offer
// P-384. GODEBUG=tlssecpmlkem=0 disables SecP256r1MLKEM768 process-wide.
var defaultTLSCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
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

	// CipherSuites is shared between TLCP and TLS paths. In hybrid mode both
	// paths read it; callers running both protocols on one ServerOptions
	// should leave this empty so each path falls back to its own safe default
	// (tlcp.DefaultCipherSuites for TLCP, tls.Config defaults for TLS).
	CipherSuites []uint16
	ClientAuth   tlcp.ClientAuthType

	// TLS 客户端认证（标准 TLS 服务端）
	TLSClientAuth tls.ClientAuthType
	ClientCAs     *polluxCert.Pool

	// ReadTimeout, WriteTimeout, IdleTimeout control the server-side timeouts.
	// They use *time.Duration pointer semantics to distinguish three states:
	//
	//   - nil  → apply the package default (30s/30s/120s) — conservative
	//   - non-nil non-zero → the explicit duration
	//   - non-nil zero     → explicitly disable that timeout (NOT recommended
	//                        except behind a reverse proxy that enforces its
	//                        own timeouts; removes Slowloris protection)
	//
	// Use pollux/https.Duration(d) to take a pointer to a literal duration,
	// or NoTimeout() to explicitly opt out of a timeout.
	ReadTimeout  *time.Duration
	WriteTimeout *time.Duration
	IdleTimeout  *time.Duration
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
	if o.Mode != ModeUnset {
		return o.Mode
	}
	return DetectMode(o.SignCert)
}

// buildTLCPConfig converts options into a tlcp.Config.
func (o *ServerOptions) buildTLCPConfig() (*tlcp.Config, error) {
	if o.SignCert == nil || o.EncCert == nil {
		return nil, errMissingTLCPCertificate
	}
	cfg := &tlcp.Config{
		SignCertificate: o.SignCert,
		EncCertificate:  o.EncCert,
		CipherSuites:    o.CipherSuites,
		ClientAuth:      o.ClientAuth,
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
		Certificates:     o.Certificates,
		ClientAuth:       o.TLSClientAuth,
		CipherSuites:     o.CipherSuites,
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: defaultTLSCurvePreferences,
	}
	if o.RootCAs != nil {
		cfg.RootCAs = o.RootCAs.ToStandardPool()
	}
	if o.ClientCAs != nil {
		cfg.ClientCAs = o.ClientCAs.ToStandardPool()
	}
	if len(cfg.Certificates) == 0 {
		return nil, errMissingTLSCertificate
	}
	return cfg, nil
}

func loadSM2KeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	// Collect ALL CERTIFICATE PEM blocks so a chain (leaf + intermediates) is
	// preserved. Previously only the first block was decoded, dropping any
	// intermediate CA certs and breaking handshakes against peers that only
	// trust the issuing root.
	var chain [][]byte
	var leafDER []byte
	rest := certPEM
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		if leafDER == nil {
			leafDER = block.Bytes
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("pollux/https: failed to decode cert PEM")
	}
	polluxCert, err := polluxCert.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("pollux/https: failed to parse SM2 certificate: %w", err)
	}
	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	// Verify the private key matches the leaf certificate's public key.
	certPub, ok := polluxCert.PublicKey.(*polluxSm2.PublicKey)
	if !ok {
		return nil, errors.New("pollux/https: SM2 certificate public key type mismatch")
	}
	keyPub := &key.PublicKey
	// sm2.Equal compares curve identity (with parameter fallback) before the
	// coordinates, so a non-SM2 key can never pass by coordinate collision.
	if !polluxSm2.Equal(certPub, keyPub) {
		return nil, errors.New("pollux/https: private key does not match certificate's public key")
	}
	return &tls.Certificate{
		Certificate: chain,
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

	// Timeout controls the end-to-end client request timeout. Same pointer
	// semantics as ServerOptions.ReadTimeout:
	//
	//   - nil  → no client.Timeout (http.Client default: unlimited per-request)
	//   - non-nil non-zero → the explicit duration
	//   - non-nil zero     → explicitly no timeout
	Timeout      *time.Duration
	MaxRedirects int // Maximum number of HTTP redirects (default: 10). Set to -1 to disable redirect following.
}

// buildTLCPClientConfig builds a tlcp.Config for client use.
func (o *ClientOptions) buildTLCPClientConfig() (*tlcp.Config, error) {
	// Fail-closed: a TLCP client without any root CAs, client certificates,
	// or explicit InsecureSkipVerify would fall back to the system cert store
	// (non-deterministic across environments) — effectively unauthenticated
	// by accident. Require at least one trust anchor or explicit opt-in.
	// TLCP client auth uses SignCert/EncCert, not Certificates (which is TLS field).
	if o.SignRootCAs == nil && o.EncRootCAs == nil &&
		(o.SignCert == nil && o.EncCert == nil) && !o.InsecureSkipVerify {
		return nil, errors.New("pollux/https: at least one certificate, root pool, or InsecureSkipVerify is required")
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
		return nil, errors.New("pollux/https: at least one certificate, root pool, or TLSInsecureSkipVerify is required")
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
