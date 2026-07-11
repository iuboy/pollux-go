package tlcp

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/iuboy/pollux-go/internal/panicsafe"
	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
	polluxtls "github.com/iuboy/pollux-go/tls"
)

var (
	// ErrTLCPNotSupported TLCP not supported error
	ErrTLCPNotSupported = errors.New("tlcp: pure Go implementation not available")

	// ErrInvalidVersion invalid TLCP version
	ErrInvalidVersion = errors.New("tlcp: invalid version")

	// ErrMissingSignCertificate missing sign certificate
	ErrMissingSignCertificate = errors.New("tlcp: missing sign certificate")

	// ErrMissingEncCertificate missing encrypt certificate
	ErrMissingEncCertificate = errors.New("tlcp: missing encrypt certificate")

	// ErrInvalidCipherSuite invalid cipher suite
	ErrInvalidCipherSuite = errors.New("tlcp: invalid cipher suite")
)

// Version TLCP version
type Version string

const (
	// Version11 TLCP 1.1 (based on TLS 1.2)
	Version11 Version = "1.1"

	// Version12 TLCP 1.2 (based on TLS 1.3)
	Version12 Version = "1.2"
)

// String returns the string representation of the version
func (v Version) String() string {
	return string(v)
}

// ClientAuthType client authentication type
type ClientAuthType int

const (
	// NoClientCert no client certificate required
	NoClientCert ClientAuthType = iota

	// RequestClientCert request client certificate (optional)
	RequestClientCert

	// RequireAnyClientCert require client certificate (no verification)
	RequireAnyClientCert

	// VerifyClientCertIfGiven verify client certificate if provided
	VerifyClientCertIfGiven

	// RequireAndVerifyClientCert require and verify client certificate
	RequireAndVerifyClientCert
)

// Config TLCP configuration
type Config struct {
	// Version TLCP version (default: Version11)
	Version Version

	// Dual certificate configuration
	// SignCertificate signing certificate (for authentication and signing)
	SignCertificate *tls.Certificate

	// EncCertificate encryption certificate (for key exchange and encryption)
	EncCertificate *tls.Certificate

	// Dual CA configuration
	// SignRootCAs signing root CA certificate pool (stdlib)
	SignRootCAs *x509.CertPool

	// EncRootCAs encryption root CA certificate pool (stdlib)
	EncRootCAs *x509.CertPool

	// SignRootCertificates raw signing root certificate slice, for building gmsm certificate pool
	SignRootCertificates []*x509.Certificate

	// EncRootCertificates raw encryption root certificate slice, for building gmsm certificate pool
	EncRootCertificates []*x509.Certificate

	// CipherSuites TLCP Cipher Suites (default uses national cipher suites)
	CipherSuites []uint16

	// ServerName SNI
	ServerName string

	// ClientAuth client authentication policy
	ClientAuth ClientAuthType

	// ClientCACertificates CA certificates for verifying client certificates (server-side).
	ClientCACertificates []*x509.Certificate

	// InsecureSkipVerify skip certificate verification (for testing only)
	InsecureSkipVerify bool

	// MinVersion minimum TLS version
	MinVersion uint16

	// MaxVersion maximum TLS version
	MaxVersion uint16
}

// NewConfig creates default TLCP configuration
func NewConfig() *Config {
	return &Config{
		Version:            Version11,
		ClientAuth:         NoClientCert,
		CipherSuites:       defaultCipherSuites,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
}

// configToNative converts a public Config into the engine's tlcpEngineConfig.
func configToNative(c *Config, isClient bool) (*tlcpEngineConfig, error) {
	if c == nil {
		return nil, ErrTLCPNotSupported
	}
	// Default the version if unset (callers that construct Config{} directly,
	// like the http package, may leave Version empty). Use a local — do NOT
	// mutate the caller's Config, which may be shared across goroutines
	// (e.g. the same Config used for both Server and Client in a test).
	version := c.Version
	if version == "" {
		version = Version11
	}
	_ = version // version is validated by the engine; no mutation of c
	// Note: we intentionally do NOT call c.Validate() here — it requires leaf
	// certificates, but some callers (e.g. root-CA-only configs for testing)
	// legitimately build a Config without them. The engine surfaces a clear
	// error during the handshake if certs are missing.
	cipherSuites := c.CipherSuites
	if len(cipherSuites) == 0 {
		cipherSuites = DefaultCipherSuites()
	}
	nc := &tlcpEngineConfig{
		rand:               rand.Reader,
		cipherSuites:       cipherSuites,
		serverName:         c.ServerName,
		insecureSkipVerify: c.InsecureSkipVerify,
	}
	if c.SignCertificate != nil && c.EncCertificate != nil {
		certs, err := buildServerCerts(c.SignCertificate, c.EncCertificate)
		if err != nil {
			return nil, err
		}
		if isClient {
			nc.clientCerts = certs
		} else {
			nc.serverCerts = certs
		}
	}
	if !isClient && c.ClientAuth >= RequestClientCert {
		nc.requestClientCert = true
		// RequireAndVerifyClientCert needs client CA material to verify against;
		// refuse to start the handshake if none is configured (matches stdlib
		// crypto/tls behavior and prevents silently accepting any client cert).
		if c.ClientAuth >= VerifyClientCertIfGiven && len(c.ClientCACertificates) == 0 {
			return nil, errors.New("tlcp: RequireAndVerifyClientCert requires ClientCACertificates")
		}
	}
	for _, cert := range c.SignRootCertificates {
		nc.rootCAs = append(nc.rootCAs, cert.Raw)
	}
	for _, cert := range c.EncRootCertificates {
		nc.rootCAs = append(nc.rootCAs, cert.Raw)
	}
	return nc, nil
}

// buildServerCerts extracts engine cert material from a pair of tls.Certificate.
// Returns an error if a private key does not implement the required interface
// (crypto.Signer for the signing cert, crypto.Decrypter for the encryption cert),
// with the actual key type in the message for debuggability.
func buildServerCerts(sign, enc *tls.Certificate) (*tlcpServerCerts, error) {
	sc := &tlcpServerCerts{}
	if len(sign.Certificate) > 0 {
		sc.signCertDER = sign.Certificate[0]
	}
	s, ok := sign.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tlcp: signing cert private key %T does not implement crypto.Signer", sign.PrivateKey)
	}
	sc.signSigner = s
	if len(enc.Certificate) > 0 {
		sc.encCertDER = enc.Certificate[0]
	}
	d, ok := enc.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("tlcp: encryption cert private key %T does not implement crypto.Decrypter", enc.PrivateKey)
	}
	sc.encDecrypter = d
	if len(sign.Certificate) > 1 {
		sc.chainDER = append(sc.chainDER, sign.Certificate[1:]...)
	}
	return sc, nil
}

// LoadCertificates loads dual certificates from files
func (c *Config) LoadCertificates(signCertFile, signKeyFile, encCertFile, encKeyFile string) error {
	signCert, err := tls.LoadX509KeyPair(signCertFile, signKeyFile)
	if err != nil {
		return fmt.Errorf("tlcp: load sign certificate: %w", err)
	}

	encCert, err := tls.LoadX509KeyPair(encCertFile, encKeyFile)
	if err != nil {
		return fmt.Errorf("tlcp: load encrypt certificate: %w", err)
	}

	c.SignCertificate = &signCert
	c.EncCertificate = &encCert
	return nil
}

// LoadCertificatesFromPEM loads dual certificates from PEM data
func (c *Config) LoadCertificatesFromPEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) error {
	signCert, err := tls.X509KeyPair(signCertPEM, signKeyPEM)
	if err != nil {
		return fmt.Errorf("tlcp: load sign certificate: %w", err)
	}

	encCert, err := tls.X509KeyPair(encCertPEM, encKeyPEM)
	if err != nil {
		return fmt.Errorf("tlcp: load encrypt certificate: %w", err)
	}

	c.SignCertificate = &signCert
	c.EncCertificate = &encCert
	return nil
}

// LoadRootCAs loads dual CA root certificates from files
func (c *Config) LoadRootCAs(signRootFile, encRootFile string) error {
	signRoot, signCerts, err := createCertPoolAndCertsFromFile(signRootFile)
	if err != nil {
		return fmt.Errorf("tlcp: load sign CA: %w", err)
	}

	encRoot, encCerts, err := createCertPoolAndCertsFromFile(encRootFile)
	if err != nil {
		return fmt.Errorf("tlcp: load encrypt CA: %w", err)
	}

	c.SignRootCAs = signRoot
	c.EncRootCAs = encRoot
	c.SignRootCertificates = signCerts
	c.EncRootCertificates = encCerts
	return nil
}

// LoadRootCAsFromPEM loads dual CA root certificates from PEM data
func (c *Config) LoadRootCAsFromPEM(signRootPEM, encRootPEM []byte) error {
	signRoot, signCerts, err := createCertPoolAndCertsFromPEM(signRootPEM)
	if err != nil {
		return fmt.Errorf("tlcp: parse sign CA: %w", err)
	}

	encRoot, encCerts, err := createCertPoolAndCertsFromPEM(encRootPEM)
	if err != nil {
		return fmt.Errorf("tlcp: parse encrypt CA: %w", err)
	}

	c.SignRootCAs = signRoot
	c.EncRootCAs = encRoot
	c.SignRootCertificates = signCerts
	c.EncRootCertificates = encCerts
	return nil
}

// createCertPoolAndCertsFromFile creates certificate pool and parses raw certificates from file
func createCertPoolAndCertsFromFile(certFile string) (*x509.CertPool, []*x509.Certificate, error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("tlcp: read certificate file: %w", err)
	}
	return createCertPoolAndCertsFromPEM(pemData)
}

// createCertPoolAndCertsFromPEM creates certificate pool and parses raw certificates from PEM data.
// Pool is built via AddCert (not AppendCertsFromPEM) because the stdlib pool helper
// rejects SM2 certificates; the pool field is retained for API compatibility while
// actual SM2 verification uses the raw certificates via buildSMX509CertPool.
func createCertPoolAndCertsFromPEM(pemData []byte) (*x509.CertPool, []*x509.Certificate, error) {
	certs := parsePEMCertificates(pemData)
	if len(certs) == 0 {
		return nil, nil, errors.New("tlcp: parse certificate file")
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, certs, nil
}

// parsePEMCertificates parses []*x509.Certificate from PEM data.
// SM2-aware: gmsm smx509 parses SM2 curves that the stdlib crypto/x509 rejects
// ("unsupported elliptic curve"). DER is preserved via ToX509(), so downstream
// buildSMX509CertPool can re-parse from Raw. Falls back to stdlib for non-SM2.
func parsePEMCertificates(pemData []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := polluxsmx509.ParseCertificate(pemBlock.Bytes); err == nil {
			certs = append(certs, cert)
			continue
		}
		if cert, err := x509.ParseCertificate(pemBlock.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// Validate validates TLCP configuration
func (c *Config) Validate() error {
	if c.Version != Version11 {
		return fmt.Errorf("%w: %s (only Version11 supported)", ErrInvalidVersion, c.Version)
	}

	if c.SignCertificate == nil {
		return ErrMissingSignCertificate
	}

	if c.EncCertificate == nil {
		return ErrMissingEncCertificate
	}

	if len(c.CipherSuites) == 0 {
		return errors.New("tlcp: no cipher suites configured")
	}

	for _, suite := range c.CipherSuites {
		if !polluxtls.IsNationalCipherSuite(suite) {
			return fmt.Errorf("%w: cipher suite 0x%04X is not a national suite", ErrInvalidCipherSuite, suite)
		}
	}

	return nil
}

// deepCopyTLSCertificate creates a deep copy of a tls.Certificate,
// copying the Certificate [][]byte and SignedCertificateTimestamps fields
// to prevent shared mutable state between cloned configs.
func deepCopyTLSCertificate(cert *tls.Certificate) *tls.Certificate {
	if cert == nil {
		return nil
	}
	clone := &tls.Certificate{
		PrivateKey: cert.PrivateKey,
		Leaf:       cert.Leaf,
	}
	if len(cert.Certificate) > 0 {
		clone.Certificate = make([][]byte, len(cert.Certificate))
		for i, der := range cert.Certificate {
			clone.Certificate[i] = make([]byte, len(der))
			copy(clone.Certificate[i], der)
		}
	}
	if len(cert.SignedCertificateTimestamps) > 0 {
		clone.SignedCertificateTimestamps = make([][]byte, len(cert.SignedCertificateTimestamps))
		for i, sct := range cert.SignedCertificateTimestamps {
			clone.SignedCertificateTimestamps[i] = make([]byte, len(sct))
			copy(clone.SignedCertificateTimestamps[i], sct)
		}
	}
	if len(cert.OCSPStaple) > 0 {
		clone.OCSPStaple = make([]byte, len(cert.OCSPStaple))
		copy(clone.OCSPStaple, cert.OCSPStaple)
	}
	return clone
}

// Clone clones TLCP configuration
func (c *Config) Clone() *Config {
	clone := &Config{
		Version:            c.Version,
		ServerName:         c.ServerName,
		ClientAuth:         c.ClientAuth,
		InsecureSkipVerify: c.InsecureSkipVerify,
		MinVersion:         c.MinVersion,
		MaxVersion:         c.MaxVersion,
	}

	if c.SignCertificate != nil {
		clone.SignCertificate = deepCopyTLSCertificate(c.SignCertificate)
	}
	if c.EncCertificate != nil {
		clone.EncCertificate = deepCopyTLSCertificate(c.EncCertificate)
	}

	if len(c.CipherSuites) > 0 {
		clone.CipherSuites = make([]uint16, len(c.CipherSuites))
		copy(clone.CipherSuites, c.CipherSuites)
	}

	if c.SignRootCAs != nil {
		clone.SignRootCAs = c.SignRootCAs
	}
	if c.EncRootCAs != nil {
		clone.EncRootCAs = c.EncRootCAs
	}
	if len(c.SignRootCertificates) > 0 {
		clone.SignRootCertificates = make([]*x509.Certificate, len(c.SignRootCertificates))
		copy(clone.SignRootCertificates, c.SignRootCertificates)
	}
	if len(c.EncRootCertificates) > 0 {
		clone.EncRootCertificates = make([]*x509.Certificate, len(c.EncRootCertificates))
		copy(clone.EncRootCertificates, c.EncRootCertificates)
	}
	if len(c.ClientCACertificates) > 0 {
		clone.ClientCACertificates = make([]*x509.Certificate, len(c.ClientCACertificates))
		copy(clone.ClientCACertificates, c.ClientCACertificates)
	}

	return clone
}

// String returns string representation of TLCP configuration
func (c *Config) String() string {
	return fmt.Sprintf("TLCPConfig{Version=%s, ServerName=%s, CipherSuites=%d}",
		c.Version, c.ServerName, len(c.CipherSuites))
}

// VersionFromString parses TLCP version from string
func VersionFromString(version string) (Version, error) {
	switch version {
	case "1.1", "11":
		return Version11, nil
	case "1.2", "12":
		return Version12, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidVersion, version)
	}
}

// IsAvailable checks if TLCP is available
func IsAvailable() bool {
	return true
}

// GetCipherSuites returns the default TLCP Cipher Suites (GCM-only)
func GetCipherSuites() []uint16 {
	return DefaultCipherSuites()
}

// AllCipherSuites returns the full TLCP Cipher Suites list (including CBC)
func AllCipherSuites() []uint16 {
	return LegacyCipherSuites()
}

// IsCipherSuite checks if it is a TLCP Cipher Suite
func IsCipherSuite(suite uint16) bool {
	return polluxtls.IsNationalCipherSuite(suite)
}

// GetCipherSuiteName returns the TLCP Cipher Suite name
func GetCipherSuiteName(suite uint16) string {
	return polluxtls.CipherSuiteName(suite)
}

// ConnectionState records TLCP connection security parameters
type ConnectionState struct {
	Version           uint16
	HandshakeComplete bool
	CipherSuite       uint16
	ServerName        string
	PeerCertificates  []*x509.Certificate
	VerifiedChains    [][]*x509.Certificate
	PeerSignCert      *x509.Certificate
	PeerEncCert       *x509.Certificate
}

// Listener TLCP listener
type Listener struct {
	net.Listener
	config *Config
}

// NewListener creates TLCP listener (similar to tls.NewListener)
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &Listener{Listener: inner, config: config}
}

// Accept accepts TLCP connections
func (l *Listener) Accept() (net.Conn, error) {
	return panicsafe.Do1(func() (net.Conn, error) {
		return l.accept()
	})
}

func (l *Listener) accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tlcpConn := Server(conn, l.config)
	if err := tlcpConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlcpConn, nil
}

// Listen creates TLCP listener (similar to tls.Listen)
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln, config), nil
}

// Dial establishes TLCP client connection (similar to tls.Dial)
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(nil, network, addr, config)
}

// DialWithDialer establishes TLCP connection with custom dialer (similar to tls.DialWithDialer)
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return panicsafe.Do1(func() (*Conn, error) {
		return dialWithDialer(dialer, network, addr, config)
	})
}

func dialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	var conn net.Conn
	var err error
	if dialer != nil {
		conn, err = dialer.Dial(network, addr)
	} else {
		conn, err = net.Dial(network, addr)
	}
	if err != nil {
		return nil, err
	}

	tlcpConn := Client(conn, config)
	if err := tlcpConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlcpConn, nil
}

// BuildClientConfig builds TLS client configuration
func (c *Config) BuildClientConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         c.ServerName,
		CipherSuites:       c.CipherSuites,
		InsecureSkipVerify: c.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}

	if c.SignCertificate != nil {
		cfg.Certificates = []tls.Certificate{*c.SignCertificate}
	} else if c.EncCertificate != nil {
		cfg.Certificates = []tls.Certificate{*c.EncCertificate}
	}

	if c.SignRootCAs != nil {
		cfg.RootCAs = c.SignRootCAs
	}

	return cfg, nil
}

// BuildServerConfig builds TLS server configuration
func (c *Config) BuildServerConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		CipherSuites:       c.CipherSuites,
		InsecureSkipVerify: c.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}

	var certs []tls.Certificate
	if c.SignCertificate != nil {
		certs = append(certs, *c.SignCertificate)
	}
	if c.EncCertificate != nil {
		certs = append(certs, *c.EncCertificate)
	}
	if len(certs) > 0 {
		cfg.Certificates = certs
	}

	switch c.ClientAuth {
	case NoClientCert:
		cfg.ClientAuth = tls.NoClientCert
	case RequestClientCert:
		cfg.ClientAuth = tls.RequestClientCert
	case RequireAnyClientCert:
		cfg.ClientAuth = tls.RequireAnyClientCert
	case VerifyClientCertIfGiven:
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	case RequireAndVerifyClientCert:
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// Enable enables TLCP Cipher Suites on existing TLS configuration
func Enable(tlsCfg *tls.Config) error {
	nationalSuites := polluxtls.NationalCipherSuites()
	if len(nationalSuites) == 0 {
		return ErrTLCPNotSupported
	}
	tlsCfg.CipherSuites = append(tlsCfg.CipherSuites, nationalSuites...)
	return nil
}

// Disable disables TLCP Cipher Suites on TLS configuration
func Disable(tlsCfg *tls.Config) {
	filtered := make([]uint16, 0, len(tlsCfg.CipherSuites))
	for _, suite := range tlsCfg.CipherSuites {
		if !polluxtls.IsNationalCipherSuite(suite) {
			filtered = append(filtered, suite)
		}
	}
	tlsCfg.CipherSuites = filtered
}

// GetStandardSummary returns a human-readable summary of the TLCP standard.
func GetStandardSummary() string {
	return `
TLCP (Transport Layer Cryptography Protocol) Standard Summary

Primary Standards:
- GB/T 38636-2020: Information security technology — Transport Layer Cryptography Protocol (TLCP)
- RFC 8998: TLS 1.3 with SM2/SM3/SM4

TLCP 1.1 (based on TLS 1.2):
- Dual certificate mechanism: signing certificate + encryption certificate
- Key exchange: ECDHE_SM2 / ECC_SM2
- Symmetric encryption: SM4_GCM / SM4_CBC
- Message digest: SM3

Primary Cipher Suites:
- ECDHE_SM2_WITH_SM4_GCM_SM3 (0xE051)
- ECDHE_SM2_WITH_SM4_CBC_SM3 (0xE011)
- ECC_SM2_WITH_SM4_GCM_SM3 (0xE053)
- ECC_SM2_WITH_SM4_CBC_SM3 (0xE013)
`
}
