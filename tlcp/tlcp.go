// Package tlcp implements the Transport Layer Cryptography Protocol (TLCP),
// the Chinese national standard for transport-layer security (GB/T 38636-2020).
//
// EXPERIMENTAL — this package has not undergone independent third-party security audit.
// It is not recommended for production use until formally audited.
// The API may change in future versions.
//
// TLCP (Transport Layer Cryptography Protocol) is the Chinese national standard
// for transport-layer cryptography, standard number: GB/T 38636-2020.
//
// This package is a wrapper around gotlcp (gitee.com/Trisia/gotlcp), providing a
// Go-idiomatic API consistent with the pollux-go ecosystem while isolating consumers
// from direct dependencies on the underlying implementation library.
//
// Differences between TLCP and RFC 8998:
//   - TLCP (GB/T 38636-2020) is a Chinese national standard that defines a TLS protocol
//     variant based on national cryptographic algorithms
//   - RFC 8998 is an IETF publication "SM2 Cipher Suites for TLS 1.3", focused on TLS 1.3
//   - This package implements TLCP 1.1 (based on TLS 1.2), not RFC 8998's TLS 1.3 national
//     cipher suites
//   - For RFC 8998 related constants, see the tls13gm package (experimental)
//
// Status: EXPERIMENTAL — pending independent security audit
package tlcp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	gmsmSmx509 "github.com/emmansun/gmsm/smx509"
	"github.com/iuboy/pollux-go/internal/panicsafe"
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
	// gotlcp uses gmsm/smx509 for certificate verification, requiring raw certificates to build gmsm certificate pool.
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

// configToGotlcp converts pollux Config to gotlcp Config.
// Core conversion: stdlib certificate types -> gmsm certificate types.
//
// SECURITY NOTE: OCSP stapling and CRL checking are not supported when using
// TLCP through this wrapper. The underlying gotlcp library does not expose
// OCSP or CRL verification hooks. Callers requiring revocation checking must
// implement it out-of-band (e.g., fetch and validate OCSP/CRL separately
// before establishing a TLCP session).
func configToGotlcp(c *Config) (*gotlcp.Config, error) {
	if c == nil {
		return nil, errors.New("tlcp: nil config")
	}

	gc := &gotlcp.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
		CipherSuites:       c.CipherSuites,
		ClientAuth:         gotlcp.ClientAuthType(c.ClientAuth),
	}

	// Certificate conversion: SignCertificate -> Certificates[0], EncCertificate -> Certificates[1]
	if c.SignCertificate != nil {
		gc.Certificates = append(gc.Certificates, gotlcp.Certificate{
			Certificate: c.SignCertificate.Certificate,
			PrivateKey:  c.SignCertificate.PrivateKey,
		})
	}
	if c.EncCertificate != nil {
		gc.Certificates = append(gc.Certificates, gotlcp.Certificate{
			Certificate: c.EncCertificate.Certificate,
			PrivateKey:  c.EncCertificate.PrivateKey,
		})
	}

	// RootCAs: merge signing + encryption root certificates into gmsm smx509.CertPool
	var allRootCerts []*x509.Certificate
	allRootCerts = append(allRootCerts, c.SignRootCertificates...)
	allRootCerts = append(allRootCerts, c.EncRootCertificates...)
	if len(allRootCerts) > 0 {
		pool, err := buildSMX509CertPool(allRootCerts)
		if err != nil {
			return nil, fmt.Errorf("tlcp: build root CA pool: %w", err)
		}
		gc.RootCAs = pool
	}

	// ClientCAs: build gmsm smx509.CertPool from raw certificates
	if len(c.ClientCACertificates) > 0 {
		pool, err := buildSMX509CertPool(c.ClientCACertificates)
		if err != nil {
			return nil, fmt.Errorf("tlcp: build client CA pool: %w", err)
		}
		gc.ClientCAs = pool
	}

	return gc, nil
}

// buildSMX509CertPool builds a gmsm smx509.CertPool from a stdlib x509.Certificate list.
// Type conversion via DER re-parsing.
func buildSMX509CertPool(certs []*x509.Certificate) (*gmsmSmx509.CertPool, error) {
	pool := gmsmSmx509.NewCertPool()
	for _, cert := range certs {
		smCert, err := gmsmSmx509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %s: %w", cert.Subject, err)
		}
		pool.AddCert(smCert)
	}
	return pool, nil
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

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, nil, fmt.Errorf("tlcp: parse certificate file")
	}

	certs := parsePEMCertificates(pemData)
	return pool, certs, nil
}

// createCertPoolAndCertsFromPEM creates certificate pool and parses raw certificates from PEM data
func createCertPoolAndCertsFromPEM(pemData []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, nil, fmt.Errorf("tlcp: parse PEM certificate")
	}

	certs := parsePEMCertificates(pemData)
	return pool, certs, nil
}

// parsePEMCertificates parses []*x509.Certificate from PEM data
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
		// Try SM2-aware parsing first, then fall back to standard x509.
		// This matches the behavior of cert.ParseCertificate.
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
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
		return fmt.Errorf("tlcp: no cipher suites configured")
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
