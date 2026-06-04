// Package tlcp 提供国密 TLCP 协议支持
//
// EXPERIMENTAL — 此包尚未经过独立第三方安全审计。
// 在经过正式安全审计之前，不建议用于生产环境。
// API 可能在未来版本中发生破坏性变更。
//
// TLCP (Transport Layer Cryptography Protocol) 是中国国家标准的传输层密码协议，
// 标准编号：GB/T 38636-2020。
//
// 本包是 gotlcp (gitee.com/Trisia/gotlcp) 的封装层，提供与 pollux-go 生态一致的
// Go 惯用 API，同时隔离消费者对底层实现库的直接依赖。
//
// TLCP 与 RFC 8998 的区别：
//   - TLCP (GB/T 38636-2020) 是中国国家标准，定义了基于国密算法的 TLS 协议变体
//   - RFC 8998 是 IETF 发布的 "SM2 Cipher Suites for TLS 1.3"，专注于 TLS 1.3
//   - 本包实现的是 TLCP 1.1（基于 TLS 1.2），不实现 RFC 8998 的 TLS 1.3 国密套件
//   - 如需 RFC 8998 相关常量，请参阅 tls13gm 包（experimental）
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
	"github.com/ycq/pollux/internal/panicsafe"
	polluxtls "github.com/ycq/pollux/tls"
)

var (
	// ErrTLCPNotSupported TLCP 不支持错误
	ErrTLCPNotSupported = errors.New("tlcp: pure Go implementation not available")

	// ErrInvalidVersion 无效的 TLCP 版本
	ErrInvalidVersion = errors.New("tlcp: invalid version")

	// ErrMissingSignCertificate 缺少签名证书
	ErrMissingSignCertificate = errors.New("tlcp: missing sign certificate")

	// ErrMissingEncCertificate 缺少加密证书
	ErrMissingEncCertificate = errors.New("tlcp: missing encrypt certificate")

	// ErrInvalidCipherSuite 无效的 Cipher Suite
	ErrInvalidCipherSuite = errors.New("tlcp: invalid cipher suite")

	// ErrNotImplemented 功能未实现
	ErrNotImplemented = errors.New("tlcp: not implemented")
)

// Version TLCP 版本
type Version string

const (
	// Version11 TLCP 1.1 (基于 TLS 1.2)
	Version11 Version = "1.1"

	// Version12 TLCP 1.2 (基于 TLS 1.3)
	Version12 Version = "1.2"
)

// String 返回版本的字符串表示
func (v Version) String() string {
	return string(v)
}

// ClientAuthType 客户端认证类型
type ClientAuthType int

const (
	// NoClientCert 不需要客户端证书
	NoClientCert ClientAuthType = iota

	// RequestClientCert 请求客户端证书（可选）
	RequestClientCert

	// RequireAnyClientCert 要求客户端证书（不验证）
	RequireAnyClientCert

	// VerifyClientCertIfGiven 如果提供客户端证书则验证
	VerifyClientCertIfGiven

	// RequireAndVerifyClientCert 要求并验证客户端证书
	RequireAndVerifyClientCert
)

// Config TLCP 配置
type Config struct {
	// Version TLCP 版本（默认 Version11）
	Version Version

	// 双证书配置
	// SignCertificate 签名证书（用于身份认证和签名）
	SignCertificate *tls.Certificate

	// EncCertificate 加密证书（用于密钥交换和加密）
	EncCertificate *tls.Certificate

	// 双 CA 配置
	// SignRootCAs 签名根 CA 证书池（stdlib）
	SignRootCAs *x509.CertPool

	// EncRootCAs 加密根 CA 证书池（stdlib）
	EncRootCAs *x509.CertPool

	// SignRootCertificates 签名根证书原始切片，用于构建 gmsm 证书池
	SignRootCertificates []*x509.Certificate

	// EncRootCertificates 加密根证书原始切片，用于构建 gmsm 证书池
	EncRootCertificates []*x509.Certificate

	// CipherSuites TLCP Cipher Suites（默认使用国密套件）
	CipherSuites []uint16

	// ServerName SNI
	ServerName string

	// ClientAuth 客户端认证策略
	ClientAuth ClientAuthType

	// ClientCACertificates 用于验证客户端证书的 CA 证书（服务端使用）。
	// gotlcp 使用 gmsm/smx509 进行证书验证，需要原始证书来构建 gmsm 证书池。
	ClientCACertificates []*x509.Certificate

	// InsecureSkipVerify 跳过证书验证（仅用于测试）
	InsecureSkipVerify bool

	// MinVersion 最小 TLS 版本
	MinVersion uint16

	// MaxVersion 最大 TLS 版本
	MaxVersion uint16
}

// NewConfig 创建默认 TLCP 配置
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

// configToGotlcp 将 pollux Config 转换为 gotlcp Config。
// 核心转换：stdlib 证书类型 → gmsm 证书类型。
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

	// 证书转换：SignCertificate → Certificates[0], EncCertificate → Certificates[1]
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

	// RootCAs：合并签名 + 加密根证书到 gmsm smx509.CertPool
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

	// ClientCAs：从原始证书构建 gmsm smx509.CertPool
	if len(c.ClientCACertificates) > 0 {
		pool, err := buildSMX509CertPool(c.ClientCACertificates)
		if err != nil {
			return nil, fmt.Errorf("tlcp: build client CA pool: %w", err)
		}
		gc.ClientCAs = pool
	}

	return gc, nil
}

// buildSMX509CertPool 从 stdlib x509.Certificate 列表构建 gmsm smx509.CertPool。
// 通过 DER 重解析实现类型转换。
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

// LoadCertificates 从文件加载双证书
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

// LoadCertificatesFromPEM 从 PEM 数据加载双证书
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

// LoadRootCAs 从文件加载双 CA 根证书
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

// LoadRootCAsFromPEM 从 PEM 加载双 CA 根证书
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

// createCertPoolAndCertsFromFile 从文件创建证书池并解析原始证书
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

// createCertPoolAndCertsFromPEM 从 PEM 数据创建证书池并解析原始证书
func createCertPoolAndCertsFromPEM(pemData []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, nil, fmt.Errorf("tlcp: parse PEM certificate")
	}

	certs := parsePEMCertificates(pemData)
	return pool, certs, nil
}

// parsePEMCertificates 从 PEM 数据解析出 []*x509.Certificate
func parsePEMCertificates(pemData []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			break
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// Validate 验证 TLCP 配置
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

// Clone 克隆 TLCP 配置
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

// String 返回 TLCP 配置的字符串表示
func (c *Config) String() string {
	return fmt.Sprintf("TLCPConfig{Version=%s, ServerName=%s, CipherSuites=%d}",
		c.Version, c.ServerName, len(c.CipherSuites))
}

// VersionFromString 从字符串解析 TLCP 版本
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

// IsAvailable 检查 TLCP 是否可用
func IsAvailable() bool {
	return true
}

// GetCipherSuites 获取默认的 TLCP Cipher Suites（GCM-only）
func GetCipherSuites() []uint16 {
	return DefaultCipherSuites()
}

// AllCipherSuites 获取完整的 TLCP Cipher Suites 列表（包含 CBC）
func AllCipherSuites() []uint16 {
	return LegacyCipherSuites()
}

// IsCipherSuite 检查是否是 TLCP Cipher Suite
func IsCipherSuite(suite uint16) bool {
	return polluxtls.IsNationalCipherSuite(suite)
}

// GetCipherSuiteName 获取 TLCP Cipher Suite 名称
func GetCipherSuiteName(suite uint16) string {
	return polluxtls.CipherSuiteName(suite)
}

// ConnectionState 记录 TLCP 连接的安全参数
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

// Listener TLCP 监听器
type Listener struct {
	net.Listener
	config *Config
}

// NewListener 创建 TLCP 监听器（参照 tls.NewListener）
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &Listener{Listener: inner, config: config}
}

// Accept 接受 TLCP 连接
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

// Listen 创建 TLCP 监听器（参照 tls.Listen）
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln, config), nil
}

// Dial 建立 TLCP 客户端连接（参照 tls.Dial）
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(nil, network, addr, config)
}

// DialWithDialer 使用自定义拨号器建立 TLCP 连接（参照 tls.DialWithDialer）
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

// BuildClientConfig 构建 TLS 客户端配置
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

// BuildServerConfig 构建 TLS 服务器配置
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

// LoadConfigFile 从配置文件加载 TLCP 配置（未实现）
func LoadConfigFile(configFile string) (*Config, error) {
	if configFile == "" {
		return nil, fmt.Errorf("tlcp: config file path is empty")
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("tlcp: config file not found: %s", configFile)
	}
	return nil, fmt.Errorf("%w: YAML config parsing not implemented", ErrNotImplemented)
}

// Enable 在现有 TLS 配置上启用 TLCP Cipher Suites
func Enable(tlsCfg *tls.Config) error {
	nationalSuites := polluxtls.NationalCipherSuites()
	if len(nationalSuites) == 0 {
		return ErrTLCPNotSupported
	}
	tlsCfg.CipherSuites = append(tlsCfg.CipherSuites, nationalSuites...)
	return nil
}

// Disable 在 TLS 配置上禁用 TLCP Cipher Suites
func Disable(tlsCfg *tls.Config) {
	filtered := make([]uint16, 0, len(tlsCfg.CipherSuites))
	for _, suite := range tlsCfg.CipherSuites {
		if !polluxtls.IsNationalCipherSuite(suite) {
			filtered = append(filtered, suite)
		}
	}
	tlsCfg.CipherSuites = filtered
}

// GetStandardSummary 获取 TLCP 标准摘要
func GetStandardSummary() string {
	return `
TLCP (Transport Layer Cryptography Protocol) 标准摘要

主要标准:
- GB/T 38636-2020: 信息安全技术 传输层密码协议（TLCP）
- RFC 8998: TLS 1.3 with SM2/SM3/SM4

TLCP 1.1 (基于 TLS 1.2):
- 双证书机制: 签名证书 + 加密证书
- 密钥交换: ECDHE_SM2 / ECC_SM2
- 对称加密: SM4_GCM / SM4_CBC
- 消息摘要: SM3

主要 Cipher Suites:
- ECDHE_SM2_WITH_SM4_GCM_SM3 (0xE051)
- ECDHE_SM2_WITH_SM4_CBC_SM3 (0xE011)
- ECC_SM2_WITH_SM4_GCM_SM3 (0xE053)
- ECC_SM2_WITH_SM4_CBC_SM3 (0xE013)
`
}
