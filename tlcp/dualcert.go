package tlcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/ycq/pollux/sm2"
	polluxSmx509 "github.com/ycq/pollux/smx509"
)

var (
	errInvalidCertPair   = errors.New("tlcp: invalid dual certificate pair")
	errSignCertMissing   = errors.New("tlcp: sign certificate is required")
	errEncCertMissing    = errors.New("tlcp: encrypt certificate is required")
	errNotSM2Certificate = errors.New("tlcp: certificate is not SM2")
)

// DualCertPair 表示一对 TLCP 双证书（签名证书 + 加密证书）。
// 这是 TLCP 协议的核心特征：签名和加密使用不同的证书和密钥。
type DualCertPair struct {
	SignCert *x509.Certificate
	EncCert  *x509.Certificate
	SignKey  *sm2.PrivateKey
	EncKey   *sm2.PrivateKey
}

// LoadDualCertPair 从 PEM 文件加载双证书对。
func LoadDualCertPair(signCertFile, signKeyFile, encCertFile, encKeyFile string) (*DualCertPair, error) {
	signCert, err := loadCertificate(signCertFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load sign cert: %w", err)
	}

	encCert, err := loadCertificate(encCertFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load encrypt cert: %w", err)
	}

	signKey, err := loadSM2PrivateKey(signKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load sign key: %w", err)
	}

	encKey, err := loadSM2PrivateKey(encKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tlcp: load encrypt key: %w", err)
	}

	pair := &DualCertPair{
		SignCert: signCert,
		EncCert:  encCert,
		SignKey:  signKey,
		EncKey:   encKey,
	}

	if err := ValidateDualCertPair(pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// LoadDualCertPairFromPEM 从 PEM 编码的字节数据加载双证书对。
func LoadDualCertPairFromPEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) (*DualCertPair, error) {
	signCert, err := parseCertificatePEM(signCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse sign cert: %w", err)
	}

	encCert, err := parseCertificatePEM(encCertPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse encrypt cert: %w", err)
	}

	signKey, err := sm2.ParsePrivateKeyFromPEM(signKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse sign key: %w", err)
	}

	encKey, err := sm2.ParsePrivateKeyFromPEM(encKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlcp: parse encrypt key: %w", err)
	}

	pair := &DualCertPair{
		SignCert: signCert,
		EncCert:  encCert,
		SignKey:  signKey,
		EncKey:   encKey,
	}

	if err := ValidateDualCertPair(pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// ValidateDualCertPair 验证双证书对的合法性。
// 检查：证书类型、密钥用途、签发者一致、未过期。
func ValidateDualCertPair(pair *DualCertPair) error {
	if pair.SignCert == nil {
		return errSignCertMissing
	}
	if pair.EncCert == nil {
		return errEncCertMissing
	}

	// 验证签名证书用途
	if err := ValidateTLCPCertificate(pair.SignCert, true); err != nil {
		return fmt.Errorf("tlcp: sign cert: %w", err)
	}

	// 验证加密证书用途
	if err := ValidateTLCPCertificate(pair.EncCert, false); err != nil {
		return fmt.Errorf("tlcp: encrypt cert: %w", err)
	}

	// 检查同一签发者（比较 RawIssuer）
	if !bytes.Equal(pair.SignCert.RawIssuer, pair.EncCert.RawIssuer) {
		return fmt.Errorf("tlcp: sign and encrypt certs from different issuers")
	}

	return nil
}

// ValidateTLCPCertificate 检查单个证书是否满足 TLCP 要求。
func ValidateTLCPCertificate(cert *x509.Certificate, isSignCert bool) error {
	if cert == nil {
		return errInvalidCertPair
	}

	// 验证是 SM2 证书
	if !polluxSmx509.IsSM2PublicKey(cert.PublicKey) {
		return errNotSM2Certificate
	}

	// 验证密钥用途
	if isSignCert {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("tlcp: sign cert missing digitalSignature key usage")
		}
	} else {
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
			cert.KeyUsage&x509.KeyUsageDataEncipherment == 0 {
			return fmt.Errorf("tlcp: encrypt cert missing keyEncipherment or dataEncipherment key usage")
		}
	}

	return nil
}

// VerifyDualCertPair 验证双证书对的配对关系（同签发者、密钥用途）。
// 链验证需由调用方分别对每张证书执行。
func VerifyDualCertPair(pair *DualCertPair) error {
	return polluxSmx509.VerifyDualCerts(pair.SignCert, pair.EncCert)
}

// ToTLSCertificates 将双证书对转换为 tls.Certificate。
// 返回 [签名证书, 加密证书]。
func (p *DualCertPair) ToTLSCertificates() ([]tls.Certificate, error) {
	signTLSCert, err := p.toTLSCertificate(p.SignCert, p.SignKey)
	if err != nil {
		return nil, fmt.Errorf("tlcp: convert sign cert: %w", err)
	}

	encTLSCert, err := p.toTLSCertificate(p.EncCert, p.EncKey)
	if err != nil {
		return nil, fmt.Errorf("tlcp: convert encrypt cert: %w", err)
	}

	return []tls.Certificate{signTLSCert, encTLSCert}, nil
}

// toTLSCertificate 将 x509 证书和 SM2 私钥转换为 tls.Certificate。
func (p *DualCertPair) toTLSCertificate(cert *x509.Certificate, key *sm2.PrivateKey) (tls.Certificate, error) {
	certDER, err := polluxSmx509.CreateCertificate(cert, cert, cert.PublicKey, key)
	if err != nil {
		return tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}, nil
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// PublicKeyPairs 返回签名和加密公钥对。
func (p *DualCertPair) PublicKeyPairs() (signPub, encPub *ecdsa.PublicKey) {
	if p.SignCert != nil {
		if pub, ok := p.SignCert.PublicKey.(*ecdsa.PublicKey); ok {
			signPub = pub
		}
	}
	if p.EncCert != nil {
		if pub, ok := p.EncCert.PublicKey.(*ecdsa.PublicKey); ok {
			encPub = pub
		}
	}
	return
}

// loadCertificate 从 PEM 文件加载 x509 证书。
func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseCertificatePEM(data)
}

// parseCertificatePEM 从 PEM 编码数据解析 x509 证书。
func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("tlcp: failed to decode PEM block")
	}
	return polluxSmx509.ParseCertificate(block.Bytes)
}

// loadSM2PrivateKey 从 PEM 文件加载 SM2 私钥。
func loadSM2PrivateKey(filename string) (*sm2.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return sm2.ParsePrivateKeyFromPEM(data)
}
