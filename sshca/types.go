// See doc.go for the package documentation (godoc convention).
// This file: wire-level types (CertType, requests, permissions) and validators.
package sshca

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// CertType 证书类型（OpenSSH PROTOCOL.certkeys 线协议值）。
// UserCert=1、HostCert=2 是 OpenSSH wire 固定值——此前 iota 隐式编号
// 导致 UserCert=0、HostCert=1，签发的证书 type 字节错误（sshd 拒绝 /
// host 证书被解析为 user 证书）。与 golang.org/x/crypto/ssh.UserCert/HostCert 对齐。
type CertType int

const (
	// UserCert 用户证书（OpenSSH wire value = 1）
	UserCert CertType = 1
	// HostCert 主机证书（OpenSSH wire value = 2）
	HostCert CertType = 2
)

// String 返回证书类型的字符串表示
func (c CertType) String() string {
	switch c {
	case UserCert:
		return "user"
	case HostCert:
		return "host"
	default:
		return "unknown"
	}
}

// CriticalOption SSH 证书关键选项
type CriticalOption struct {
	Name  string
	Value string
}

// Extension SSH 证书扩展
type Extension struct {
	Name  string
	Value string
}

// CertificateRequest SSH 证书请求
type CertificateRequest struct {
	// Type 证书类型
	Type CertType
	// Key 公钥
	Key ssh.PublicKey
	// KeyID 密钥标识（通常是用户名或主机名）
	KeyID string
	// ValidPrincipals 主体（用户名或主机名）
	ValidPrincipals []string
	// ValidAfter 证书生效时间（Unix 时间戳）
	ValidAfter uint64
	// ValidBefore 证书过期时间（Unix 时间戳）
	ValidBefore uint64
	// CriticalOptions 关键选项
	CriticalOptions []CriticalOption
	// Extensions 扩展
	Extensions []Extension
	// Permissions 权限
	Permissions *Permissions
}

// Permissions SSH 证书权限
type Permissions struct {
	// PermitX11Forwarding 是否允许 X11 转发
	PermitX11Forwarding bool
	// PermitAgentForwarding 是否允许 Agent 转发
	PermitAgentForwarding bool
	// PermitPortForwarding 是否允许端口转发
	PermitPortForwarding bool
	// PermitPTY 是否允许 PTY
	PermitPTY bool
	// PermitUserRC 是否允许用户 RC 文件
	PermitUserRC bool
	// SourceAddress 允许的源地址（CIDR 格式）
	SourceAddresses []string
}

// Certificate 签发的 SSH 证书
type Certificate struct {
	// Certificate SSH 证书
	*ssh.Certificate
	// Type 证书类型
	Type CertType
	// KeyID 密钥标识
	KeyID string
	// ValidPrincipals 主体列表
	ValidPrincipals []string
	// ValidAfter 生效时间
	ValidAfter time.Time
	// ValidBefore 过期时间
	ValidBefore time.Time
}

// Signer SSH 证书签名器接口
type Signer interface {
	// SignCertificate 签发证书
	SignCertificate(req *CertificateRequest) (*Certificate, error)
	// SignUserCertificate 签发用户证书
	SignUserCertificate(req *CertificateRequest) (*Certificate, error)
	// SignHostCertificate 签发主机证书
	SignHostCertificate(req *CertificateRequest) (*Certificate, error)
	// GetPublicKey 获取签名公钥
	GetPublicKey() ssh.PublicKey
	// GetType 获取签名密钥类型
	GetType() string
}

// Authority SSH 证书授权机构接口
type Authority interface {
	// Signer 返回用户证书签名器（兼容历史调用）
	Signer() Signer
	// HostSigner 返回主机证书签名器（GetSSHHostCAPublicKey 用，此前 Signer() 仅返回 userSigner
	// 导致 host-ca.pub 返回的是用户 CA 公钥）
	HostSigner() Signer
	// CreateUserCertificate 创建用户证书请求
	CreateUserCertificateRequest(keyID string, publicKey ssh.PublicKey, principals []string, duration time.Duration, permissions *Permissions) (*CertificateRequest, error)
	// CreateHostCertificateRequest 创建主机证书请求
	CreateHostCertificateRequest(keyID string, publicKey ssh.PublicKey, principals []string, duration time.Duration) (*CertificateRequest, error)
	// ValidateCertificate 验证证书
	ValidateCertificate(cert *ssh.Certificate) error
}

// KeyPair 密钥对
type KeyPair struct {
	PrivateKey ssh.Signer
	PublicKey  ssh.PublicKey
}

// GetDefaultUserPermissions 获取默认用户权限（全 permit-*，ssh-keygen 惯例）。
func GetDefaultUserPermissions() *Permissions {
	return &Permissions{
		PermitX11Forwarding:   true,
		PermitAgentForwarding: true,
		PermitPortForwarding:  true,
		PermitPTY:             true,
		PermitUserRC:          true,
		SourceAddresses:       []string{},
	}
}

// GetDefaultHostPermissions 获取默认主机权限。
// OpenSSH 约定：host 证书不带 permit-* 扩展（这些扩展仅定义于 user 证书），
// 返回全零 Permissions（signer 的 host 分支据此不写任何扩展）。
func GetDefaultHostPermissions() *Permissions {
	return &Permissions{SourceAddresses: []string{}}
}

// ValidatePrincipals 验证主体列表。
// SSH principal（用户名或主机名）按 RFC 4251/4252：字母、数字、点、连字符、
// 下划线。拒绝空白、控制字符、shell 元字符（防止注入 root"; rm -rf / 这类主体）。
func ValidatePrincipals(principals []string) error {
	if len(principals) == 0 {
		return errors.New("主体列表不能为空")
	}

	for _, principal := range principals {
		if principal == "" {
			return fmt.Errorf("主体不能为空字符串")
		}
		// 检查长度限制
		if len(principal) > 1024 {
			return fmt.Errorf("主体 %s 超过最大长度 1024", principal)
		}
		// 字符白名单：alnum . _ - （POSIX 用户名/主机名常见字符）。
		// 拒绝空格、引号、分号、管道、反引号等 shell 元字符。
		for _, ch := range principal {
			if !isPrincipalChar(ch) {
				return fmt.Errorf("主体 %q 含非法字符 %q（仅允许字母数字 . _ -）", principal, ch)
			}
		}
	}

	return nil
}

// isPrincipalChar 检查字符是否为允许的 principal 字符。
func isPrincipalChar(ch rune) bool {
	switch {
	case ch >= 'a' && ch <= 'z':
		return true
	case ch >= 'A' && ch <= 'Z':
		return true
	case ch >= '0' && ch <= '9':
		return true
	case ch == '.' || ch == '_' || ch == '-':
		return true
	}
	return false
}

// ValidateSourceAddresses 验证源地址列表
func ValidateSourceAddresses(addresses []string) error {
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		// 验证 CIDR 格式或 IP 地址
		if _, _, err := net.ParseCIDR(addr); err != nil {
			if ip := net.ParseIP(addr); ip == nil {
				return fmt.Errorf("无效的源地址: %s", addr)
			}
		}
	}

	return nil
}
