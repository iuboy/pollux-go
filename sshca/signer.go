// See doc.go for the package documentation (godoc convention).
// This file: certificate signing, validation, and the sshAuthority assembly.
package sshca

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateCertSerial 生成加密随机的 SSH 证书序列号。
// 此前用 time.Now().Unix() 导致同秒内签发的证书 serial 碰撞——
// CA serial 必须唯一（RFC 4251 §3）。改用 crypto/rand 读 64-bit。
func generateCertSerial() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// rand.Read 失败极罕见；回退到时间戳+纳秒扰动，保证进程内递增唯一。
		return uint64(time.Now().UnixNano())
	}
	serial := binary.BigEndian.Uint64(buf[:])
	// 清零最高位避免某些客户端的有符号 int64 溢出问题。
	return serial &^ (1 << 63)
}

// CertificateSigner SSH 证书签名器实现
type CertificateSigner struct {
	signer      ssh.Signer
	certType    CertType
	maxDuration time.Duration
}

// NewCertificateSigner 创建证书签名器
func NewCertificateSigner(keyPair *KeyPair, certType CertType, maxDuration time.Duration) (*CertificateSigner, error) {
	if keyPair == nil {
		return nil, errors.New("密钥对不能为空")
	}
	if keyPair.PrivateKey == nil {
		return nil, fmt.Errorf("私钥不能为空")
	}

	return &CertificateSigner{
		signer:      keyPair.PrivateKey,
		certType:    certType,
		maxDuration: maxDuration,
	}, nil
}

// SignCertificate 签发证书
func (s *CertificateSigner) SignCertificate(req *CertificateRequest) (*Certificate, error) {
	if err := s.validateRequest(req); err != nil {
		return nil, fmt.Errorf("请求验证失败: %w", err)
	}
	// 时长上限强制（此前仅 CreateUserCertificateRequest 检查，库层调用方可
	// 自行填 ValidBefore 绕过 24h 上限）。
	if s.maxDuration > 0 && req.ValidBefore > req.ValidAfter &&
		time.Duration(req.ValidBefore-req.ValidAfter)*time.Second > s.maxDuration {
		return nil, fmt.Errorf("证书有效期 %v 超过最大值 %v",
			time.Duration(req.ValidBefore-req.ValidAfter)*time.Second, s.maxDuration)
	}

	// 创建证书
	cert := &ssh.Certificate{
		Key:             req.Key,
		Serial:          generateCertSerial(),
		CertType:        uint32(s.certType),
		KeyId:           req.KeyID,
		ValidPrincipals: req.ValidPrincipals,
		ValidAfter:      req.ValidAfter,
		ValidBefore:     req.ValidBefore,
		// 注意：CriticalOptions 和 Extensions 需要在签名前设置
	}

	// 设置关键选项
	cert.CriticalOptions = s.buildCriticalOptions(req)

	// 设置扩展
	cert.Extensions = s.buildExtensions(req)

	// 签名证书
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return nil, fmt.Errorf("签名证书失败: %w", err)
	}

	// 转换为证书对象
	return &Certificate{
		Certificate:     cert,
		Type:            s.certType,
		KeyID:           req.KeyID,
		ValidPrincipals: req.ValidPrincipals,
		ValidAfter:      time.Unix(int64(req.ValidAfter), 0),
		ValidBefore:     time.Unix(int64(req.ValidBefore), 0),
	}, nil
}

// SignUserCertificate 签发用户证书
func (s *CertificateSigner) SignUserCertificate(req *CertificateRequest) (*Certificate, error) {
	if s.certType != UserCert {
		return nil, errors.New("此签名器用于用户证书")
	}
	return s.SignCertificate(req)
}

// SignHostCertificate 签发主机证书
func (s *CertificateSigner) SignHostCertificate(req *CertificateRequest) (*Certificate, error) {
	if s.certType != HostCert {
		return nil, fmt.Errorf("此签名器用于主机证书")
	}
	return s.SignCertificate(req)
}

// GetPublicKey 获取签名公钥
func (s *CertificateSigner) GetPublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

// GetType 获取签名密钥类型
func (s *CertificateSigner) GetType() string {
	return s.signer.PublicKey().Type()
}

// validateRequest 验证证书请求
func (s *CertificateSigner) validateRequest(req *CertificateRequest) error {
	if req == nil {
		return fmt.Errorf("证书请求不能为空")
	}

	if req.Key == nil {
		return fmt.Errorf("公钥不能为空")
	}

	if req.KeyID == "" {
		return fmt.Errorf("密钥 ID 不能为空")
	}

	if err := ValidatePrincipals(req.ValidPrincipals); err != nil {
		return err
	}

	// 验证有效期
	now := uint64(time.Now().Unix())
	if req.ValidAfter == 0 {
		req.ValidAfter = now
	}

	if req.ValidBefore == 0 {
		req.ValidBefore = now + uint64(s.maxDuration.Seconds())
	}

	if req.ValidBefore <= req.ValidAfter {
		return fmt.Errorf("证书过期时间必须大于生效时间")
	}

	// 验证源地址（如果配置了）
	if req.Permissions != nil && len(req.Permissions.SourceAddresses) > 0 {
		if err := ValidateSourceAddresses(req.Permissions.SourceAddresses); err != nil {
			return err
		}
	}

	return nil
}

// buildCriticalOptions 构建关键选项
func (s *CertificateSigner) buildCriticalOptions(req *CertificateRequest) map[string]string {
	options := make(map[string]string)

	// 添加请求中的关键选项
	for _, opt := range req.CriticalOptions {
		options[opt.Name] = opt.Value
	}

	// 源地址限制
	if req.Permissions != nil && len(req.Permissions.SourceAddresses) > 0 {
		options["source-address"] = joinAddresses(req.Permissions.SourceAddresses)
	}

	return options
}

// buildExtensions 构建扩展
func (s *CertificateSigner) buildExtensions(req *CertificateRequest) map[string]string {
	extensions := make(map[string]string)

	// 添加请求中的扩展
	for _, ext := range req.Extensions {
		extensions[ext.Name] = ext.Value
	}

	// 根据证书类型添加默认扩展
	if req.Permissions != nil {
		if s.certType == UserCert {
			// 用户证书权限
			if req.Permissions.PermitX11Forwarding {
				extensions["permit-X11-forwarding"] = ""
			}
			if req.Permissions.PermitAgentForwarding {
				extensions["permit-agent-forwarding"] = ""
			}
			if req.Permissions.PermitPortForwarding {
				extensions["permit-port-forwarding"] = ""
			}
			if req.Permissions.PermitPTY {
				extensions["permit-pty"] = ""
			}
			if req.Permissions.PermitUserRC {
				extensions["permit-user-rc"] = ""
			}
		} else if s.certType == HostCert {
			// 主机证书权限
			if req.Permissions.PermitPortForwarding {
				extensions["permit-port-forwarding"] = ""
			}
		}
	}

	return extensions
}

// joinAddresses 连接地址列表
func joinAddresses(addresses []string) string {
	return strings.Join(addresses, ",")
}

// Authority SSH 证书授权机构实现
type sshAuthority struct {
	userSigner  *CertificateSigner
	hostSigner  *CertificateSigner
	maxDuration time.Duration
}

// NewAuthority 创建 SSH 证书授权机构
func NewAuthority(userKeyPair, hostKeyPair *KeyPair, maxDuration time.Duration) (Authority, error) {
	if userKeyPair == nil {
		return nil, fmt.Errorf("用户密钥对不能为空")
	}
	if hostKeyPair == nil {
		return nil, fmt.Errorf("主机密钥对不能为空")
	}

	userSigner, err := NewCertificateSigner(userKeyPair, UserCert, maxDuration)
	if err != nil {
		return nil, fmt.Errorf("创建用户证书签名器失败: %w", err)
	}

	hostSigner, err := NewCertificateSigner(hostKeyPair, HostCert, maxDuration)
	if err != nil {
		return nil, fmt.Errorf("创建主机证书签名器失败: %w", err)
	}

	return &sshAuthority{
		userSigner:  userSigner,
		hostSigner:  hostSigner,
		maxDuration: maxDuration,
	}, nil
}

// Signer 返回签名器
func (a *sshAuthority) Signer() Signer {
	return a.userSigner
}

// HostSigner 返回主机证书签名器。GetSSHHostCAPublicKey 用此获取正确的 host CA
// 公钥（此前 Signer() 仅返回 userSigner → host-ca.pub 返回的是用户 CA 公钥）。
func (a *sshAuthority) HostSigner() Signer {
	return a.hostSigner
}

// CreateUserCertificate 创建用户证书请求
func (a *sshAuthority) CreateUserCertificateRequest(keyID string, publicKey ssh.PublicKey, principals []string, duration time.Duration, permissions *Permissions) (*CertificateRequest, error) {
	if duration > a.maxDuration {
		return nil, fmt.Errorf("证书有效期 %v 超过最大值 %v", duration, a.maxDuration)
	}

	now := uint64(time.Now().Unix())

	return &CertificateRequest{
		Type:            UserCert,
		Key:             publicKey,
		KeyID:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      now,
		ValidBefore:     now + uint64(duration.Seconds()),
		Permissions:     permissions,
	}, nil
}

// CreateHostCertificateRequest 创建主机证书请求
func (a *sshAuthority) CreateHostCertificateRequest(keyID string, publicKey ssh.PublicKey, principals []string, duration time.Duration) (*CertificateRequest, error) {
	if duration > a.maxDuration {
		return nil, fmt.Errorf("证书有效期 %v 超过最大值 %v", duration, a.maxDuration)
	}

	now := uint64(time.Now().Unix())

	return &CertificateRequest{
		Type:            HostCert,
		Key:             publicKey,
		KeyID:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      now,
		ValidBefore:     now + uint64(duration.Seconds()),
		Permissions:     GetDefaultHostPermissions(),
	}, nil
}

// ValidateCertificate 验证证书的基础完整性：签名 CA 公钥与本服务持有的 CA 公钥
// 字节一致 + 有效期窗口。此前仅比较 SignatureKey.Type()（类型名字符串）——
// 任何同类型 CA 签发的证书都会通过，伪造 CA 也无法被发现。
//
// 注：完整的密码学签名验证应使用 ssh.CertChecker.CheckCert（x/crypto/ssh 内部
// 用 bytesForSigning，未导出）。本方法已接线到 /console/ssh/Validate；
// 后续加固方向是改用 CertChecker 做完整验证（含 principals / critical options）。
// 当前先做字节级 CA 匹配。
func (a *sshAuthority) ValidateCertificate(cert *ssh.Certificate) error {
	if cert == nil {
		return errors.New("证书不能为空")
	}

	// 选 CA 公钥（按证书类型路由到对应 signer）。
	var checkKey ssh.PublicKey
	if CertType(cert.CertType) == UserCert {
		checkKey = a.userSigner.GetPublicKey()
	} else {
		checkKey = a.hostSigner.GetPublicKey()
	}

	// 字节级比对签名 CA 公钥（此前仅比 Type() 字符串）。
	if cert.SignatureKey.Type() != checkKey.Type() {
		return fmt.Errorf("证书签名密钥类型不匹配: %s != %s",
			cert.SignatureKey.Type(), checkKey.Type())
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), checkKey.Marshal()) {
		return errors.New("证书签名 CA 公钥与本服务 CA 不一致")
	}

	// 密码学签名验证（PROTOCOL.certkeys：未通过 CA 签名验证的证书必须拒绝）。
	// 旧实现跳过签名验证——伪造证书只要把 SignatureKey 字段填成本 CA 公钥
	// 即可通过本端点。CertChecker.CheckCert 内部做 bytesForSigning 签名验证、
	// critical options 授权、有效期校验。
	if cert.Signature == nil {
		return errors.New("证书缺少 CA 签名")
	}
	isUser := CertType(cert.CertType) == UserCert
	checker := &ssh.CertChecker{}
	if isUser {
		checker.IsUserAuthority = func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), a.userSigner.GetPublicKey().Marshal())
		}
	} else {
		checker.IsHostAuthority = func(auth ssh.PublicKey, _ string) bool {
			return bytes.Equal(auth.Marshal(), a.hostSigner.GetPublicKey().Marshal())
		}
	}
	// principal 匹配对本端点无意义（授权由 SSH 服务端执行时按连接主体判定）——
	// 任取证书自带的一个 principal（若非空）绕过 CheckCert 的主体匹配，
	// 签名/critical option/有效期校验不受影响。
	principalArg := ""
	if len(cert.ValidPrincipals) > 0 {
		principalArg = cert.ValidPrincipals[0]
	}
	if err := checker.CheckCert(principalArg, cert); err != nil {
		return fmt.Errorf("证书校验失败: %w", err)
	}

	// host 证书不得携带 critical option（PROTOCOL.certkeys：host 证书唯一的
	// 合法 critical option 是保留的空集合）。
	if CertType(cert.CertType) == HostCert && len(cert.CriticalOptions) > 0 {
		return fmt.Errorf("host 证书不允许携带 critical option: %v", criticalOptionNames(cert))
	}

	// 未识别的 critical option 必须拒绝（user 证书仅支持 force-command /
	// source-address，且值需语义合法）。
	if CertType(cert.CertType) == UserCert {
		for name, raw := range cert.CriticalOptions {
			switch name {
			case "force-command":
				if len(raw) == 0 {
					return errors.New("force-command 值不能为空")
				}
			case "source-address":
				if err := ValidateSourceAddresses(splitCommaList(string(raw))); err != nil {
					return fmt.Errorf("source-address 值非法: %w", err)
				}
			default:
				return fmt.Errorf("未识别的 critical option %q，拒绝证书", name)
			}
		}
	}

	// 检查有效期
	now := uint64(time.Now().Unix())
	if now < cert.ValidAfter {
		return fmt.Errorf("证书尚未生效")
	}

	if now > cert.ValidBefore {
		return fmt.Errorf("证书已过期")
	}

	return nil
}

// criticalOptionNames 列出证书的 critical option 名（错误信息用）。
func criticalOptionNames(cert *ssh.Certificate) []string {
	names := make([]string, 0, len(cert.CriticalOptions))
	for name := range cert.CriticalOptions {
		names = append(names, name)
	}
	return names
}

// splitCommaList 按逗号切分（source-address 的 wire 格式为逗号连接的 CIDR 列表）。
func splitCommaList(s string) []string {
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
		if r == ',' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
