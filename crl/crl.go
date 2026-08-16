// Package crl 提供证书撤销列表 (CRL) 的生成和管理功能
//
// 本包实现了 X.509 CRL 的生成、更新和分发功能：
//   - CRL 生成：根据已撤销证书列表生成 CRL
//   - CRL 更新：定期更新 CRL
//   - CRL 缓存：缓存生成的 CRL 以提高性能
//   - CRL 分发：通过 HTTP API 提供 CRL 下载
//   - 国密支持：SM2 密钥自动使用 SM2+SM3 签名（符合 GM/T 0009-2012）
//
// 使用示例：
//
//	generator := crl.NewGenerator(auth)
//	crlPEM, err := generator.Generate(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// 保存 CRL 到文件
//	os.WriteFile("crl.pem", crlPEM, 0644)
//
// SM2+SM3 CRL 支持：
// 对于 SM2 密钥，本包自动使用 smx509.CreateRevocationList 创建符合
// GM/T 0009-2012 标准的 CRL（使用 SM2 签名和 SM3 哈希）。
package crl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// Generator CRL 生成器接口
type Generator interface {
	// Generate 生成 CRL
	Generate(ctx context.Context) ([]byte, error)

	// GenerateWithOptions 使用选项生成 CRL
	GenerateWithOptions(ctx context.Context, opts *GenerateOptions) ([]byte, error)

	// Update 更新 CRL
	Update(ctx context.Context) error

	// Get 获取缓存的 CRL
	Get() []byte

	// StartAutoUpdate 启动自动更新
	StartAutoUpdate(interval time.Duration)

	// StopAutoUpdate 停止自动更新
	StopAutoUpdate()
}

// GenerateOptions CRL 生成选项
type GenerateOptions struct {
	// ThisUpdate CRL 的生效时间
	ThisUpdate time.Time

	// NextUpdate CRL 的下次更新时间
	NextUpdate time.Time

	// RevokedCertificates 已撤销证书列表（如果为空则从存储获取）
	RevokedCertificates []*RevokedCertificate

	// Number CRL 序列号
	Number int
}

// RevokedCertificate 已撤销证书
type RevokedCertificate struct {
	// 序列号
	Serial string

	// 撤销原因
	Reason polluxsmx509.CRLReason

	// 撤销时间
	RevokedAt time.Time

	// 过期时间
	ExpiresAt time.Time
}

// RFC 5280 §5.3.1 CRLReason 常量（别名，指向 pollux-go/smx509）。
const (
	ReasonUnspecified          = polluxsmx509.ReasonUnspecified
	ReasonKeyCompromise        = polluxsmx509.ReasonKeyCompromise
	ReasonCACompromise         = polluxsmx509.ReasonCACompromise
	ReasonAffiliationChanged   = polluxsmx509.ReasonAffiliationChanged
	ReasonSuperseded           = polluxsmx509.ReasonSuperseded
	ReasonCessationOfOperation = polluxsmx509.ReasonCessationOfOperation
	ReasonCertificateHold      = polluxsmx509.ReasonCertificateHold
	ReasonRemoveFromCRL        = polluxsmx509.ReasonRemoveFromCRL
	ReasonPrivilegeWithdrawn   = polluxsmx509.ReasonPrivilegeWithdrawn
	ReasonAACompromise         = polluxsmx509.ReasonAACompromise
)

// crlGenerator CRL 生成器实现
type crlGenerator struct {
	authority   Authority
	cache       CRLCache
	issuerKeyID string // 限定该生成器只覆盖此 issuer 签发的证书（空=全量，单 issuer 兼容）

	mu             sync.RWMutex
	lastCRL        []byte
	lastUpdateTime time.Time
	crlNumber      int
	// numberSource 持久序号源（server 注入 DB 实现）；nil 时退回进程内计数
	// （仅测试/无 DB 场景——重启归零，不符合 §5.2.3）。
	numberSource func() (int, error)
	validity     time.Duration // CRL 有效期（nextUpdate - thisUpdate）

	stopCh   chan struct{}
	once     sync.Once
	stopOnce sync.Once
}

// Authority CRL 所需的权威接口
type Authority interface {
	// GetRevokedList 获取已撤销证书列表
	GetRevokedList(ctx context.Context) ([]*RevokedCertificate, error)

	// GetRevokedListByIssuer 获取指定 issuer 的已撤销证书列表（多 issuer CRL 路由用）。
	// issuerKeyID 为 issuer SubjectKeyIdentifier（hex），严格匹配（无空值回退）。
	GetRevokedListByIssuer(ctx context.Context, issuerKeyID string) ([]*RevokedCertificate, error)

	// GetCertificateChain 获取证书链
	GetCertificateChain() []*x509.Certificate

	// GetIntermediateCA 获取中级 CA 证书
	GetIntermediateCA() *x509.Certificate

	// GetIntermediateKey 获取中级 CA 签名能力
	GetIntermediateKey() crypto.Signer
}

// CRLCache CRL 缓存接口
type CRLCache interface {
	// Set 设置 CRL
	Set(crl []byte)

	// Get 获取 CRL
	Get() []byte

	// Clear 清空 CRL
	Clear()
}

// memoryCRLCache 内存 CRL 缓存实现
type memoryCRLCache struct {
	mu  sync.RWMutex
	crl []byte
}

// NewMemoryCRLCache 创建内存 CRL 缓存
func NewMemoryCRLCache() CRLCache {
	return &memoryCRLCache{}
}

func (m *memoryCRLCache) Set(crl []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crl = crl
}

func (m *memoryCRLCache) Get() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.crl
}

func (m *memoryCRLCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crl = nil
}

// SetNumberSource 注入持久序号源（生成器构造后装配期调用）。
func (g *crlGenerator) SetNumberSource(src NumberSource) { g.numberSource = src }

// NumberSource 返回该 issuer 的下一个 CRL 序号（由 server 注入持久实现）。
type NumberSource func() (int, error)

// NewGeneratorWithNumberSource 创建带持久序号源的生成器（RFC 5280 §5.2.3：
// 序号须跨重启/跨生成器实例单调）。
func NewGeneratorWithNumberSource(auth Authority, cache CRLCache, issuerKeyID string, src NumberSource) Generator {
	g := NewGeneratorWithIssuer(auth, cache, issuerKeyID)
	if cg, ok := g.(*crlGenerator); ok {
		cg.numberSource = src
	}
	return g
}

// NewGenerator 创建 CRL 生成器
func NewGenerator(auth Authority, cache CRLCache) Generator {
	return &crlGenerator{
		authority: auth,
		cache:     cache,
		stopCh:    make(chan struct{}),
	}
}

// NewGeneratorWithIssuer 创建限定到指定 issuer 的 CRL 生成器（多 issuer 路由用）。
// issuerKeyID 非空时，仅覆盖该 issuer 签发的撤销记录。空则退化为全量（单 issuer）。
func NewGeneratorWithIssuer(auth Authority, cache CRLCache, issuerKeyID string) Generator {
	return &crlGenerator{
		authority:   auth,
		cache:       cache,
		issuerKeyID: issuerKeyID,
		stopCh:      make(chan struct{}),
	}
}

// Generate 生成 CRL
func (g *crlGenerator) Generate(ctx context.Context) ([]byte, error) {
	// Number: 0 是"自动递增"哨兵——GenerateWithOptions 会用 g.crlNumber+1。
	// RFC 5280 §5.2.3 要求 CRL number 单调递增；此前恒为 0 违反该约束。
	validity := g.validity
	if validity <= 0 {
		validity = 24 * time.Hour // 默认有效期
	}
	return g.GenerateWithOptions(ctx, &GenerateOptions{
		ThisUpdate: time.Now().UTC(),
		NextUpdate: time.Now().Add(validity).UTC(),
		Number:     0,
	})
}

// GenerateWithOptions 使用选项生成 CRL
func (g *crlGenerator) GenerateWithOptions(ctx context.Context, opts *GenerateOptions) ([]byte, error) {
	// 获取已撤销证书列表
	revokedList := opts.RevokedCertificates
	if revokedList == nil {
		var err error
		// issuer 限定：多 issuer 部署时每个生成器只覆盖对应 issuer 的撤销记录。
		if g.issuerKeyID != "" {
			revokedList, err = g.authority.GetRevokedListByIssuer(ctx, g.issuerKeyID)
		} else {
			revokedList, err = g.authority.GetRevokedList(ctx)
		}
		if err != nil {
			return nil, err
		}
	}

	// 构建撤销证书列表（添加 RFC 5279 撤销原因扩展）
	revokedCerts := make([]x509.RevocationListEntry, 0, len(revokedList))
	for _, revoked := range revokedList {
		serial := new(big.Int)
		// authority 以十进制存储序列号（cert.SerialNumber.String()），此处按十进制解析。
		// 此前用 base 16 解析十进制串会得到数值不同的 serial，导致 CRL 里的撤销号
		// 与实际证书号对不上（撤销检测失效）。
		if _, ok := serial.SetString(revoked.Serial, 10); !ok {
			// 序列号非法的记录若被静默跳过，证书会"漏撤销"；至少留痕便于排查。
			slog.Warn("CRL 撤销记录序列号非法，已跳过", "serial", revoked.Serial)
			continue
		}

		// 创建撤销条目。撤销原因（RFC 5280 §5.3.1 reasonCode, OID 2.5.29.21）
		// 必须经 ReasonCode 字段携带：Go 1.26 序列化只认该字段，此前手工
		// CreateCRLReasonExtension 塞 Extensions 的写法被静默忽略——CRL 里
		// 的原因全部退化为 unspecified。
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revoked.RevokedAt.UTC(),
			ReasonCode:     int(revoked.Reason),
		}

		// invalidityDate（2.5.29.24）不再编码：RFC 5280 §5.3.2 定义其为
		// "CA 已知/怀疑证书失效的日期"，此前误用证书自然到期时间（NotAfter），
		// 属错误断言。本系统不单独追踪失效感知时间，故省略该可选扩展。

		revokedCerts = append(revokedCerts, entry)
	}

	// 获取中级 CA 证书和私钥
	x509Cert := g.authority.GetIntermediateCA()
	key := g.authority.GetIntermediateKey()

	// 设置默认时间
	now := opts.ThisUpdate
	if now.IsZero() {
		now = time.Now().UTC()
	}

	nextUpdate := opts.NextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = now.Add(24 * time.Hour).UTC()
	}

	var crlBytes []byte
	var err error

	// CRL number 单调递增（RFC 5280 §5.2.3）。opts.Number == 0 表示"自动递增"
	// 哨兵——用 g.crlNumber + 1。显式非零值则采用调用方指定（测试/外部触发用）。
	//
	// 并发安全：effectiveNumber 的读取+计算+回写必须在同一把锁内完成，否则
	// autoUpdateLoop 与 HTTP Generate 并发时两个 goroutine 可能读到相同的
	// g.crlNumber，各自 +1 得到相同值，违反 §5.2.3 单调/唯一约束。这里在
	// 签发前 reserve number（立即回写），签发失败会跳号（可接受，CRL Number
	// 不要求连续）。
	effectiveNumber := opts.Number
	if effectiveNumber == 0 {
		if g.numberSource != nil {
			n, nErr := g.numberSource()
			if nErr != nil {
				return nil, fmt.Errorf("分配持久 CRL 序号失败: %w", nErr)
			}
			effectiveNumber = n
		} else {
			g.mu.Lock()
			effectiveNumber = g.crlNumber + 1
			g.crlNumber = effectiveNumber // reserve，防止并发拿到相同值
			g.mu.Unlock()
		}
	}

	// SM2: use pollux smx509 for SM2+SM3 signing (GM/T 0009-2012)
	if polluxsmx509.IsSM2Key(key) {
		crlBytes, err = polluxsmx509.CreateRevocationList(&x509.RevocationList{
			RevokedCertificateEntries: revokedCerts,
			Number:                    big.NewInt(int64(effectiveNumber)),
			ThisUpdate:                now,
			NextUpdate:                nextUpdate,
		}, x509Cert, key)
		if err != nil {
			return nil, fmt.Errorf("SM2 CRL creation failed: %w", err)
		}
	} else {
		// 非 SM2 密钥使用标准库
		crlBytes, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			RevokedCertificateEntries: revokedCerts,
			Number:                    big.NewInt(int64(effectiveNumber)),
			ThisUpdate:                now,
			NextUpdate:                nextUpdate,
		}, x509Cert, key)
		if err != nil {
			return nil, err
		}
	}

	// 编码为 PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	// 更新缓存（effectiveNumber 已在 reserve 阶段回写，这里只更新 CRL 内容）
	g.mu.Lock()
	g.lastCRL = crlPEM
	g.lastUpdateTime = time.Now()
	g.mu.Unlock()

	// 保存到缓存
	if g.cache != nil {
		g.cache.Set(crlPEM)
	}

	return crlPEM, nil
}

// Update 更新 CRL
func (g *crlGenerator) Update(ctx context.Context) error {
	_, err := g.Generate(ctx)
	return err
}

// Get 获取缓存的 CRL
func (g *crlGenerator) Get() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.cache != nil {
		if crl := g.cache.Get(); crl != nil {
			return crl
		}
	}

	return g.lastCRL
}

// StartAutoUpdate 启动自动更新。
// CRL 有效期设为 2*interval，保证 ticker 触发刷新时 CRL 仍有 interval
// 时长的有效期（RFC 5280 §5.2.6：nextUpdate 之后的 CRL 不应被信任为
// 完整撤销集合——有效期 > 刷新间隔消除过期窗口）。
func (g *crlGenerator) StartAutoUpdate(interval time.Duration) {
	g.once.Do(func() {
		g.validity = 2 * interval
		go g.autoUpdateLoop(interval)
	})
}

// StopAutoUpdate 停止自动更新。幂等：多次调用安全（sync.Once 保护，
// 避免 graceful shutdown 与 signal handler 双触发时重复 close 导致 panic）。
func (g *crlGenerator) StopAutoUpdate() {
	g.stopOnce.Do(func() {
		close(g.stopCh)
	})
}

// autoUpdateLoop 自动更新循环
func (g *crlGenerator) autoUpdateLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if err := g.Update(ctx); err != nil {
				slog.Error("CRL 自动更新失败，吊销状态可能无法及时传播",
					"error", err)
				cancel() // 确保在所有路径都调用 cancel
				continue
			}
			cancel()

		case <-g.stopCh:
			return
		}
	}
}

// IsExpired 检查 CRL 是否过期
func IsExpired(crlPEM []byte) bool {
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return true
	}
	if block.Type != "X509 CRL" {
		return true
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return true
	}

	return time.Now().After(crl.NextUpdate)
}

// crlError CRL 错误
type crlError struct {
	msg string
}

func (e *crlError) Error() string {
	return "crl: " + e.msg
}

// ErrInvalidCRL 无效的 CRL
var ErrInvalidCRL = &crlError{"invalid CRL"}

// GetRevokedSerials 从 CRL 中提取已撤销证书的序列号
func GetRevokedSerials(crlPEM []byte) ([]string, error) {
	block, rest := pem.Decode(crlPEM)
	if block == nil {
		if len(rest) > 0 {
			return nil, fmt.Errorf("无效的 CRL PEM 数据（剩余 %d 字节无法解析）", len(rest))
		}
		return nil, ErrInvalidCRL
	}
	if block.Type != "X509 CRL" {
		return nil, fmt.Errorf("无效的 PEM 块类型: %s（期望 X509 CRL）", block.Type)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CRL 失败: %w", err)
	}

	serials := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, revoked := range crl.RevokedCertificateEntries {
		serials = append(serials, revoked.SerialNumber.String())
	}

	return serials, nil
}

// CRLRecord CRL 中单条撤销记录的解析视图（控制台展示用）。
type CRLRecord struct {
	// Serial 被撤销证书的序列号（十进制）
	Serial string
	// ReasonCode RFC 5280 §5.3.1 撤销原因码（0 = unspecified/未携带）
	ReasonCode int
	// Reason 原因码对应的可读名（unspecified/keyCompromise/...）
	Reason string
	// RevokedAt 撤销时间
	RevokedAt time.Time
}

// crlReasonNames RFC 5280 §5.3.1 reasonCode 枚举名（7 未分配，供展示）。
var crlReasonNames = map[int]string{
	0: "unspecified", 1: "keyCompromise", 2: "cACompromise",
	3: "affiliationChanged", 4: "superseded", 5: "cessationOfOperation",
	6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn",
	10: "aACompromise",
}

// ParseCRLRecords 解析 CRL PEM，返回全部撤销条目（含原因与撤销时间）。
// 解析只读结构、不验签，国密签名的 CRL 同样适用。
func ParseCRLRecords(crlPEM []byte) ([]CRLRecord, error) {
	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		return nil, ErrInvalidCRL
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CRL 失败: %w", err)
	}
	records := make([]CRLRecord, 0, len(rl.RevokedCertificateEntries))
	for _, entry := range rl.RevokedCertificateEntries {
		reason := entry.ReasonCode
		name, ok := crlReasonNames[reason]
		if !ok {
			name = fmt.Sprintf("reason(%d)", reason)
		}
		records = append(records, CRLRecord{
			Serial:     entry.SerialNumber.String(),
			ReasonCode: reason,
			Reason:     name,
			RevokedAt:  entry.RevocationTime,
		})
	}
	return records, nil
}

// GetCRLNumber 从 CRL 中提取序列号
func GetCRLNumber(crlPEM []byte) (int, error) {
	block, rest := pem.Decode(crlPEM)
	if block == nil {
		if len(rest) > 0 {
			return 0, fmt.Errorf("无效的 CRL PEM 数据（剩余 %d 字节无法解析）", len(rest))
		}
		return 0, ErrInvalidCRL
	}
	if block.Type != "X509 CRL" {
		return 0, fmt.Errorf("无效的 PEM 块类型: %s（期望 X509 CRL）", block.Type)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("解析 CRL 失败: %w", err)
	}

	if crl.Number == nil {
		return 0, nil
	}

	return int(crl.Number.Int64()), nil
}
