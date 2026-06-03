# pollux-go 统一证书与 X.509 隔离层实施计划

## 0. 文档定位

本文基于 `docs/plan` 下现有路线和当前代码状态，规划新增统一证书隔离层，使调用方不需要自行区分：

- 标准 `crypto/x509` 证书
- SM2/国密 X.509 证书
- 标准 TLS 单证书
- TLCP 签名/加密双证书
- 标准 `x509.CertPool`
- 需要保留 raw DER 的 SM2-aware 证书池

相关计划：

- `docs/plan/quic-tls13-gm-roadmap.md` 第 2.5、9 节
- `docs/plan/implementation-master-plan.md` M1、M5
- `docs/plan/test-blackbox-api-implementation-plan.md` smx509、tlcp、http 测试矩阵
- `docs/plan/audit-status-matrix.md` X-4、T-4、X-H1、X-H3

当前基线日期：2026-05-26。

## 1. 当前判断

应该新增统一证书隔离层。

原因：

1. 调用方不应该理解标准 X.509 与 SM2 X.509 的 backend 差异。
2. 标准 `x509.CertPool` 不能反枚举原始 DER，不能作为 SM2 验证路径的唯一 root 表达。
3. TLCP 双证书让调用方同时处理 sign/enc 证书，复杂度明显高于普通 TLS。
4. 审计风险 T-4、X-4 都来自证书验证语义不清或 fallback 过宽。
5. 已有 `smx509.CertPool` 保留 raw DER，是进一步抽象的基础，但还没有形成面向调用方的完整隔离层。

结论：

- 保留 `smx509` 作为底层 SM2-aware X.509 能力包。
- 新增更高层的 `cert` 包作为推荐入口。
- `http`、`tlcp`、`tls13`、`quic`、`quicgm` 后续逐步接入 `cert` 包。

不建议命名为 `x509`，避免和标准库 `crypto/x509` 冲突。

## 2. 目标

新增 `cert` 包，提供统一证书解析、加载、证书池、验证、TLS/TLCP 配置适配能力。

调用方目标体验：

```go
roots := cert.NewPool()
if !roots.AppendCertsFromPEM(rootPEM) {
    return errors.New("no roots")
}

leaf, err := cert.ParseCertificatePEM(certPEM)
if err != nil {
    return err
}

if err := cert.VerifyCertificate(leaf, cert.VerifyOptions{
    Roots:   roots,
    DNSName: "example.com",
}); err != nil {
    return err
}
```

TLCP 双证书目标体验：

```go
pair, err := cert.LoadDualCertificatePEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM)
if err != nil {
    return err
}

cfg, err := cert.BuildTLCPConfig(cert.TLCPConfigOptions{
    Certificates: pair,
    SignRoots:    roots,
    EncRoots:     roots,
})
```

调用方不需要自己判断：

- 用 `x509.ParseCertificate` 还是 `gmsm/smx509.ParseCertificate`
- root pool 是否能转换
- 是否需要保存 raw DER
- SM2 fallback 怎么处理
- 自签 leaf 是否能信任
- TLCP sign/enc 证书怎么分别验证

## 3. 非目标

本计划不做：

1. 不替换标准库 `crypto/x509` 类型。
2. 不发明新的证书格式。
3. 不把 SM2 证书强行塞进 Go 标准 TLS 传输层并宣称 RFC8998。
4. 不改变 `smx509` 现有 API 的兼容性。
5. 不默认信任自签 leaf。
6. 不在没有 roots 时静默切换为系统池或 leaf-as-root。

## 4. 包结构

新增：

```text
cert/
  doc.go
  cert.go
  pool.go
  verify.go
  load.go
  tls.go
  tlcp.go
  errors.go
```

测试：

```text
cert/
  cert_test.go
  pool_test.go
  verify_test.go
  load_test.go
  tls_test.go
  tlcp_test.go

test/
  cert_blackbox_test.go
  cert_tlcp_blackbox_test.go
```

## 5. API 设计

### 5.1 证书类型

对外继续使用标准类型：

```go
*x509.Certificate
tls.Certificate
*x509.CertificateRequest
```

原因：

- 与 Go 生态兼容。
- 避免调用方被迫重写已有 TLS/HTTP 逻辑。
- SM2 差异由 `cert`/`smx509` 内部处理。

可选新增轻量元信息：

```go
type Kind int

const (
    KindUnknown Kind = iota
    KindStandard
    KindSM2
)

func DetectKind(cert *x509.Certificate) Kind
func IsSM2Certificate(cert *x509.Certificate) bool
```

### 5.2 Pool

```go
type Pool struct {
    // internal: parsed certs + raw DER
}

func NewPool() *Pool
func NewPoolFromCerts(certs ...*x509.Certificate) *Pool
func (p *Pool) AddCert(cert *x509.Certificate)
func (p *Pool) AppendCertsFromPEM(pemData []byte) bool
func (p *Pool) Certificates() []*x509.Certificate
func (p *Pool) RawDER() [][]byte
func (p *Pool) Len() int
func (p *Pool) ToStandardPool() *x509.CertPool
func (p *Pool) ToSMX509Pool() (*smx509.CertPool, error)
```

实现规则：

- `AddCert` 必须复制 `cert.Raw`。
- `RawDER` 必须返回深拷贝。
- `Certificates` 返回 slice 拷贝。
- 不从 `x509.CertPool.Subjects()` 反推证书。
- `AppendCertsFromPEM` 使用统一 `cert.ParseCertificate`。

与已有 `smx509.CertPool` 的关系：

- 第一阶段可以让 `cert.Pool` 包装 `smx509.CertPool`。
- 第二阶段可考虑将 `smx509.CertPool` 作为兼容 alias 或底层实现。
- 不在一个 PR 里大规模迁移所有调用方。

### 5.3 解析和加载

```go
func ParseCertificate(der []byte) (*x509.Certificate, error)
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error)
func ParseCertificatesPEM(pemData []byte) ([]*x509.Certificate, error)

func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error)
func ParseCertificateRequestPEM(pemData []byte) (*x509.CertificateRequest, error)

func LoadKeyPairPEM(certPEM, keyPEM []byte) (tls.Certificate, error)
func LoadKeyPairFiles(certFile, keyFile string) (tls.Certificate, error)
```

实现规则：

- 证书解析优先走 `smx509.ParseCertificate` 的统一 wrapper。
- 私钥解析支持标准 RSA/ECDSA/Ed25519 和 SM2。
- PEM 类型错误必须返回明确错误。
- 加密私钥解密使用 `smx509.DecryptPEMPrivateKeyDER` 或后续统一 key loader。

### 5.4 验证

```go
type VerifyOptions struct {
    DNSName       string
    Roots         *Pool
    Intermediates *Pool
    KeyUsages     []x509.ExtKeyUsage
    CurrentTime   time.Time
}

func VerifyCertificate(cert *x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error)
func VerifyChain(certs []*x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error)
```

语义：

- 自动识别标准证书和 SM2 证书。
- 标准证书优先使用 `crypto/x509`。
- SM2 证书使用 `gmsm/smx509` 验证。
- roots/intermediates 统一从 `Pool` 转换。
- 不允许 leaf-as-root fallback。
- nil roots 的策略必须显式：
  - 默认：不自动信任 leaf。
  - 是否使用系统 roots 通过 `UseSystemRoots bool` 单独表达。

建议：

```go
type TrustPolicy int

const (
    TrustExplicitRoots TrustPolicy = iota
    TrustSystemRoots
)
```

不要用 nil roots 同时表达“没配置”和“使用系统 root”。

### 5.5 双证书

```go
type DualCertificate struct {
    Sign tls.Certificate
    Enc  tls.Certificate
}

func LoadDualCertificatePEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM []byte) (*DualCertificate, error)
func LoadDualCertificateFiles(signCertFile, signKeyFile, encCertFile, encKeyFile string) (*DualCertificate, error)

type DualVerifyOptions struct {
    SignRoots *Pool
    EncRoots  *Pool
    DNSName   string
}

func VerifyDualCertificate(pair *DualCertificate, opts DualVerifyOptions) error
```

验证规则：

- sign cert 必须有 `KeyUsageDigitalSignature`。
- enc cert 必须有 `KeyUsageKeyEncipherment` 或 `KeyUsageDataEncipherment`。
- 两张证书 issuer 应符合 TLCP 双证书策略。
- roots 不得为空时悄悄信任 leaf。
- 错 CA、错 KeyUsage、过期、不在有效期内均失败。

### 5.6 TLS/TLCP 适配

标准 TLS/TLS1.3：

```go
type TLSConfigOptions struct {
    Certificates []tls.Certificate
    Roots        *Pool
    ClientCAs    *Pool
    ClientAuth   tls.ClientAuthType
    NextProtos   []string
}

func BuildClientTLSConfig(opts TLSConfigOptions) (*tls.Config, error)
func BuildServerTLSConfig(opts TLSConfigOptions) (*tls.Config, error)
```

TLCP：

```go
type TLCPConfigOptions struct {
    Certificates *DualCertificate
    SignRoots    *Pool
    EncRoots     *Pool
    CipherSuites []uint16
    ServerName   string
}

func BuildTLCPConfig(opts TLCPConfigOptions) (*tlcp.Config, error)
```

实现规则：

- TLS builder 只生成标准 `crypto/tls.Config`。
- TLCP builder 生成 `tlcp.Config`，同时填充：
  - `SignCertificate`
  - `EncCertificate`
  - `SignRootCAs`
  - `EncRootCAs`
  - `SignRootCertificates`
  - `EncRootCertificates`
- 不在 `cert` 包内 import `http` 或 `quic`，避免循环和过宽职责。

## 6. 分阶段实施

### C0：状态同步

任务：

1. 更新 `docs/plan/audit-status-matrix.md`，确认当前 `go test ./...` 已通过。
2. 标记 `smx509.CertPool` 已存在。
3. 将证书隔离层加入 `implementation-master-plan.md` 的 M2/M5 之间。

验收：

```text
go test ./...
```

### C1：新增 `cert.Pool`

任务：

1. 新增 `cert` 包。
2. 实现 `Pool` 和 PEM 追加。
3. 实现 `ToStandardPool`、`ToSMX509Pool`。
4. 增加并发安全或明确非并发安全；建议并发安全。

测试：

```text
go test ./cert -run 'Pool'
go test ./test -run 'Cert.*Pool'
```

完成定义：

- raw DER 不丢失。
- 返回值不暴露内部 slice。
- SM2 root 可转换到 gmsm cert pool。

### C2：解析和加载

任务：

1. `ParseCertificate`、`ParseCertificatePEM`。
2. `ParseCertificatesPEM`。
3. `LoadKeyPairPEM`。
4. `LoadDualCertificatePEM`。

测试：

```text
go test ./cert -run 'Parse|Load'
go test ./test -run 'Cert.*Parse|Cert.*Load'
```

完成定义：

- RSA/ECDSA/SM2 证书都可解析。
- invalid PEM/DER 返回错误。
- TLCP 双证书可加载。

### C3：统一验证

任务：

1. `VerifyCertificate`。
2. `VerifyChain`。
3. 显式 `TrustPolicy`。
4. `VerifyDualCertificate`。

测试：

```text
go test ./cert ./smx509 ./test -run 'Verify|Cert|X509'
```

完成定义：

- 正确 root 成功。
- 错误 root 失败。
- nil roots 策略明确。
- leaf-as-root 被拒绝。
- SM2 证书链验证不依赖 `x509.CertPool.Subjects()`。

### C4：TLS/TLCP 配置适配

任务：

1. `BuildClientTLSConfig`。
2. `BuildServerTLSConfig`。
3. `BuildTLCPConfig`。
4. 修正 `http/tls13.go` 中 `ClientCAs`、`RootCAs` 类型，改为 `*x509.CertPool` 或后续 `*cert.Pool`。
5. 让 `tlcp.Config.LoadRootCAsFromPEM` 内部逐步复用 `cert.Pool`。

测试：

```text
go test ./cert ./http ./tlcp ./test -run 'TLS|TLCP|HTTP|Cert'
```

完成定义：

- 标准 TLS 使用标准 root pool。
- TLCP 同时获得标准 pool 和 raw root cert slice。
- HTTP/TLS13 不丢失 RootCAs/ClientCAs。

### C5：迁移调用方

迁移顺序：

1. `tlcp` root CA 加载逻辑。
2. `http` TLS/TLCP 配置构建。
3. `tls13` 可选新增 `cert.Pool` 适配 helper，不改变核心 API。
4. `quic` 继续依赖 `tls13`，必要时新增 cert-aware helper。
5. `quicgm` 的 SM2 identity 验证接入 `cert.VerifyCertificate`。

原则：

- 旧 API 保留。
- 新 API 作为推荐入口。
- 文档标记旧路径为 lower-level。

## 7. 黑盒测试计划

新增测试文件：

```text
test/cert_blackbox_test.go
test/cert_tlcp_blackbox_test.go
```

用例：

| 测试名 | 行为 |
|--------|------|
| `TestBlackBox_Cert_ParseCertificate_StandardAndSM2` | 标准和 SM2 证书均可解析 |
| `TestBlackBox_Cert_Pool_RawDERRoundTrip` | root raw DER 不丢失 |
| `TestBlackBox_Cert_Verify_WithCorrectRoot` | 正确 root 验证成功 |
| `TestBlackBox_Cert_Verify_WithWrongRoot` | 错 root 失败 |
| `TestBlackBox_Cert_Verify_LeafAsRootRejected` | leaf-as-root 失败 |
| `TestBlackBox_Cert_Verify_NilRootsPolicyExplicit` | nil roots 行为明确 |
| `TestBlackBox_Cert_LoadKeyPairPEM_SM2` | SM2 cert/key 可加载为 tls.Certificate |
| `TestBlackBox_Cert_LoadDualCertificatePEM` | TLCP 双证书加载成功 |
| `TestBlackBox_Cert_VerifyDualCertificate_KeyUsageRejected` | 错 KeyUsage 失败 |
| `TestBlackBox_Cert_BuildTLCPConfig_PopulatesRootCertificates` | TLCP root pool 和 raw certs 都被填充 |

发布前命令：

```text
go test ./cert ./smx509 ./tlcp ./http ./test -run 'Cert|X509|TLCP|HTTP'
go test ./...
```

## 8. 文档更新

需要更新：

| 文档 | 改动 |
|------|------|
| `docs/plan/implementation-master-plan.md` | 增加 cert 隔离层里程碑 |
| `docs/plan/test-blackbox-api-implementation-plan.md` | 增加 cert 黑盒测试矩阵 |
| `docs/plan/quic-tls13-gm-roadmap.md` | 将 SMX509 重构扩展为 cert facade + smx509 backend |
| `README.md` | 推荐调用方使用 `cert` 包 |
| `smx509` package doc | 标记为底层 SM2-aware X.509 backend/helper |

## 9. 风险

| 风险 | 处理 |
|------|------|
| 抽象层过宽，变成第二套 x509 | 对外保留标准类型，只封装解析/验证/池/加载 |
| 循环依赖 | `cert` 可 import `tlcp`，但不得 import `http`、`quic`；`tlcp` 迁移需避免反向 import |
| 破坏现有调用方 | 旧 API 保留，新 API 推荐 |
| root 策略再次变模糊 | 引入显式 `TrustPolicy`，nil roots 不表达多种含义 |
| SM2 与 ECDSA P-256 误判 | 后续结合证书算法 OID，不只看曲线对象 |

## 10. 当前下一步

1. 创建 `cert` 包和 `Pool`。
2. 复用现有 `smx509.CertPool` 的实现经验，但不要直接暴露底层 backend。
3. 补 `test/cert_blackbox_test.go` 中 root pool、leaf-as-root、SM2 parse 用例。
4. 修正 `http/tls13.go` 中 RootCAs/ClientCAs 类型与透传问题。
5. 更新 `implementation-master-plan.md`，将 cert 隔离层放在 TLS/HTTP/QUIC 进一步扩展前。

