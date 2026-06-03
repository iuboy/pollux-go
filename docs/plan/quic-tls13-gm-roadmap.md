# pollux-go QUIC、TLS 1.3 与国密能力补全方案

## 0. 方案定位

本文为 pollux-go 增补 QUIC、TLS 1.3 与国密相关能力的完整计划，同时记录当前项目中已经观察到的设计问题、实现问题、测试基线问题和修复优先级。

pollux-go 当前定位是 Go 风格的国密算法与协议封装库，已有模块包括：

- `sm2`：SM2 签名、加密、密钥交换辅助。
- `sm3`：SM3 hash、HMAC、KDF/HKDF。
- `sm4`：SM4 block cipher、GCM/CBC/CTR/CFB 等模式辅助。
- `smx509`：SM2-aware X.509 解析、CSR、证书链相关辅助。
- `tlcp`：TLCP 1.1 协议实现。
- `tls`：国密/TLS cipher suite ID 与名称管理。
- `http`：TLS/TLCP HTTP server/client 辅助。
- `gmstd`、`sm9`、`zuc`：其他国密算法辅助。

本方案的核心判断：

1. QUIC 传输必须基于 TLS 1.3，不能直接复用 TLCP 1.1。
2. `tls` 包中登记国密套件 ID，不等于 Go `crypto/tls` 或 quic-go 已支持 RFC 8998。
3. pollux-go 可以优先提供“QUIC + 标准 TLS 1.3 + 应用层国密安全层”的生产可用路径。
4. “QUIC + RFC 8998 TLS 1.3 国密套件”应作为长期研究/实验路径，单独隔离，不应与生产 API 混淆。

## 1. 当前状态摘要

### 1.1 当前包能力

| 模块 | 当前能力 | 适合进入 QUIC/TLS1.3 计划的程度 |
|------|----------|--------------------------------|
| `sm2` | SM2 key/sign/encrypt，PEM 辅助，压缩点 | 适合作应用层身份、签名、证书能力基础 |
| `sm3` | SM3、HMAC-SM3、HKDF-SM3 | 适合作 HMAC、KDF、未来 RFC 8998 研究基础 |
| `sm4` | SM4 block，GCM/CBC/CTR/CFB helper | 只建议使用 `NewCipher`/`NewGCM`，避免高层模式误用 |
| `smx509` | SM2-aware X.509 解析和验证辅助 | 需要先修复 Roots/验证路径问题 |
| `tlcp` | TLCP 1.1 自研握手、记录层 | 不适合直接用于 QUIC；需先完成安全修复再声称生产可用 |
| `tls` | 国密套件 ID 注册、命名 | 需要改名或文档澄清，避免误导为可用 TLS1.3 国密实现 |
| `http` | TLS/TLCP HTTP helper，hybrid listener | 需要安全收敛；不适合作 QUIC 基础 |

### 1.2 当前测试基线

在 `pollux-go` 根目录执行：

```text
go test ./...
```

当前结果：

- 多数包测试通过。
- `github.com/ycq/pollux/test` 失败，集中在 SM9 Wrap/Unwrap：
  - `TestBlackBox_SM9_WrapUnwrapKey`
  - `TestBlackBox_SM9_WrapKeyASN1`
  - `TestBlackBox_SM9_WrapKey_DifferentKeyLengths`

失败现象：

```text
wrapped key length: got 65, want 32
UnwrapKey: sm9: decryption error
```

这不是 QUIC/TLS1.3 主路径问题，但它说明项目当前没有绿色测试基线。任何新增 QUIC/TLS1.3 计划前，都应先把测试基线恢复到可发布状态，或显式隔离 SM9 失败测试。

### 1.3 审计报告状态

`AUDIT_REPORT.md` 记录了大量 CRITICAL/HIGH 问题。源码显示其中部分问题已经被修复或缓解，例如：

- TLCP 客户端已检查 ServerHello 版本。
- TLCP ECDHE ServerKeyExchange 已增加签名验证逻辑。
- TLCP CBC IV 已在加密/解密后链式更新。
- SM3 HKDF 当前已使用 `NewHMAC`。
- SM2 `BytesToPrivateKey` 当前已检查私钥标量范围。

但仍应保留审计报告作为安全 backlog。需要补一个“审计项状态矩阵”，标记：

- still open
- fixed
- partially fixed
- needs regression test
- not applicable

没有回归测试覆盖的修复，不应视为完成。

## 2. 当前设计问题

### 2.1 TLCP、TLS 1.3、RFC 8998 概念混用

当前 `tlcp/tlcp.go` 注释把 TLCP 描述为：

```text
GB/T 38636-2020 / RFC 8998
```

这在设计上容易误导。TLCP/GB/T 38636 和 RFC 8998 TLS 1.3 国密套件不是同一个协议层：

- TLCP 是独立传输层密码协议，通常与 TLS 1.2 族更接近。
- RFC 8998 是 TLS 1.3 中的 SM2/SM3/SM4 套件定义。
- QUIC 使用 TLS 1.3 handshake 和 QUIC packet protection，不能直接套 TLCP 记录层。

计划要求：

- 文档中明确区分 `tlcp`、`tls13gm`、`quic` 三条路线。
- 不再把 TLCP 注释写成 RFC 8998 的等价实现。

### 2.2 `tls` 包命名过宽

当前 `tls` 包提供 cipher suite ID 管理，但包名和注释容易让使用者误认为它提供完整 TLS 国密实现。

问题：

- `GetCipherSuites(CryptoModeNational)` 返回的国密 suite ID 不能直接塞进 Go `crypto/tls` 后得到可用 TLS1.3 国密连接。
- TLS 1.3 的 cipher suite 配置方式与 TLS 1.2 不同。
- RFC 8998 不只是 cipher suite ID，还包括 transcript hash、HKDF、签名算法、曲线、证书链和 QUIC packet protection。

计划要求：

- 保留兼容 API，但文档标注“suite registry only”。
- 新增更明确的包或子包：`tlsgm/registry`、`tls13gm`、`quicgm`。

### 2.3 HTTP hybrid listener 安全边界弱

`http/listener.go` 通过 TLS record header 的 version 字段判断 TLS/TLCP：

```text
0x0101 -> TLCP
其他 -> TLS
```

问题：

- 记录头可被伪造。
- `Accept` 中同步握手，慢客户端可占用 accept loop。
- fallback 到 TLS 路径可能导致策略绕过。
- hybrid 模式对生产系统的安全审计复杂。

计划要求：

- hybrid listener 默认禁用或标记 experimental。
- 加入 handshake timeout。
- 明确配置允许的协议集合，不能由客户端单字节自由决定安全策略。
- 增加 fuzz 和慢握手测试。

### 2.4 TLCP 当前仍不应作为生产可用基础

即便部分审计问题已修复，TLCP 模块仍需要系统性回归测试：

- 握手 transcript。
- ServerKeyExchange 签名输入。
- ECC/ECDHE 分支。
- Finished verify_data。
- 证书链验证。
- GCM nonce/sequence。
- CBC MAC 和 padding。
- alert 行为。
- downgrade 防护。

在完成这些前，不应在 README/API 文档中声称 TLCP 可安全暴露在不可信网络。

### 2.5 SMX509 验证抽象不够可靠

当前 `smx509.Verify` 试图在标准 x509 和 gmsm/smx509 之间自动 fallback，但 Roots 转换曾被审计指出为空池问题。

设计问题：

- 标准 `x509.CertPool` 无法可靠枚举原始证书 DER。
- fallback 如果不带真实 root，会导致验证语义变化。
- “自动识别 SM2”不能以牺牲信任链确定性为代价。

计划要求：

- 新增 pollux 自己的 `CertPool` 抽象，保存原始 DER 和 parsed cert。
- 明确区分 standard x509 pool 和 SMX509 pool。
- 验证 API 不得在没有 roots 时悄悄改为系统/自签策略。

### 2.6 SM4 模式 API 过宽

当前 `sm4` 暴露 ECB/CBC/CTR/CFB/GCM 高层 `Encrypt/Decrypt`。

问题：

- ECB 不应作为常规可用模式暴露。
- CBC padding oracle 风险需要文档和常量时间处理。
- GCM nonce 复用是灾难性错误，helper API 不能鼓励隐式 nonce。
- `Encrypt(..., ModeGCM, nil)` 这种接口容易导致调用者误解 nonce 管理。

计划要求：

- 新增安全推荐 API：`gcm.Seal/Open` 或 `sm4gcm` 子包。
- 弱/危险模式标记 deprecated 或移入 `insecure`/`legacy`。
- 强制调用方显式传入 nonce，或返回 `nonce+ciphertext` 的结构体。

## 3. 当前实现问题清单

### 3.1 必须修复或确认的现有问题

| 优先级 | 问题 | 文件/模块 | 当前影响 | 计划 |
|--------|------|-----------|----------|------|
| P0 | `go test ./...` 失败 | `test/sm9_test.go` / `sm9` | 项目没有绿色基线 | 先修复 API/测试语义或隔离失败 |
| P0 | TLCP 与 RFC8998 文档混淆 | `tlcp/tlcp.go` | 用户误用 | 修正文档和包边界 |
| P0 | SMX509 roots 验证语义不清 | `smx509/verify.go` | 证书链信任风险 | 新 CertPool/Verifier |
| P0 | HTTP hybrid listener 弱检测 | `http/listener.go` | 降级/DoS 风险 | 默认 experimental + timeout + fuzz |
| P1 | TLS config 默认 `MinVersion=tls.VersionTLS12` | `http/config.go` | TLS1.3 计划不明确 | 新增 TLS13 config builder |
| P1 | 国密 suite registry 易被误用 | `tls/cipher_suite.go` | 用户以为可直接启用 TLS1.3 国密 | 包文档和 API 重命名/拆分 |
| P1 | SM4 高层模式 API 过宽 | `sm4/modes.go` | 易误用 | 安全 API 和 deprecated 策略 |
| P1 | TLCP 回归覆盖不足 | `tlcp/*` | 修复不可证明 | 增加 transcript/fuzz/interop |

### 3.2 已观察到可能已修复但仍需测试固化的问题

| 审计项 | 当前观察 | 仍需动作 |
|--------|----------|----------|
| TLCP SKE 签名未验证 | 当前代码已有验证逻辑 | 增加篡改签名单测 |
| TLCP 全零 PMS | 当前 nil PMS 分支使用随机值 | 增加解密失败常量时间/随机 PMS 测试 |
| TLCP CBC IV 固定 | 当前加解密后更新 IV | 增加连续记录密文差异测试 |
| SM3 HKDF 手写 HMAC | 当前已使用 `NewHMAC` | 增加 RFC5869/SM3 向量 |
| SM2 私钥范围 | 当前已校验 `0 < d < n` | 增加 0/n/n+1 测试 |
| SM4 GCM nonce 返回 | 高层 `encryptGCM` 当前拼接 nonce | 明确线格式，避免调用者混淆 |

## 4. 目标架构

### 4.1 包结构建议

新增或调整为：

```text
quic/           // QUIC over standard TLS 1.3, production path
quicgm/         // QUIC + application-layer GM profile helpers
tls13/          // standard TLS 1.3 config builders
tls13gm/        // RFC 8998 research/experimental interfaces
tlsregistry/    // cipher suite IDs and names only
sm4gcm/         // safe SM4-GCM AEAD helpers
smx509/         // strengthened SM2-aware cert verification
tlcp/           // TLCP 1.1, after security hardening
http/           // HTTP over TLS/TLCP, conservative defaults
internal/testutil/
```

为了兼容，现有 `tls` 包可以保留，但需要明确文档：

```text
Package tls contains cipher suite registry helpers. It does not implement TLS 1.3 GM handshakes.
```

### 4.2 三条传输/安全路线

#### 路线 A：QUIC + 标准 TLS 1.3

生产主路径：

```text
quic-go
  -> crypto/tls TLS 1.3
  -> ALPN
  -> standard certificates RSA/ECDSA/Ed25519
```

pollux-go 提供：

- QUIC config builder。
- TLS1.3 安全默认值。
- certificate loading helpers。
- metrics/debug hooks。

#### 路线 B：QUIC + 标准 TLS 1.3 + 应用层国密 Profile

近期可交付主路径：

```text
QUIC TLS 1.3 transport security
+ application profile:
  - SM2 cert auth at application/session layer
  - HMAC-SM3
  - SM4-GCM payload encryption
  - SM3-HKDF optional key schedule
```

这条路线适合给上层协议使用，例如 MBTA。

#### 路线 C：QUIC + RFC 8998 TLS 1.3 国密套件

长期实验路径：

```text
TLS_SM4_GCM_SM3
SM3 transcript hash
HKDF-SM3
SM2 signature scheme
curveSM2
QUIC packet protection with SM4-GCM
```

这不是简单配置 cipher suite 能完成的功能，需要 TLS 和 QUIC handshake/packet protection 深度支持。

## 5. QUIC 设计方案

### 5.1 新增 `quic` 包定位

`quic` 包提供标准 QUIC/TLS1.3 的安全配置和连接封装，不提供国密 TLS1.3 传输层。

建议 API：

```go
package quic

type ServerConfig struct {
    Addr               string
    Certificates       []tls.Certificate
    ClientCAs          *x509.CertPool
    ClientAuth         tls.ClientAuthType
    NextProtos         []string
    MinTLSVersion      uint16
    MaxIdleTimeout     time.Duration
    MaxIncomingStreams int64
}

type ClientConfig struct {
    Addr               string
    ServerName         string
    RootCAs            *x509.CertPool
    Certificates       []tls.Certificate
    NextProtos         []string
    InsecureSkipVerify bool
    MinTLSVersion      uint16
    MaxIdleTimeout     time.Duration
}

func BuildServerTLSConfig(cfg ServerConfig) (*tls.Config, error)
func BuildClientTLSConfig(cfg ClientConfig) (*tls.Config, error)
func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error)
func Dial(ctx context.Context, cfg ClientConfig) (*Conn, error)
```

默认值：

- `MinTLSVersion = tls.VersionTLS13`
- `NextProtos` 必须非空
- `InsecureSkipVerify=false`
- server 必须提供证书

### 5.2 ALPN 策略

QUIC 必须配置 ALPN。pollux-go 不应提供“空 ALPN 也可连接”的便利 API。

规则：

- Server `NextProtos` 为空时报错。
- Client `NextProtos` 为空时报错。
- 提供 helper：

```go
func SingleALPN(proto string) []string
```

### 5.3 mTLS 支持

QUIC server 应直接使用 Go `tls.ClientAuthType`：

- `tls.NoClientCert`
- `tls.RequestClientCert`
- `tls.RequireAnyClientCert`
- `tls.VerifyClientCertIfGiven`
- `tls.RequireAndVerifyClientCert`

不要复用 `tlcp.ClientAuthType`，避免跨协议枚举混淆。

### 5.4 QUIC 与 TLCP 的边界

`quic` 包不得 import：

```go
github.com/ycq/pollux/tlcp
```

`quic` 包可以 import：

```go
crypto/tls
github.com/quic-go/quic-go
```

### 5.5 测试

必须覆盖：

- TLS1.3 成功握手。
- ALPN mismatch 失败。
- server cert 不可信失败。
- ServerName mismatch 失败。
- mTLS required 成功/失败。
- `InsecureSkipVerify` 默认 false。
- 空 ALPN 拒绝。
- 不引用 TLCP 包的静态检查。

## 6. TLS 1.3 设计方案

### 6.1 新增 `tls13` 包

`tls13` 只负责标准 Go TLS1.3 配置，不负责国密 TLS1.3。

建议 API：

```go
package tls13

type ServerOptions struct {
    Certificates []tls.Certificate
    ClientCAs    *x509.CertPool
    ClientAuth   tls.ClientAuthType
    NextProtos   []string
}

type ClientOptions struct {
    ServerName         string
    RootCAs            *x509.CertPool
    Certificates       []tls.Certificate
    NextProtos         []string
    InsecureSkipVerify bool
}

func ServerConfig(opts ServerOptions) (*tls.Config, error)
func ClientConfig(opts ClientOptions) (*tls.Config, error)
```

强制：

- `MinVersion = tls.VersionTLS13`
- 不允许 TLS1.2 cipher suite 参数混入 TLS1.3 builder。
- `InsecureSkipVerify` 使用时返回带类型的 warning/error，生产 profile 可直接禁止。

### 6.2 现有 HTTP TLS config 调整

当前 `http/config.go` 标准 TLS 构建为：

```go
MinVersion: tls.VersionTLS12
```

计划：

- 保留现有行为作为 legacy。
- 新增 `TLSMinVersion` 字段。
- 新增 `ModeTLS13` 或 `RequireTLS13 bool`。
- 新的 secure default 使用 TLS1.3。
- HTTP/2 行为需要明确，不能在 TLCP 路径启用。

### 6.3 TLS suite registry 重构

当前 `tls` 包改为 registry 定位：

建议：

```text
tls/            // 兼容保留，文档降级为 registry
tlsregistry/    // 新包，后续迁移目标
tls13/          // 标准 TLS1.3 config builder
tls13gm/        // experimental RFC8998 model
```

`tlsregistry` 提供：

- cipher suite IDs。
- names。
- `IsNationalCipherSuite`。
- `IsTLS13GMSuite`。
- `IsTLCPSuite`。

明确：

- registry 不执行握手。
- registry 不保证 Go `crypto/tls` 支持该 suite。

## 7. TLS 1.3 国密 / RFC 8998 设计方案

### 7.1 新增 `tls13gm` experimental 包

`tls13gm` 初期不实现完整 TLS handshake，而是沉淀模型、常量、测试向量和可替换接口。

包状态：

```go
// Package tls13gm is experimental and does not provide production TLS handshakes.
```

### 7.2 RFC 8998 组成

完整支持需要：

| 组件 | 标准 TLS1.3 | RFC 8998 国密 |
|------|-------------|---------------|
| CipherSuite | TLS_AES_128_GCM_SHA256 | TLS_SM4_GCM_SM3 |
| Transcript Hash | SHA-256/SHA-384 | SM3 |
| HKDF | HKDF-SHA256/SHA384 | HKDF-SM3 |
| Signature | ECDSA/RSA-PSS/Ed25519 | SM2-SM3 |
| Key Exchange | X25519/P-256 | curveSM2 |
| AEAD | AES-GCM/ChaCha20 | SM4-GCM |

### 7.3 可先交付的基础件

`tls13gm` Phase 1 可交付：

- `const TLS_SM4_GCM_SM3 uint16 = 0x00C6`
- `const TLS_SM4_CCM_SM3 uint16 = 0x00C7`
- SM3 HKDF wrapper。
- SM4-GCM AEAD wrapper。
- SM2 signature scheme ID registry。
- RFC 8998 测试向量目录。
- 文档说明：不可直接用于 `crypto/tls.Config.CipherSuites`。

### 7.4 完整实现路线

完整路线分三种：

1. Fork Go `crypto/tls`：
   - 工作量最大，维护成本高。
   - 可控性最好。

2. Fork quic-go + 自定义 TLS handshake：
   - QUIC 集成深。
   - 需要维护 packet protection。

3. 等待 Go/社区支持 RFC 8998：
   - 最稳妥。
   - 时间不可控。

短期不建议承诺生产实现。

## 8. 应用层国密 Profile 设计

### 8.1 新增 `quicgm` 包

`quicgm` 不改变 QUIC TLS1.3 传输层，只提供上层协议可复用的应用层国密能力。

能力：

- HMAC-SM3。
- SM4-GCM envelope。
- SM2 certificate identity。
- SM3-HKDF session key derivation。
- nonce registry。
- AAD builder。

### 8.2 API 草案

```go
package quicgm

type Suite struct {
    HMACAlgo string // "sm3"
    AEAD     string // "sm4_gcm"
    Identity string // "sm2_cert"
}

type SessionKeys struct {
    KeyID   string
    HMACKey []byte // 32 bytes
    SM4Key  []byte // 16 bytes
}

type Envelope struct {
    Version    int
    SessionID  string
    KeyID      string
    Nonce      []byte
    AAD        []byte
    Ciphertext []byte
    MAC        []byte
}

func GenerateSessionKeys(rand io.Reader) (SessionKeys, error)
func SealSM4GCM(keys SessionKeys, nonce, plaintext, aad []byte) ([]byte, error)
func OpenSM4GCM(keys SessionKeys, nonce, ciphertext, aad []byte) ([]byte, error)
func MACSM3(key, data []byte) []byte
func VerifyMACSM3(key, data, mac []byte) bool
```

### 8.3 SM4-GCM 约束

- 只允许 96-bit nonce。
- 同一 `key_id` 下 nonce 不得重复。
- API 不允许 nonce 为空。
- AAD 必须显式传入。
- 返回值不隐式拼接 nonce，除非使用结构化结果类型。

### 8.4 SM2 身份认证

提供：

```go
type SM2Identity struct {
    Certificate *x509.Certificate
    PublicKey   *ecdsa.PublicKey
    Subject     pkix.Name
}

type SM2Verifier interface {
    Verify(certPEM []byte, opts VerifyOptions) (*SM2Identity, error)
}
```

实现要求：

- 明确 root pool。
- 不允许 leaf-as-root fallback。
- 支持 KeyUsage/ExtKeyUsage 策略。
- 支持 SAN/Subject 与业务身份绑定。
- 支持 CRL/OCSP 作为可选策略。

## 9. SMX509 重构计划

### 9.1 新 CertPool

新增：

```go
type CertPool struct {
    certs  []*x509.Certificate
    rawDER [][]byte
}

func NewCertPool() *CertPool
func (p *CertPool) AddCert(cert *x509.Certificate)
func (p *CertPool) AppendCertsFromPEM(pem []byte) bool
func (p *CertPool) ToStandardPool() *x509.CertPool
func (p *CertPool) ToSMX509Pool() (*smx509.CertPool, error)
```

重点是保留 raw DER，不能只保存 `x509.CertPool.Subjects()`。

### 9.2 Verify API

新增明确 API：

```go
type VerifyOptions struct {
    DNSName       string
    Roots         *CertPool
    Intermediates *CertPool
    KeyUsages     []x509.ExtKeyUsage
    CurrentTime   time.Time
}

func VerifyCertificate(cert *x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error)
func VerifySM2Certificate(cert *x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error)
```

旧 `Verify` 可以保留，但内部必须调用新实现。

### 9.3 测试

- 正确 root 成功。
- 错误 root 失败。
- nil root 策略明确。
- leaf self-signed 不应自动通过。
- expired/not-yet-valid。
- wrong KeyUsage。
- intermediates chain。

## 10. SM4 API 收敛计划

### 10.1 新 `sm4gcm` 推荐 API

```go
package sm4gcm

const KeySize = 16
const NonceSize = 12

type Sealed struct {
    Nonce      []byte
    Ciphertext []byte
}

func GenerateKey(rand io.Reader) ([]byte, error)
func GenerateNonce(rand io.Reader) ([]byte, error)
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error)
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error)
func SealRandomNonce(rand io.Reader, key, plaintext, aad []byte) (Sealed, error)
```

### 10.2 Deprecated 策略

标记为不推荐：

- `ModeECB`
- `Encrypt(... ModeECB ...)`
- `Encrypt(... ModeCBC ...)` 用于新协议。
- `Encrypt(... ModeGCM, nil)`。

文档中明确：

- GCM nonce must be unique per key。
- CBC requires authenticated encryption construction，不建议新系统使用。
- ECB must not be used for sensitive data。

## 11. TLCP 修复与收敛计划

### 11.1 TLCP P0 修复确认

建立 `docs/security/tlcp-audit-status.md`，逐项确认：

- T-1 SKE signature verification。
- T-2 PMS decrypt failure behavior。
- T-3 CBC IV chaining。
- T-4 CA verification fallback。

每项必须有：

- 修复说明。
- 单元测试。
- 负向测试。
- fuzz/interop 覆盖计划。

### 11.2 禁用 CBC 默认套件

默认 suite 只保留 GCM：

```text
ECDHE_SM2_SM4_GCM_SM3
ECC_SM2_SM4_GCM_SM3
```

CBC 套件保留为 legacy，需要显式启用。

### 11.3 TLCP 状态标记

在修复和互通前：

```go
// Package tlcp is experimental until security audit items are closed.
```

README 中也应明确。

## 12. HTTP 包修复计划

### 12.1 TLS13 profile

新增 HTTP TLS1.3 server/client builder：

```go
func NewTLS13Server(opts ServerOptions) (*http.Server, error)
func NewTLS13Client(opts ClientOptions) (*http.Client, error)
```

默认：

- `MinVersion=tls.VersionTLS13`
- `ClientAuth` 使用标准 `tls.ClientAuthType`
- 不混入 TLCP cipher suites。

### 12.2 Hybrid listener

处理：

- 标记 experimental。
- 增加 handshake timeout。
- 限制 Accept 中同步握手耗时。
- unknown version 直接拒绝，不默认 TLS fallback。
- 增加 fuzz。

## 13. 分阶段路线

### Phase 0：恢复基线

目标：

- `go test ./...` 全绿。
- 审计报告状态矩阵完成。
- 文档澄清 TLCP/TLS1.3/RFC8998 边界。

任务：

1. 修复或隔离 SM9 Wrap/Unwrap 测试失败。
2. 更新 `AUDIT_REPORT.md` 或新增状态矩阵。
3. 修正 `tlcp` 包注释中 TLCP/RFC8998 混淆。
4. 给 `tls` 包加 registry-only 文档。

验收：

- `go test ./...` 通过。
- 所有 CRITICAL 审计项有状态。

### Phase 1：TLS1.3 安全配置基础

目标：

- 提供标准 TLS1.3 config builders。
- HTTP 可选择 TLS1.3 profile。

任务：

1. 新增 `tls13` 包。
2. 服务端/客户端配置 builder。
3. mTLS 测试。
4. ALPN 测试。
5. HTTP TLS1.3 helper。

验收：

- TLS1.3 server/client 互通。
- TLS1.2 不会在 TLS13 builder 中启用。

### Phase 2：QUIC 标准传输

目标：

- 新增 `quic` 包，基于 quic-go。

任务：

1. 增加 `github.com/quic-go/quic-go` 依赖。
2. `quic.ServerConfig` / `quic.ClientConfig`。
3. `Listen` / `Dial`。
4. ALPN 强制。
5. mTLS。
6. stream open/accept helper。

验收：

- QUIC TLS1.3 握手成功。
- ALPN mismatch 失败。
- mTLS required 场景通过/失败符合预期。
- `quic` 包不 import `tlcp`。

### Phase 3：国密安全基础件

目标：

- 提供应用层国密 profile 的安全原语。

任务：

1. 新增 `sm4gcm` 推荐包。
2. 新增 `quicgm` 或 `gmprofile` 包。
3. HMAC-SM3 helper。
4. SM4-GCM nonce/AAD helper。
5. SM3-HKDF wrapper。

验收：

- SM4-GCM AAD 篡改失败。
- nonce 空/长度错误失败。
- HMAC-SM3 使用 `hmac.Equal`。

### Phase 4：SMX509 重构

目标：

- 可信 SM2 证书链验证。

任务：

1. 新 CertPool。
2. roots/intermediates 保留 raw DER。
3. VerifySM2Certificate。
4. KeyUsage/ExtKeyUsage 策略。
5. leaf-as-root 回归测试。

验收：

- 错误 CA 不通过。
- 自签 leaf 不自动通过。
- 正确链通过。

### Phase 5：QUIC + 应用层国密 Profile

目标：

- 提供可被上层协议复用的 QUIC GM profile。

任务：

1. QUIC 标准 TLS1.3 建连。
2. 应用层 SM2 identity。
3. session key generation。
4. SM4-GCM envelope。
5. HMAC-SM3 envelope。
6. 示例 echo 协议。

验收：

- 标准 QUIC TLS1.3 负责传输加密。
- 应用层 payload 通过 SM4-GCM 加密。
- envelope 元数据通过 HMAC-SM3 认证。
- SM2 cert auth 失败不会降级。

### Phase 6：TLS13GM/RFC8998 研究包

目标：

- 明确 RFC8998 模型，但不承诺生产。

任务：

1. `tls13gm` experimental 包。
2. RFC8998 constants。
3. SM3 HKDF test vectors。
4. SM4-GCM AEAD vectors。
5. SM2 signature scheme registry。
6. QUIC packet protection 设计文档。

验收：

- 文档明确不可直接用于 Go `crypto/tls`。
- 不影响生产 `quic` 包。

### Phase 7：TLCP 安全收敛

目标：

- 让 TLCP 从 experimental 逐步接近可用。

任务：

1. 关闭 CRITICAL 审计项。
2. GCM-only 默认。
3. handshake fuzz。
4. record fuzz。
5. interop tests。
6. downgrade tests。

验收：

- 审计 P0/P1 项关闭。
- TLCP 文档不再过度承诺。

## 14. 发布准入

### 14.1 v0.x 内部预览

允许：

- `quic` 标准 TLS1.3。
- `tls13`。
- `sm4gcm`。
- `quicgm` 应用层国密。

不允许：

- 宣称 RFC8998 QUIC 传输层国密已完成。
- 默认启用 hybrid listener。
- 默认启用 CBC。

### 14.2 v1.0 准入

必须：

- `go test ./...` 通过。
- fuzz 无已知 panic。
- TLCP 文档和实际安全状态一致。
- QUIC/TLS1.3 与 TLCP 边界清楚。
- SMX509 链验证可信。
- SM4-GCM nonce 管理有专项测试。
- RFC8998 experimental 标记清晰。

## 15. 风险表

| 风险 | 严重度 | 处理 |
|------|--------|------|
| 把 TLCP 当成 QUIC TLS1.3 国密实现 | 高 | 包边界、文档、代码 import 禁止 |
| 用户误用 `tls` 包 suite ID | 高 | registry-only 文档和新包命名 |
| SMX509 验证绕过 | 高 | 新 CertPool/Verifier |
| SM4-GCM nonce 重用 | 高 | sm4gcm 安全 API + nonce tests |
| HTTP hybrid listener 降级 | 中高 | experimental + timeout + explicit policy |
| TLCP 自研协议复杂 | 高 | 审计、fuzz、interop、GCM-only |
| 当前测试基线失败 | 中 | Phase 0 先恢复 |

## 16. 最终建议

短期优先级：

1. 先恢复 `go test ./...`。
2. 澄清 TLCP、TLS1.3、RFC8998、QUIC 的边界。
3. 新增 `tls13` 和 `quic`，先提供标准 QUIC/TLS1.3 能力。
4. 新增 `sm4gcm` 和 `quicgm`，提供应用层国密 profile。
5. 重构 `smx509` 验证，消除证书信任链歧义。
6. 将完整 RFC8998 QUIC 作为 experimental research，不进入生产承诺。

这条路线能最快形成安全可用的能力：标准 QUIC/TLS1.3 负责传输安全，pollux-go 的 SM2/SM3/SM4 提供应用层国密能力，同时避免把尚未具备完整支持的 RFC8998/TLCP 能力误暴露为生产级 QUIC 国密。
