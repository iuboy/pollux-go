# pollux-go 功能补全实施计划

## 0. 计划定位

本文承接：

- `docs/plan/AUDIT_REPORT.md`
- `docs/plan/quic-tls13-gm-roadmap.md`
- `docs/plan/test-blackbox-completion-plan.md`

目标是把路线图中的 QUIC、TLS 1.3、国密应用层 profile、安全修复和测试基线恢复，拆成可以逐步落地的工程实施计划。

更细的派工级任务拆解、里程碑门禁、文件级改动建议和执行顺序见：

- `docs/plan/implementation-master-plan.md`

当前原则：

1. 先恢复绿色测试基线，再扩展功能。
2. 标准 QUIC/TLS1.3 是近期生产路径。
3. QUIC + RFC 8998 TLS1.3 国密套件是 experimental/research，不进入生产承诺。
4. TLCP 先做安全收敛，不作为 QUIC 基础。
5. 所有新增公开 API 必须同步新增黑盒测试。

## 1. 总体依赖图

```text
Phase 0 基线恢复
  -> Phase 1 审计状态矩阵和文档边界
  -> Phase 2 TLS1.3 config builder
  -> Phase 3 HTTP TLS1.3 profile
  -> Phase 4 QUIC 标准传输
  -> Phase 5 SM4-GCM 安全 API
  -> Phase 6 QUICGM 应用层国密 profile
  -> Phase 7 SMX509 验证重构
  -> Phase 8 TLCP 安全收敛
  -> Phase 9 TLS13GM/RFC8998 experimental
```

Phase 7 和 Phase 8 可与 Phase 4/5 并行推进，但不能阻塞标准 QUIC/TLS1.3 路线。

## 2. Phase 0：恢复绿色基线

目标：

- `go test ./...` 通过。
- 公开 API 注释、实现和黑盒测试一致。

任务：

1. 修复 `sm9.WrapKey` 返回语义：
   - 方案 A：保持公开签名 `(cipher, key, err)`，在 wrapper 内交换底层返回值。
   - 方案 B：承认底层顺序 `(key, cipher, err)`，修改公开注释和黑盒测试。
   - 推荐方案 A，因为当前公开注释和调用者直觉都是“先密文、后密钥”。
2. 明确 `WrapKeyASN1` 的解封装 API：
   - 若公开 wrapper 只支持 raw `UnwrapKey`，则新增 `UnwrapKeyASN1`。
   - 若直接使用 gmsm 方法，黑盒测试必须明确 ASN.1 格式路径。
3. 增加 SM9 raw/ASN.1 格式混用失败测试。
4. 运行：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

验收：

- `github.com/ycq/pollux/test` 不再失败。
- SM9 包内测试和黑盒测试对返回值顺序没有冲突。

## 3. Phase 1：审计状态矩阵和文档边界

目标：

- 把审计报告从问题清单变成可关闭 backlog。
- 消除 TLCP、TLS1.3、RFC8998、QUIC 概念混用。

任务：

1. 新增 `docs/security/tlcp-audit-status.md` 或在 `docs/plan` 下新增审计状态矩阵。
2. 每个审计项标记：
   - `open`
   - `fixed`
   - `partially fixed`
   - `needs regression test`
   - `not applicable`
3. 修正 `tlcp` 包文档：
   - TLCP/GB/T 38636 不等同于 RFC 8998。
   - TLCP 当前在 P0/P1 审计关闭前标记为 experimental。
4. 修正 `tls` 包文档：
   - 当前是 cipher suite registry，不是完整 TLS 国密实现。
5. 为已经修复但缺测试的审计项建立测试任务。

验收：

- 所有 CRITICAL 审计项有状态、负责人字段或待办说明。
- 文档中不再暗示 TLCP 可直接作为 QUIC TLS1.3 国密实现。

## 4. Phase 2：标准 TLS1.3 配置包

目标：

- 新增标准 TLS1.3 配置 builder，作为 HTTP 和 QUIC 的共同基础。

新增包：

```text
tls13/
```

建议 API：

```go
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

实施要求：

- 强制 `MinVersion = tls.VersionTLS13`。
- Server 证书不能为空。
- Client 默认 `InsecureSkipVerify=false`。
- ALPN 是否必填由上层决定；QUIC 层必须必填。
- 不暴露 TLS1.2 cipher suite 配置入口。

测试：

- ServerConfig 空证书失败。
- ClientConfig 默认不跳过证书验证。
- mTLS roots/client cert 配置正确写入。
- MinVersion 固定为 TLS1.3。

验收：

```text
go test ./tls13
go test ./...
```

## 5. Phase 3：HTTP TLS1.3 profile

目标：

- 在现有 HTTP helper 上提供标准 TLS1.3 安全配置。
- 保留 legacy TLS/TLCP 行为但不扩大默认信任边界。

任务：

1. 新增 HTTP TLS1.3 server/client builder。
2. `http/config.go` 增加 TLS 最低版本或明确 profile 字段。
3. `ModeTLS` legacy 行为保持兼容。
4. 新 profile 不混入 TLCP cipher suites。
5. `InsecureSkipVerify` 在测试中显式使用，在生产文档中标记风险。

测试：

- TLS1.3 HTTP round trip。
- TLS1.2-only peer 连接失败。
- server cert 不可信失败。
- ServerName mismatch 失败。
- mTLS required 成功/失败。

验收：

```text
go test ./http ./test -run 'TLS13|HTTP'
```

## 6. Phase 4：QUIC 标准传输

目标：

- 新增 `quic` 包，基于标准 `crypto/tls` TLS1.3 和 `quic-go`。
- 不导入、不复用 TLCP。

新增依赖：

```text
github.com/quic-go/quic-go
```

新增包：

```text
quic/
```

建议 API：

```go
type ServerConfig struct {
    Addr               string
    Certificates       []tls.Certificate
    ClientCAs          *x509.CertPool
    ClientAuth         tls.ClientAuthType
    NextProtos         []string
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
    MaxIdleTimeout     time.Duration
}

func Listen(ctx context.Context, cfg ServerConfig) (*Listener, error)
func Dial(ctx context.Context, cfg ClientConfig) (*Conn, error)
```

实施要求：

- 强制 ALPN 非空。
- 强制 TLS1.3。
- 默认不跳过证书验证。
- `quic` 包不得 import `github.com/ycq/pollux/tlcp`。
- 提供最小 stream open/accept helper。

测试：

- QUIC echo round trip。
- ALPN mismatch 失败。
- 空 ALPN 配置失败。
- root 不可信失败。
- ServerName mismatch 失败。
- mTLS required 成功/失败。
- 静态检查 `quic` 不 import `tlcp`。

验收：

```text
go test ./quic ./test -run 'QUIC'
go test ./...
```

## 7. Phase 5：SM4-GCM 安全 API

目标：

- 提供推荐的 SM4-GCM AEAD API，降低现有 `sm4.Encrypt/Decrypt` 模式参数误用风险。

新增包：

```text
sm4gcm/
```

建议 API：

```go
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

实施要求：

- 只接受 16 字节 key。
- 只接受 12 字节 nonce。
- `Seal` 不接受空 nonce。
- `SealRandomNonce` 返回结构化 nonce 和 ciphertext，不隐藏格式。
- 使用 `cipher.AEAD`。

测试：

- round trip。
- AAD 篡改失败。
- tag 篡改失败。
- nonce 长度错误失败。
- key 长度错误失败。
- `SealRandomNonce` 连续调用 nonce 不同。

验收：

```text
go test ./sm4gcm ./test -run 'SM4.*GCM'
```

## 8. Phase 6：QUICGM 应用层国密 profile

目标：

- 在标准 QUIC/TLS1.3 之上提供应用层 SM2/SM3/SM4 profile。
- 不宣称传输层 RFC8998。

新增包：

```text
quicgm/
```

能力：

- HMAC-SM3。
- SM4-GCM envelope。
- session key generation。
- SM2 certificate identity hook。
- AAD builder。

建议 API：

```go
type SessionKeys struct {
    KeyID   string
    HMACKey []byte
    SM4Key  []byte
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
func Seal(keys SessionKeys, plaintext, aad []byte) (Envelope, error)
func Open(keys SessionKeys, env Envelope) ([]byte, error)
func MACSM3(key, data []byte) []byte
func VerifyMACSM3(key, data, mac []byte) bool
```

实施要求：

- HMAC 校验使用常量时间比较。
- envelope metadata 必须进入 AAD 或 MAC。
- 不允许空 key_id/session_id。
- nonce 必须唯一，至少提供进程内 nonce registry 或调用方显式 nonce 策略。
- 文档明确 QUIC TLS1.3 负责传输安全，quicgm 负责应用层 payload 保护。

测试：

- envelope round trip。
- payload 篡改失败。
- AAD 篡改失败。
- MAC 篡改失败。
- wrong key 失败。
- 空 KeyID/SessionID 失败。
- QUIC echo 示例中 payload 通过 quicgm 加密。

验收：

```text
go test ./quicgm ./test -run 'QUICGM|Envelope'
```

## 9. Phase 7：SMX509 验证重构

目标：

- 消除 roots 转换为空池、leaf-as-root fallback、自签证书误通过等风险。

任务：

1. 新增保留 raw DER 的 `smx509.CertPool`。
2. 新增明确的 `VerifyOptions`。
3. 标准 x509 和 gmsm/smx509 路径都从同一 root/intermediate 语义派生。
4. 旧 `Verify` 保持兼容，但内部调用新实现。
5. 不允许没有 roots 时静默切换为自签信任。

测试：

- 正确 root 成功。
- 错误 root 失败。
- nil root 行为明确。
- 自签 leaf 未加入 roots 失败。
- intermediate chain 成功。
- KeyUsage/ExtKeyUsage 不匹配失败。
- expired/not-yet-valid 失败。

验收：

```text
go test ./smx509 ./test -run 'Cert|X509'
```

## 10. Phase 8：TLCP 安全收敛

目标：

- 关闭审计 P0/P1 风险。
- 在完成互通和 fuzz 前保持 experimental 定位。

任务：

1. 建立 TLCP 审计状态矩阵。
2. 确认并测试：
   - ServerKeyExchange 签名验证。
   - PMS 解密失败随机假值。
   - CBC IV 链式更新。
   - 证书验证不 leaf-as-root。
   - record version 验证。
   - ServerHello version 验证。
3. 默认只启用 GCM 套件。
4. CBC 套件迁移到 legacy 显式配置。
5. hybrid listener 默认允许 TLS+TLCP，支持 ProtocolMask 和 HandshakeTimeout 安全保护。
6. 增加 handshake/record fuzz。

测试：

- 握手成功路径。
- 证书错误失败。
- downgrade 失败。
- 篡改 SKE 失败。
- record version 错误失败。
- 慢握手触发 HandshakeTimeout。
- ProtocolMask 正确过滤协议版本。

验收：

```text
go test ./tlcp ./http ./test -run 'TLCP|Hybrid'
go test ./tlcp -fuzz=Fuzz -fuzztime=60s
```

## 11. Phase 9：TLS13GM/RFC8998 experimental

目标：

- 沉淀 RFC8998 常量、模型和测试向量。
- 不进入生产传输路径。

新增包：

```text
tls13gm/
```

任务：

1. RFC8998 cipher suite constants：
   - `TLS_SM4_GCM_SM3 = 0x00C6`
   - `TLS_SM4_CCM_SM3 = 0x00C7`
2. SM3 HKDF wrapper。
3. SM4-GCM AEAD wrapper。
4. SM2 signature scheme registry。
5. 测试向量目录。
6. QUIC packet protection 设计文档。

限制：

- 包文档必须写明 experimental。
- 不提供可直接传入 `crypto/tls.Config.CipherSuites` 的误导性 builder。
- 不影响 `quic` 标准传输包。

验收：

```text
go test ./tls13gm
```

## 12. 跨阶段工程要求

### 12.1 错误处理

- 配置错误必须在 builder 阶段返回。
- 网络握手错误必须可诊断。
- 密码学输入错误返回 error，不 panic。
- 格式混用返回明确错误。

### 12.2 文档

每个新包必须有 package doc：

- 包定位。
- 生产/experimental 状态。
- 安全边界。
- 不支持的能力。
- 最小示例。

### 12.3 测试

每个新包必须同步添加：

- 包内单元测试。
- `test/` 黑盒测试。
- 至少一个负向测试。
- 安全相关功能的篡改测试。

### 12.4 兼容性

- 不破坏现有 public API，除非先标记 deprecated。
- 必须修复文档与实现不一致的问题。
- 新 API 优先使用新包承载，避免在旧包中继续扩大模糊边界。

## 13. 发布里程碑

### M0：基线可发布

包含：

- Phase 0。
- Phase 1 的 CRITICAL 状态矩阵。
- `go test ./...` 通过。

不包含：

- 新 QUIC 功能。

### M1：标准 TLS1.3/HTTP

包含：

- Phase 2。
- Phase 3。
- TLS1.3 HTTP 黑盒测试。

不包含：

- QUIC。
- RFC8998。

### M2：标准 QUIC

包含：

- Phase 4。
- QUIC echo/mTLS/ALPN 测试。

不包含：

- 传输层国密 TLS1.3。

### M3：应用层国密 profile

包含：

- Phase 5。
- Phase 6。
- QUIC + quicgm 示例。

不包含：

- RFC8998 生产承诺。

### M4：证书与 TLCP 安全收敛

包含：

- Phase 7。
- Phase 8。
- fuzz 和互通测试入口。

### M5：RFC8998 研究包

包含：

- Phase 9。
- 常量、向量、设计文档。

状态：

- experimental。

## 14. 最终准入清单

发布前必须满足：

1. `go test ./...` 通过。
2. 新增包的黑盒测试通过。
3. 审计 CRITICAL 项均为 `fixed` 或有明确阻断说明。
4. TLCP/TLS1.3/RFC8998/QUIC 文档边界清楚。
5. 默认配置不启用 CBC 或 `InsecureSkipVerify`；hybrid listener 默认允许 TLS+TLCP，支持 ProtocolMask 和 HandshakeTimeout。
6. SMX509 不存在 leaf-as-root fallback。
7. QUIC 包不 import TLCP。
8. RFC8998 相关能力标记 experimental。
