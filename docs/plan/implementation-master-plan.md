# pollux-go 完整实施总计划

## 0. 文档定位

本文是面向执行的总实施计划，整合以下文档：

- `docs/plan/AUDIT_REPORT.md`
- `docs/plan/quic-tls13-gm-roadmap.md`
- `docs/plan/test-blackbox-completion-plan.md`
- `docs/plan/feature-completion-implementation-plan.md`

本文重点回答：

1. 先做什么，后做什么。
2. 每个阶段具体改哪些模块。
3. 每个工作包的完成定义是什么。
4. 每个阶段需要哪些测试、文档和准入条件。
5. 哪些能力可以发布，哪些只能标记 experimental。

当前基线日期：2026-05-25。
更新日期：2026-05-26（M9 完成）。

## 里程碑完成状态

| 里程碑 | 状态 | 说明 |
|--------|------|------|
| M0 基线恢复 | DONE | SM9 WrapKey 修复，审计矩阵创建，go test ./... 全绿 |
| M1 安全回归 | DONE | TLCP/SMX509/SM4 CRITICAL 全部修复 |
| M2 TLS1.3 | DONE | tls13 包、cert facade、HTTP TLS1.3 profile |
| M3 QUIC | DONE | quic 包 + QUIC echo round trip 黑盒测试 |
| M4 国密 profile | DONE | sm4gcm、quicgm 包 + 黑盒测试 |
| M5 SMX509/TLCP 收敛 | DONE | CertPool raw DER、GCM-only 默认、fuzz 入口 |
| M6 RFC8998 | DONE | tls13gm experimental 模型包 |
| M7 审计收尾 | DONE | 剩余 HIGH 项除内存清零外全部修复（5 个内存清零项保留 open） |
| M8 黑盒测试补全 | DONE | 279 个黑盒测试、审计回归测试名映射、QUIC 修复 |
| M9 文档和收尾 | DONE | GCM-only 默认、hybrid listener 修复、quicgm nonce API、TLCP/RFC8998 区分 |

## 1. 总体目标

pollux-go 的补全目标分为三层：

| 层级 | 目标 | 发布状态 |
|------|------|----------|
| 基线层 | 恢复 `go test ./...`，关闭关键审计风险，补齐黑盒测试 | 必须完成 |
| 生产层 | 标准 TLS1.3、HTTP TLS1.3、标准 QUIC、应用层国密 profile | 可进入正式能力 |
| 研究层 | RFC8998 TLS1.3 国密、QUIC 传输层国密、TLCP 深度互通 | experimental |

核心边界：

- QUIC 使用标准 TLS1.3，不复用 TLCP。
- `tls` 当前是 cipher suite registry，不是完整 TLS 实现。
- `quicgm` 是应用层国密 profile，不是 RFC8998 QUIC。
- TLCP 在审计项和互通测试完成前保持 experimental。

## 2. 实施总览

```text
M0 基线恢复
  P0.1 SM9 WrapKey 语义修复
  P0.2 当前黑盒测试全绿
  P0.3 审计状态矩阵

M1 安全回归补齐
  P1.1 TLCP CRITICAL 回归
  P1.2 SMX509 信任链回归
  P1.3 SM4 GCM/CBC 回归
  P1.4 SM2/SM3/SM9/ZUC 输入验证补齐

M2 标准 TLS1.3 能力
  P2.0 cert 统一证书与 X.509 隔离层
  P2.1 tls13 包
  P2.2 HTTP TLS1.3 profile
  P2.3 registry-only 文档澄清

M3 标准 QUIC 能力
  P3.1 quic 包
  P3.2 QUIC 黑盒测试
  P3.3 QUIC 示例

M4 应用层国密能力
  P4.1 sm4gcm 包
  P4.2 quicgm 包
  P4.3 QUIC + quicgm 示例

M5 证书与 TLCP 收敛
  P5.1 smx509 CertPool/Verifier 重构
  P5.2 TLCP GCM-only 默认
  P5.3 TLCP fuzz/interop 入口

M6 RFC8998 研究包
  P6.1 tls13gm constants/model
  P6.2 RFC8998 向量和设计文档
```

## 3. 分支和提交策略

建议按里程碑拆分分支：

| 分支 | 范围 |
|------|------|
| `fix/baseline-sm9-wrapkey` | M0 |
| `test/security-blackbox-regression` | M1 |
| `feat/tls13-profile` | M2 |
| `feat/quic-standard-transport` | M3 |
| `feat/gm-application-profile` | M4 |
| `feat/smx509-tlcp-hardening` | M5 |
| `exp/tls13gm-rfc8998` | M6 |

每个 PR 必须包含：

- 功能或修复说明。
- 风险说明。
- 测试命令和结果。
- 是否改变公开 API。
- 是否新增 experimental 能力。

## 4. M0：基线恢复

### 4.1 P0.1 SM9 WrapKey 语义修复

问题：

- `sm9.WrapKey` 的返回值顺序存在歧义：底层 `gmsmSM9.WrapKey` 返回 `(key, cipher, err)`。
- 包内测试和黑盒测试对返回值顺序的期望不一致。

实际实现（M0 已完成）：

| 文件 | 改动 |
|------|------|
| `sm9/sm9.go` | 保持底层 `(key, cipher, err)` 返回值顺序，与 gmsm 一致 |
| `sm9/sm9_test.go` | 包内测试匹配底层返回值顺序 |
| `test/sm9_test.go` | 黑盒测试更新为 `(key, cipher, err)` 语义 |

实际实现：

```go
func WrapKey(publicKey *EncryptMasterPublicKey, uid []byte, keyLen int) (key []byte, cipher []byte, err error) {
    if len(uid) == 0 {
        return nil, nil, errUIDEmpty
    }
    return gmsmSM9.WrapKey(rand.Reader, publicKey, uid, DefaultEncryptHID, keyLen)
}
```

设计决策：

- 保持与底层 gmsm 库的 API 一致性，返回 `(key, cipher, err)`
- 添加 `WrapKeyASN1` 函数用于 ASN.1 编码的场景
- 调用方应使用命名返回值避免混淆：`key, cipher, err := sm9.WrapKey(...)`

ASN.1 路径：

- 提供 `WrapKeyASN1` 函数返回 ASN.1 编码的结果
- 黑盒测试明确区分 raw 和 ASN.1 两种格式

验收：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

完成定义：

- `go test ./...` 全绿。
- SM9 raw 和 ASN.1 格式边界清楚。
- 包内测试和黑盒测试使用一致语义。

### 4.2 P0.2 测试基线记录

新增或更新文档：

| 文件 | 内容 |
|------|------|
| `docs/plan/test-blackbox-completion-plan.md` | 标记 M0 完成状态 |
| `docs/plan/implementation-master-plan.md` | 更新当前基线 |

记录内容：

- 执行日期。
- Go 版本。
- `go test ./...` 结果。
- 已知跳过项。
- 仍需人工互通的项目。

### 4.3 P0.3 审计状态矩阵

新增文档：

```text
docs/plan/audit-status-matrix.md
```

字段：

| 字段 | 说明 |
|------|------|
| ID | 审计项编号，如 T-1 |
| Severity | CRITICAL/HIGH/MEDIUM/LOW |
| Module | 模块 |
| Status | open/fixed/partial/needs-test/not-applicable |
| Code Status | 代码是否已修复 |
| Test Status | 是否已有回归测试 |
| Owner | 负责人 |
| Notes | 说明 |

首批必须覆盖：

- 所有 CRITICAL 项。
- 所有路线图 P0 项。
- 已观察到“可能已修复但缺测试”的项。

完成定义：

- CRITICAL 项没有空状态。
- 每个 fixed 项都有测试状态。
- 每个 open 项都有后续阶段归属。

## 5. M1：安全黑盒回归补齐

### 5.1 P1.1 TLCP CRITICAL 回归

范围：

| 审计项 | 回归目标 |
|--------|----------|
| T-1 | 篡改 ServerKeyExchange 签名必须握手失败 |
| T-2 | 解密失败不得产生可预测 PMS |
| T-3 | CBC IV 不得固定重用 |
| T-4 | 证书验证不得 leaf-as-root |

实施步骤：

1. 在 `tlcp` 包内补最小单元测试，便于构造握手消息。
2. 在 `test/` 补黑盒网络测试，验证真实 client/server 行为。
3. 对难以黑盒构造的场景，新增内部测试辅助，不暴露生产 API。

候选文件：

| 文件 | 用途 |
|------|------|
| `tlcp/handshake_messages_test.go` | 消息篡改和 transcript 测试 |
| `tlcp/record_test.go` | CBC/GCM record 行为 |
| `test/tlcp_http_test.go` | 黑盒 client/server |
| `test/cert_chain_test.go` | 证书链失败场景 |

验收：

```text
go test ./tlcp ./test -run 'TLCP|Cert'
```

完成定义：

- 每个 TLCP CRITICAL 项至少一个回归测试。
- 无 panic。
- 失败场景返回明确错误或 handshake failure。

### 5.2 P1.2 SMX509 信任链和解析回归

范围：

| 审计项 | 回归目标 |
|--------|----------|
| X-1 | PKCS#8 CBC 密文长度错误不 panic |
| X-2 | legacy PEM IV 长度错误不 panic |
| X-3 | PBKDF2 迭代次数下限 |
| X-4 | roots 转换不丢失证书 |

实施步骤：

1. 先补 failing test，锁定当前行为。
2. 修复解析和验证逻辑。
3. 补黑盒证书链测试。
4. 将 root/intermediate 行为写入 package doc。

候选文件：

| 文件 | 用途 |
|------|------|
| `smx509/cert_key_decrypt_test.go` | malformed encrypted key |
| `smx509/ca_chain_test.go` | chain verification |
| `test/cert_chain_test.go` | 黑盒证书链 |
| `smx509/verify.go` | roots/intermediates 实现 |

验收：

```text
go test ./smx509 ./test -run 'Cert|X509|Decrypt'
```

完成定义：

- 错误 DER/PEM 不 panic。
- 自签 leaf 未显式信任时失败。
- 正确 root/intermediate chain 成功。

### 5.3 P1.3 SM4 模式安全回归

范围：

| 审计项 | 回归目标 |
|--------|----------|
| S4-1 | GCM 随机 nonce 可被调用者拿到并用于解密 |
| S4-2 | CBC padding 错误不泄露明显分支行为，不 panic |
| S4-3 | 文档明确 GCM/CTR/CFB nonce/IV 不得复用 |

实施步骤：

1. 明确现有 `Encrypt(... ModeGCM, nil)` 线格式。
2. 补 AAD/tag/nonce 错误测试。
3. 对 ECB/CBC helper 加 deprecated 文档。
4. 为后续 `sm4gcm` 新包准备测试向量。

验收：

```text
go test ./sm4 ./test -run 'SM4'
```

完成定义：

- GCM 成功路径和篡改路径都有黑盒覆盖。
- 危险模式不会被文档推荐为新协议默认。

### 5.4 P1.4 算法包输入验证

范围：

| 模块 | 必补项 |
|------|--------|
| `sm2` | 私钥范围、曲线点验证、错误 key |
| `sm3` | HKDF/KDF 边界、标准向量 |
| `sm9` | 空 UID、错误 UID、错误 keyLen、ASN.1/raw |
| `zuc` | 标准向量、key/iv 长度、bearer/direction |

验收：

```text
go test ./sm2 ./sm3 ./sm9 ./zuc ./test
```

完成定义：

- 输入验证错误返回 error 或 false。
- 不出现 panic。
- 黑盒测试覆盖每个公开 API 的主要失败路径。

## 6. M2：标准 TLS1.3 能力

### 6.0 P2.0 统一证书与 X.509 隔离层

详细实施计划见：

- `docs/plan/cert-x509-abstraction-implementation-plan.md`

目标：

- 新增 caller-facing `cert` 包。
- 调用方不再需要区分标准 X.509、SM2 X.509、TLCP 双证书和 raw DER root pool。
- `smx509` 保留为底层 SM2-aware X.509 helper。

验收：

```text
go test ./cert ./smx509 ./tlcp ./http ./test -run 'Cert|X509|TLCP|HTTP'
go test ./...
```

### 6.1 P2.1 新增 `tls13` 包

包定位：

```text
tls13/
```

只提供标准 Go TLS1.3 config builder，不提供国密 TLS1.3。

文件建议：

```text
tls13/doc.go
tls13/config.go
tls13/config_test.go
```

API：

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

实现规则：

- `MinVersion = tls.VersionTLS13`。
- Server 必须有证书。
- Client 不默认跳过验证。
- 不设置 TLS1.2 cipher suite。
- 不导入 pollux `tls` registry 包。

测试：

- 空 server certificate 失败。
- MinVersion 固定 TLS1.3。
- NextProtos 透传。
- ClientAuth、ClientCAs 透传。
- InsecureSkipVerify 只有显式设置才为 true。

验收：

```text
go test ./tls13
go test ./...
```

### 6.2 P2.2 HTTP TLS1.3 profile

候选改动：

| 文件 | 改动 |
|------|------|
| `http/config.go` | 新增 TLS13 options 或 builder |
| `http/client.go` | 新增 TLS13 client helper |
| `http/http_test.go` | 包内测试 |
| `test/tls_http_test.go` | 黑盒测试 |

API 方向：

```go
func NewTLS13Server(opts ServerOptions) (*nethttp.Server, error)
func NewTLS13Client(opts ClientOptions) (*nethttp.Client, error)
```

兼容策略：

- 保留现有 `ModeTLS` 和 `ModeTLCP`。
- TLS13 profile 不改变 legacy 默认行为。
- 文档明确 TLS13 profile 是新推荐路径。

验收：

```text
go test ./http ./test -run 'TLS13|HTTP'
```

完成定义：

- TLS1.3 HTTP round trip 成功。
- TLS1.2-only 配置不能通过 TLS13 helper。
- 证书错误和 ServerName 错误失败。

### 6.3 P2.3 `tls` registry 文档澄清

候选改动：

| 文件 | 改动 |
|------|------|
| `tls/doc.go` 或 `tls/cipher_suite.go` | 写明 registry-only |
| `README.md` | 避免宣称完整 TLS 国密 |

完成定义：

- 文档明确 suite ID 不等于 Go `crypto/tls` 支持。
- 不误导用户把 RFC8998 suite 直接塞进 TLS config。

## 7. M3：标准 QUIC 能力

### 7.1 P3.1 新增 `quic` 包

依赖：

```text
github.com/quic-go/quic-go
```

文件建议：

```text
quic/doc.go
quic/config.go
quic/listener.go
quic/conn.go
quic/quic_test.go
test/quic_blackbox_test.go
```

API：

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
```

实现规则：

- 强制 `NextProtos` 非空。
- 复用 `tls13` builder。
- 不 import `github.com/ycq/pollux/tlcp`。
- `Listen` 和 `Dial` 接受 context。
- 默认 idle timeout 有保守值。

测试：

- echo round trip。
- 空 ALPN 配置失败。
- ALPN mismatch 失败。
- server cert 不可信失败。
- ServerName mismatch 失败。
- mTLS required 成功/失败。
- 静态检查不 import TLCP。

验收：

```text
go test ./quic ./test -run 'QUIC'
go test ./...
```

### 7.2 P3.2 示例

新增：

```text
examples/quic_echo/
```

要求：

- 本地自签证书只用于示例。
- 示例代码显式配置 ALPN。
- 示例文档写明使用标准 TLS1.3。

## 8. M4：应用层国密能力

### 8.1 P4.1 新增 `sm4gcm` 包

文件建议：

```text
sm4gcm/doc.go
sm4gcm/sm4gcm.go
sm4gcm/sm4gcm_test.go
test/sm4gcm_blackbox_test.go
```

实现规则：

- key 固定 16 字节。
- nonce 固定 12 字节。
- `Seal` 不生成 nonce。
- `SealRandomNonce` 返回结构体。
- AAD 显式传入。

完成定义：

- round trip、AAD 篡改、tag 篡改、wrong key、wrong nonce length 全覆盖。

### 8.2 P4.2 新增 `quicgm` 包

文件建议：

```text
quicgm/doc.go
quicgm/keys.go
quicgm/envelope.go
quicgm/mac.go
quicgm/quicgm_test.go
test/quicgm_blackbox_test.go
```

能力范围：

- HMAC-SM3。
- SM4-GCM envelope。
- session key generation。
- KeyID/SessionID 校验。
- AAD/MAC 绑定。

不做：

- 不改 QUIC packet protection。
- 不实现 RFC8998 handshake。
- 不自动信任 SM2 证书。

完成定义：

- envelope round trip。
- metadata/payload/MAC 任一篡改失败。
- wrong key 失败。
- 文档明确应用层 profile。

### 8.3 P4.3 QUIC + quicgm 示例

新增：

```text
examples/quicgm_echo/
```

要求：

- QUIC 连接使用标准 TLS1.3。
- 应用 payload 使用 quicgm envelope。
- 示例中显示 KeyID、SessionID、AAD 的生成和验证。

验收：

```text
go test ./sm4gcm ./quicgm ./test -run 'SM4GCM|QUICGM|Envelope'
go test ./...
```

## 9. M5：SMX509 与 TLCP 安全收敛

### 9.1 P5.1 SMX509 CertPool/Verifier

新增或重构：

```go
type CertPool struct {
    certs  []*x509.Certificate
    rawDER [][]byte
}

type VerifyOptions struct {
    DNSName       string
    Roots         *CertPool
    Intermediates *CertPool
    KeyUsages     []x509.ExtKeyUsage
    CurrentTime   time.Time
}
```

实现规则：

- CertPool 必须保存 raw DER。
- 不从 `x509.CertPool.Subjects()` 反推证书。
- nil Roots 策略明确。
- 不做 leaf-as-root fallback。

验收：

```text
go test ./smx509 ./test -run 'Cert|X509'
```

### 9.2 P5.2 TLCP 默认安全收敛

任务：

1. 默认 cipher suite 列表改为 GCM-only。
2. CBC suite 标记 legacy，必须显式启用。
3. record version 严格验证。
4. ServerHello version 严格验证。
5. hybrid listener 标记 experimental。
6. Accept/handshake 增加 timeout。

验收：

```text
go test ./tlcp ./http ./test -run 'TLCP|Hybrid'
```

### 9.3 P5.3 fuzz 和互通入口

新增 fuzz：

```text
tlcp/FuzzHandshakeMessage
tlcp/FuzzRecord
smx509/FuzzParseCertificate
smx509/FuzzDecryptPrivateKey
```

发布前命令：

```text
go test ./tlcp ./smx509 -fuzz=Fuzz -fuzztime=60s
```

互通：

- Tongsuo 相关测试默认 short 跳过。
- 提供环境变量显式启用。
- 互通失败不阻塞普通单测，但阻塞正式发布。

## 10. M6：RFC8998 experimental

### 10.1 P6.1 新增 `tls13gm` 包

文件建议：

```text
tls13gm/doc.go
tls13gm/constants.go
tls13gm/hkdf.go
tls13gm/aead.go
tls13gm/signature.go
tls13gm/tls13gm_test.go
```

内容：

- `TLS_SM4_GCM_SM3 = 0x00C6`
- `TLS_SM4_CCM_SM3 = 0x00C7`
- SM3 HKDF wrapper。
- SM4-GCM AEAD wrapper。
- SM2 signature scheme registry。

限制：

- package doc 必须写明 experimental。
- 不提供完整 TLS handshake。
- 不提供误导性 `BuildTLSConfig`。

### 10.2 P6.2 设计文档

新增：

```text
docs/plan/rfc8998-tls13gm-design.md
```

必须说明：

- RFC8998 组成部分。
- Go `crypto/tls` 当前限制。
- quic-go 集成难点。
- packet protection 需要 SM4-GCM。
- 生产路径仍是标准 QUIC/TLS1.3 + quicgm。

验收：

```text
go test ./tls13gm
```

## 11. 质量门禁

### 11.1 每个 PR 的最低门禁

```text
go test ./...
```

如果改动涉及协议、证书或密码模式，还必须运行对应专项：

| 改动范围 | 命令 |
|----------|------|
| SM9 | `go test ./sm9 ./test -run 'SM9'` |
| SMX509 | `go test ./smx509 ./test -run 'Cert|X509|Decrypt'` |
| TLCP | `go test ./tlcp ./test -run 'TLCP'` |
| HTTP | `go test ./http ./test -run 'HTTP|TLS'` |
| QUIC | `go test ./quic ./test -run 'QUIC'` |
| SM4/SM4GCM | `go test ./sm4 ./sm4gcm ./test -run 'SM4|GCM'` |
| QUICGM | `go test ./quicgm ./test -run 'QUICGM|Envelope'` |

### 11.2 发布前门禁

```text
go test ./...
go test -race ./...
go test ./tlcp ./smx509 -fuzz=Fuzz -fuzztime=60s
```

发布前人工检查：

- README 和 package doc 没有过度承诺。
- experimental 包标记清楚。
- 默认配置不启用 `InsecureSkipVerify`。
- 默认配置不启用 hybrid listener。
- 默认配置不启用 CBC。
- QUIC 包不 import TLCP。

## 12. 风险和阻塞条件

| 风险 | 阻塞阶段 | 处理 |
|------|----------|------|
| SM9 API 返回值改变造成兼容风险 | M0 | 保持公开签名语义，修 wrapper，不改调用者期望 |
| quic-go 依赖引入网络或 Go 版本约束 | M3 | 先确认 `go.mod` 支持版本，必要时把 QUIC 放独立 PR |
| SMX509 root pool 重构影响现有调用者 | M5 | 保留旧 API，新增明确 API，旧 API 内部适配 |
| TLCP 自研协议修复复杂 | M5 | 保持 experimental，先测试和文档收敛 |
| RFC8998 被误认为生产可用 | M6 | 包名、doc、README 均标记 experimental |
| fuzz 暴露大量历史 panic | M5 | fuzz 发现项进入单独 bug backlog，不和功能 PR 混合 |

## 13. 执行顺序建议

第一批：

1. M0：修 SM9，恢复 `go test ./...`。
2. M0：创建审计状态矩阵。
3. M1：补 TLCP/SMX509/SM4 CRITICAL 回归。

第二批：

1. M2：新增 `tls13`。
2. M2：新增 HTTP TLS1.3 profile。
3. M2：澄清 `tls` registry 文档。

第三批：

1. M3：新增标准 `quic` 包。
2. M4：新增 `sm4gcm`。
3. M4：新增 `quicgm`。

第四批：

1. M5：重构 SMX509 verifier。
2. M5：TLCP GCM-only 默认和 fuzz。
3. M6：RFC8998 experimental 模型包。

## 14. 当前状态

M9 已完成（2026-05-26）：

- ✅ SM9 WrapKey 返回值已稳定为 `(key, cipher, err)`（与 gmsm 库保持一致）
- ✅ 所有 CRITICAL 和 HIGH 功能性审计项已修复
- ✅ GCM-only 默认配置已应用到 HTTP/cert/TLCP
- ✅ hybrid listener 已修复并添加安全保护
- ✅ quicgm nonce registry 和显式 nonce API 已实现并测试
- ✅ 全量测试 `go test ./...` 全绿
- ✅ 所有文档已更新以反映实际实现

剩余工作（非阻塞）：

- 5 个 HIGH open 项（内存清零相关）需要人工代码审查
- 可选：进一步的互通测试和性能优化
