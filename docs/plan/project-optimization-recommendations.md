# pollux-go 项目优化建议

## 0. 范围

本文结合 `docs/plan` 下已有计划和当前代码状态，记录除“统一证书与 X.509 隔离层”以外，项目当前值得优先处理的优化点。

当前基线日期：2026-05-26。

当前验证：

```text
go test ./...
```

结果：通过。

## 1. 先同步计划状态

现状：

- 当前 `go test ./...` 已通过。
- `tls13`、`quic`、`sm4gcm`、`quicgm`、`tls13gm` 包已经存在。
- `smx509.CertPool` 已经存在并保留 raw DER。
- 部分计划文档仍描述为“待新增”或“当前 test 失败”。

建议：

1. 更新 `docs/plan/audit-status-matrix.md` 的基线日期和测试状态。
2. 更新 `implementation-master-plan.md` 中 M0-M4 的完成/部分完成状态。
3. 更新 `test-blackbox-completion-plan.md` 和 `test-blackbox-api-implementation-plan.md` 中的 SM9 失败基线，改为历史问题和回归项。
4. 为新增包补对应完成度矩阵，而不是继续按“尚未创建”描述。

优先级：P0。

## 2. 统一证书隔离层应提前

现有路线把 SMX509 重构放在 M5，但现在 `tls13`、`quic`、`http TLS1.3`、`quicgm` 已经开始落地。证书语义如果继续分散，会让后续迁移成本上升。

建议：

- 将 `cert` 隔离层提升到 M1/M2 之间。
- 在 HTTP TLS1.3、QUIC mTLS、quicgm SM2 identity 深化前先稳定证书入口。
- 保留 `smx509` 作为 backend，新增 `cert` 作为 caller-facing facade。

优先级：P0。

## 3. 修正 HTTP TLS1.3 option 类型

当前 `http/tls13.go` 中：

```go
type TLS13ServerOptions struct {
    ClientCAs *tls.Config
}

type TLS13ClientOptions struct {
    RootCAs *tls.Config
}
```

这与 `tls13.ServerOptions`、`tls13.ClientOptions` 的 `*x509.CertPool` 不一致，而且当前 builder 没有透传这些字段。

建议：

```go
ClientCAs *x509.CertPool
RootCAs   *x509.CertPool
```

并透传到 `tls13`。

如果引入 `cert` 包，可再补：

```go
ClientCAPool *cert.Pool
RootPool     *cert.Pool
```

但不要在同一字段里混用 `*tls.Config` 和 root pool 语义。

优先级：P0。

## 4. quicgm Envelope MAC 实现可收敛

当前 `quicgm.Open` 中计算了 `expectedMAC`，但实际校验又调用 `VerifyMACSM3(keys.HMACKey, macInput(env), env.MAC)` 重新计算，`expectedMAC` 只是避免未使用变量。

建议：

1. 删除无用 `expectedMAC`。
2. `macInput` 改为明确的二进制 canonical encoding，避免 `fmt.Sprintf` 字符串拼接成为长期协议格式。
3. MAC 输入应继续覆盖：
   - version
   - session id
   - key id
   - nonce
   - aad
   - ciphertext
4. 增加 envelope version 不支持时失败的行为。

优先级：P1。

## 5. TLS/QUIC 证书策略需要统一表达

当前 `tls13` 和 `quic` 使用标准 `*x509.CertPool`，这是标准 TLS 路线合理选择。但应用层 SM2 identity、TLCP、SMX509 需要 raw DER pool。

建议：

- `tls13` 保持标准库 API，低层稳定。
- 新增 `cert.BuildClientTLSConfig` / `cert.BuildServerTLSConfig` 作为更高层入口。
- `quic` 可保持标准 `RootCAs`，再新增 cert-aware helper，而不是把 `cert.Pool` 强塞进核心 config。

优先级：P1。

## 6. TLCP 状态仍应保守

虽然 `go test ./...` 通过，但审计状态矩阵中 TLCP 仍有多项 CRITICAL/HIGH open 或 needs-test。

建议：

1. TLCP package doc 保持 experimental 或 security status 说明。
2. 默认 cipher suite 收敛到 GCM-only。
3. CBC 标记 legacy，需要显式启用。
4. 补 T-1/T-2/T-3/T-4 黑盒和半白盒回归。
5. hybrid listener 默认禁用或 experimental。

优先级：P0/P1。

## 7. API 命名和兼容策略

建议统一包层次：

| 层级 | 包 | 定位 |
|------|----|------|
| 基础算法 | `sm2`、`sm3`、`sm4`、`sm9`、`zuc` | 算法 wrapper |
| 安全推荐原语 | `sm4gcm` | 推荐 AEAD |
| 证书 facade | `cert` | 调用方面向证书入口 |
| 底层证书 backend | `smx509` | SM2-aware X.509 helper |
| 标准传输 | `tls13`、`quic` | 标准 TLS1.3/QUIC |
| 应用层国密 | `quicgm` | envelope/profile |
| experimental | `tls13gm` | RFC8998 research |
| registry | `tls` | cipher suite registry only |

建议：

- 不再扩大 `tls` 包能力，避免误解。
- `TLSNat`、`National TLS` 等命名需谨慎，避免暗示 RFC8998 已支持。
- 新 API 使用清晰的 profile 名称：`StandardTLS13`、`TLCP`、`ApplicationGM`。

优先级：P1。

## 8. 黑盒测试计划需要转为覆盖矩阵

已有测试计划很详细，但下一步应变成可维护矩阵。

建议新增：

```text
docs/plan/test-coverage-matrix.md
```

字段：

| Module | API | Success | Failure | Security | Interop | Status |
|--------|-----|---------|---------|----------|---------|--------|

优先填：

- `cert`
- `smx509`
- `tlcp`
- `http`
- `tls13`
- `quic`
- `quicgm`

优先级：P1。

## 9. 审计矩阵需要和代码自动化挂钩

当前 `audit-status-matrix.md` 是手工状态，容易漂移。

建议：

1. 每个审计项对应一个测试名。
2. 矩阵增加 `Regression Test` 列。
3. fixed 项没有测试名时不得标为完成。
4. 发布前执行：

```text
go test ./... 
go test ./test -run 'T1|T2|T3|T4|X1|X2|X3|X4|S4|H1|H2'
```

优先级：P1。

## 10. 错误类型应更稳定

现在很多错误是未导出变量或普通 `fmt.Errorf` 字符串。对上层库用户来说，证书失败、配置错误、格式错误、验证失败、unsupported profile 应该能区分。

建议：

- 为新 `cert` 包定义导出 sentinel errors 或错误类型。
- `tls13`、`quic` 的配置错误可逐步导出。
- 不要求所有旧包一次性改造。

示例：

```go
var ErrNoRoots = errors.New("cert: no roots")
var ErrLeafAsRoot = errors.New("cert: leaf certificate is not trusted root")
var ErrUnsupportedCertificate = errors.New("cert: unsupported certificate")
```

优先级：P2。

## 11. 文档中的生产承诺要更严格

建议所有包文档都明确状态：

| 包 | 状态 |
|----|------|
| `sm2`/`sm3`/`sm4`/`sm9`/`zuc` | wrapper around gmsm |
| `sm4gcm` | recommended AEAD helper |
| `cert` | recommended certificate facade |
| `smx509` | lower-level SM2-aware x509 helper |
| `tls13` | standard TLS1.3 only |
| `quic` | standard QUIC/TLS1.3 only |
| `quicgm` | application-layer GM profile |
| `tlcp` | experimental until audit closed |
| `tls13gm` | experimental/research |
| `tls` | registry only |

优先级：P1。

## 12. 建议执行顺序

更新于 2026-05-26：

| 步骤 | 状态 |
|------|------|
| 1. 同步计划状态，记录当前 `go test ./...` 通过 | DONE |
| 2. 修正 HTTP TLS1.3 root/client CA 类型 | DONE |
| 3. 新增 `cert` facade 的 Pool、Parse、Verify | DONE |
| 4. 将 TLCP root 加载迁移到 `cert.Pool` | DONE |
| 5. 补 cert/smx509/TLCP 证书黑盒测试 | DONE |
| 6. 补 quicgm envelope MAC canonical encoding | DONE |
| 7. 更新审计矩阵，增加回归测试名 | DONE |
| 8. 扩展 QUICGM SM2 identity、TLCP 安全收敛、RFC8998 experimental | 后续迭代 |

## 13. 后续可扩展方向

1. QUICGM SM2 identity binding — envelope 中绑定 SM2 证书身份
2. TLCP Tongsuo 互通测试入口
3. RFC8998 TLS 1.3 完整 handshake 设计文档
4. 性能 benchmark 和 race detector 集成
5. 发布前 `go test -race ./...` 和 fuzz 基线

