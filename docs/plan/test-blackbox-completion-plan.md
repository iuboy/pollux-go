# pollux-go test 黑盒测试补全计划

## 0. 计划定位

本文基于 `docs/plan/AUDIT_REPORT.md` 和 `docs/plan/quic-tls13-gm-roadmap.md`，专门补齐 `test/` 目录的黑盒测试计划。

更细的 API 级测试矩阵、目标文件结构、测试命名和分批实施步骤见：

- `docs/plan/test-blackbox-api-implementation-plan.md`

目标不是替代各包内部单元测试，而是从公开 API、跨模块行为、错误输入、安全边界和互通语义出发，建立可发布前执行的黑盒验收套件。

当前基线日期：2026-05-25。
更新日期：2026-05-26（M9 完成）。

## 1. 当前测试基线

在仓库根目录执行：

```text
go test ./...
```

当前状态（更新于 2026-05-26 M9）：

- 17 个包全部通过 `go test ./...`。
- SM9 Wrap/Unwrap 语义已稳定为 `(key, cipher, err)`（M0/M9）。
- `tls13`、`quic`、`sm4gcm`、`quicgm`、`tls13gm` 包已创建并有黑盒测试。
- `cert` 统一证书 facade 已创建。
- **255** 个黑盒测试函数覆盖所有公开 API。
- **审计矩阵：39 项 fixed、5 项 open（内存清零相关）、5 项 not-applicable**。
- HTTP/cert/TLCP 默认配置已改为 GCM-only。
- hybrid listener 已修复，默认允许 TLS+TLCP，支持 ProtocolMask 和 HandshakeTimeout。
- quicgm 已实现 nonce registry 和显式 nonce API，包含 13 个新增测试。

## 2. 黑盒测试原则

黑盒测试只依赖公开 API 和稳定文档承诺：

1. 不访问未导出的函数、字段或内部状态。
2. 不依赖随机输出的固定值，只验证长度、可逆性、唯一性、拒绝行为和跨库一致性。
3. 每个成功路径必须有对应失败路径。
4. 每个安全修复必须有回归测试，且测试名能映射到审计项。
5. 网络类测试默认使用本地回环、临时端口和短超时。
6. 跨库、Tongsuo、外网等不稳定依赖必须可通过 `testing.Short()` 或环境变量隔离。
7. 新功能进入路线图前，必须先补黑盒验收用例。

## 3. 优先级

| 优先级 | 范围 | 目标 |
|--------|------|------|
| P0 | 当前失败测试、审计 CRITICAL 回归 | 恢复 `go test ./...` 绿色基线，证明高危修复未回退 |
| P1 | 公开 API 错误输入和安全边界 | 让常见误用返回明确错误，不 panic、不静默降级 |
| P2 | 跨模块和互通 | 证明 test 目录覆盖真实组合场景 |
| P3 | 性能、并发、长期稳定 | 补充压力、race、fuzz 和长跑测试入口 |

## 4. P0 补全计划

### 4.1 SM9 Wrap/Unwrap 基线修复

目标：

- `sm9.WrapKey` 的公开返回值顺序、注释、包内测试和黑盒测试一致。
- raw 格式和 ASN.1 格式分别使用正确的 unwrap API。
- 不再出现“把密钥当密文”或“把 ASN.1 密文当 raw 密文”的测试歧义。

用例：

| 用例 | 行为 |
|------|------|
| `TestBlackBox_SM9_WrapUnwrapKey` | `WrapKey` 返回密文和明文会话密钥，`UnwrapKey` 能恢复同一密钥 |
| `TestBlackBox_SM9_WrapKey_DifferentKeyLengths` | keyLen 为 16/24/32 时均可封装和解封装 |
| `TestBlackBox_SM9_WrapKey_WrongUID` | UID 不一致必须失败 |
| `TestBlackBox_SM9_WrapKey_TamperedCipher` | 密文被篡改必须失败 |
| `TestBlackBox_SM9_WrapKey_InvalidKeyLen` | 0 或负数长度必须返回错误 |
| `TestBlackBox_SM9_WrapKeyASN1_RoundTrip` | ASN.1 格式只走 ASN.1 对应 unwrap 路径 |
| `TestBlackBox_SM9_WrapKey_RawAndASN1NotConfused` | raw/ASN.1 格式混用必须失败或显式报错 |

验收：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

### 4.2 TLCP 审计 CRITICAL 回归

来源：`AUDIT_REPORT.md` 的 T-1、T-2、T-3、T-4。

用例：

| 审计项 | 黑盒测试 |
|--------|----------|
| T-1 ServerKeyExchange 签名验证 | 篡改 ECDHE ServerKeyExchange 签名，客户端必须握手失败 |
| T-2 解密失败 PMS | 伪造 ClientKeyExchange，服务端不得形成可预测会话密钥 |
| T-3 CBC IV 链式更新 | 同一连接连续发送相同明文记录，密文块不得重复暴露固定 IV 行为 |
| T-4 证书验证 fallback | 自签 leaf 在未加入 roots 时必须失败 |

验收：

```text
go test ./tlcp ./test -run 'TLCP|Cert'
```

### 4.3 SMX509 信任链回归

来源：`AUDIT_REPORT.md` 的 X-1、X-2、X-3、X-4，以及路线图第 9 节。

用例：

| 场景 | 行为 |
|------|------|
| 正确 root + leaf | 验证成功 |
| 错误 root + leaf | 验证失败 |
| nil root + leaf | 行为明确，不自动把 leaf 当 root |
| 自签 leaf | 未显式信任时失败 |
| 过期证书 | 失败 |
| not-yet-valid 证书 | 失败 |
| KeyUsage 不匹配 | 失败 |
| malformed PEM/DER | 返回错误，不 panic |
| PKCS#8 密文长度不对齐 | 返回错误，不 panic |
| legacy PEM IV 长度错误 | 返回错误，不 panic |

验收：

```text
go test ./smx509 ./test -run 'Cert|X509|Decrypt'
```

### 4.4 SM4 GCM/CBC 安全回归

来源：`AUDIT_REPORT.md` 的 S4-1、S4-2、S4-3。

用例：

| 场景 | 行为 |
|------|------|
| GCM 随机 nonce 加密 | 返回值包含可解密所需的 nonce 或结构化结果 |
| GCM AAD 篡改 | 解密失败 |
| GCM tag 篡改 | 解密失败 |
| GCM nonce 长度错误 | 返回错误 |
| CBC padding 篡改 | 返回错误，不 panic |
| ECB 模式 | 黑盒测试只保留 legacy 明确测试，不作为推荐路径 |

验收：

```text
go test ./sm4 ./test -run 'SM4'
```

## 5. P1 补全计划

### 5.1 SM2

补充用例：

- `BytesToPrivateKey` 拒绝 0、n、n+1。
- `UnmarshalUncompressed` 拒绝不在曲线上的点。
- `NewPrivateKey`、`NewPublicKey` 对 nil、短输入、长输入返回错误。
- 签名验签覆盖错误 UID、错误消息、篡改签名。
- 加密 envelope 覆盖空明文、大明文、错误私钥、篡改密文。

### 5.2 SM3

补充用例：

- SM3 标准向量。
- HMAC-SM3 与独立实现或已确认向量对齐。
- HKDF-SM3 extract/expand 覆盖空 salt、长 info、超大 keyLen。
- KDF 对 0 长度、极大长度、nil 输入行为明确。

### 5.3 SM4

补充用例：

- 标准分组加密向量。
- KeyWrap 对 16/24/32 字节 key 的 round trip。
- KeyWrap 错误 KEK、篡改密文、长度不对齐失败。
- CMAC 确定性、错误 key、篡改消息失败。
- `GenerateIV` 连续调用唯一性抽样检查。

### 5.4 SM9

补充用例：

- 签名验签错误 UID、错误消息、篡改签名。
- 加解密错误 UID、篡改密文、大明文。
- 空 UID 策略明确。
- `Sign` 参数命名与语义明确后，测试同时覆盖“原始消息”和“外部 hash”文档承诺。

### 5.5 ZUC

补充用例：

- 3GPP TS 35.221/35.222 标准向量。
- EEA/EIA 不同 bearer、direction、count 产生不同输出。
- key/iv 长度错误返回错误。
- MAC 篡改失败。
- IV 复用风险只通过文档和静态检查提示，不在 API 中制造隐式安全承诺。

## 6. P2 跨模块黑盒测试

| 组合 | 测试目标 |
|------|----------|
| SM2 + SMX509 | 证书生成、CSR、签发、解析、链验证、KeyUsage |
| HTTP + TLS | 标准 TLS client/server，本地回环，无外网依赖 |
| HTTP + TLCP | TLCP HTTP round trip，证书错误必须失败 |
| Hybrid HTTP | 默认允许 TLS+TLCP，支持 ProtocolMask 和 HandshakeTimeout 安全保护 |
| TLS registry + HTTP | registry suite ID 不得被误认为完整 TLS1.3 GM 实现 |
| QUIC + TLS13 | 新增 quic 包后验证 ALPN、mTLS、证书错误 |
| QUICGM + SM4/SM3/SM2 | 应用层 envelope 加密、认证、身份绑定 |

## 7. P3 稳定性测试入口

建议新增脚本或 make target：

```text
go test ./...
go test -race ./...
go test ./... -run 'BlackBox'
go test ./tlcp ./smx509 -fuzz=Fuzz -fuzztime=60s
go test ./test -run 'Interop' -short
```

长跑测试不作为默认 `go test ./...` 的强依赖，但必须在发布前执行并记录结果。

## 8. 测试目录组织

建议保持 `test/` 作为公开 API 黑盒测试目录，并逐步拆分文件：

```text
test/
  sm2_blackbox_test.go
  sm3_blackbox_test.go
  sm4_blackbox_test.go
  sm9_blackbox_test.go
  smx509_blackbox_test.go
  tlcp_blackbox_test.go
  http_blackbox_test.go
  quic_blackbox_test.go
  quicgm_blackbox_test.go
  interop_crypto_test.go
  testutil_test.go
```

命名规则：

- 成功路径：`TestBlackBox_<Module>_<Feature>_RoundTrip`
- 错误路径：`TestBlackBox_<Module>_<Feature>_<FailureReason>`
- 审计回归：`TestBlackBox_<Module>_<AuditID>_<Behavior>`
- 互通测试：`TestInterop_<Module>_<Library>_<Behavior>`

## 9. 发布准入

任何功能合并到主线前必须满足：

1. `go test ./...` 通过。
2. 新公开 API 有至少一个成功黑盒测试和一个失败黑盒测试。
3. 安全相关 API 有篡改、错误身份或错误密钥测试。
4. 审计项修复必须带对应回归测试。
5. 网络协议功能必须覆盖证书错误、协议协商错误和超时。
6. 不稳定外部依赖测试默认跳过，并提供显式启用方式。

## 10. 执行顺序

1. 修复 SM9 Wrap/Unwrap 语义，恢复 `go test ./...`。
2. 补 TLCP/SMX509/SM4 审计 CRITICAL 回归。
3. 补 SM2/SM3/SM9/ZUC 输入验证和负向用例。
4. 补 HTTP/TLCP hybrid 和 TLS registry 误用测试。
5. 随功能实施计划新增 `tls13`、`quic`、`sm4gcm`、`quicgm` 黑盒测试。
6. 建立发布前 `race`、`fuzz`、`interop` 测试清单。
