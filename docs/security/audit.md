# pollux-go 安全审计报告

**初始审计日期**: 2026-05-24
**最后更新**: 2026-06-14（Route C 完成）
**审计范围**: 全部密码学模块（sm2, sm3, sm4, sm9, smx509, tlcp, zuc, http, tls, tls13gm, quicgm）

本文合并了原始审计报告的问题描述与修复状态矩阵。架构层面的背景见
[`../design/architecture.md`](../design/architecture.md)。

## 1. 总体统计

初始审计共发现 **15 CRITICAL + 32 HIGH + 35 MEDIUM + 24 LOW/INFO** 问题：

| 模块 | CRITICAL | HIGH | MEDIUM | LOW/INFO |
|------|----------|------|--------|----------|
| tlcp/ | 4 | 7 | 9 | 6 |
| smx509/ | 4 | 4 | 6 | 3 |
| sm4/ | 3 | 3 | 3 | 3 |
| http/ + tls/ | 2 | 6 | 5 | 3 |
| sm3/ | 1 | 2 | 2 | 3 |
| sm2/ | 1 | 4 | 3 | 2 |
| sm9/ | 0 | 3 | 3 | 2 |
| zuc/ | 0 | 3 | 4 | 2 |
| **合计** | **15** | **32** | **35** | **24** |

> **TLCP 架构变更说明**：初始审计针对的是 pollux-go 早期**自研的** TLCP 握手实现
> （T-1 ~ T-4 等审计项即针对它）。该自研代码已随后被 `gitee.com/Trisia/gotlcp`
> 封装替换（commit `202ac7e`），TLCP 握手由上游库提供。下表中的 tlcp 修复记录
> 反映的是自研阶段的加固，现已随重构整体移除。

## 2. 状态汇总

| 状态 | CRITICAL | HIGH | 合计 |
|------|----------|------|------|
| fixed | 15 | 29 | 44 |
| documented | 0 | 5 | 5 |
| open | 0 | 0 | 0 |

**所有 CRITICAL 和 HIGH 功能性审计项已修复**。剩余 5 个内存安全项通过
`internal/memsecure` 机制 + 安全文档完成（fixed + documented）。

## 3. CRITICAL 级别

| ID | 模块 | 问题 | Code | Test | Phase |
|----|------|------|------|------|-------|
| T-1 | tlcp | ServerKeyExchange 签名完全未验证（中间人攻击） | fixed | fixed | M1 |
| T-2 | tlcp | 解密失败时使用全零 preMasterSecret（密钥可恢复） | fixed | fixed | M1 |
| T-3 | tlcp | CBC 模式 IV 固定重用（语义安全性破坏） | fixed | fixed | M1 |
| T-4 | tlcp | 证书验证 fallback 使用自签名根池（CA 验证绕过） | fixed | fixed | M1 |
| X-1 | smx509 | CBC 解密缺少密文对齐校验（panic/DoS） | fixed | fixed | M1 |
| X-2 | smx509 | Legacy IV 长度未校验（越界 panic） | fixed | fixed | M1 |
| X-3 | smx509 | PBKDF2 迭代次数无下限（允许极弱密钥派生） | fixed | fixed | M1 |
| X-4 | smx509 | 证书验证 Roots 转换为空池 | fixed | fixed | M0 |
| S4-1 | sm4 | GCM nonce 生成后不返回（数据无法解密） | fixed | fixed | M0 |
| S4-2 | sm4 | CBC padding oracle 时序侧信道 | fixed | fixed | M1 |
| S4-3 | sm4 | GCM/CTR/CFB 无 IV 重用保护 | fixed | fixed | M7 |
| S3-1 | sm3 | HKDF-Expand 手工构建 HMAC（绕过审计过的标准库） | fixed | fixed | M1 |
| S2-1 | sm2 | BytesToPrivateKey 缺少私钥标量范围验证 | fixed | fixed | M0 |
| H-1 | http | 混合监听器协议检测可被伪造（降级攻击） | fixed | fixed | M1 |
| H-2 | http | NewClient default 分支传入 nil TLCP 配置（panic） | fixed | fixed | M0 |

## 4. HIGH 级别

| ID | 模块 | 问题 | Code | Test | Phase |
|----|------|------|------|------|-------|
| T-H1 | tlcp | GCM 解密不验证显式 Nonce 等于序列号 | fixed | fixed | M5 |
| T-H3 | tlcp | CBC MAC 输入缺少 content_type 和 version | fixed | fixed | M5 |
| T-H4 | tlcp | 记录层未验证版本号 | fixed | fixed | M5 |
| T-H5 | tlcp | 客户端不验证 ServerHello 版本号 | fixed | fixed | M5 |
| T-H6 | tlcp | ECDHE 曲线类型不明确 | fixed | fixed | M7 |
| T-H7 | tlcp | 无重放攻击防护 | fixed | fixed | M7 |
| X-H1 | smx509 | SM2 公钥识别仅依赖曲线对象实例 | fixed | fixed | M7 |
| X-H3 | smx509 | CSR 类型转换可能不安全 | fixed | fixed | M7 |
| X-H4 | smx509 | 密码/密钥材料未内存清零 | fixed | documented | M10 |
| S2-H1 | sm2 | API 拼写错误 RepondKeyExchange | fixed | fixed | M7 |
| S2-H2 | sm2 | KeyExchangePerformer 未暴露 Destroy 方法 | fixed | documented | M10 |
| S2-H3 | sm2 | PrivateKeyToBytes 无内存清理指引 | fixed | documented | M10 |
| S2-H4 | sm2 | UnmarshalUncompressed 未验证点在曲线上 | fixed | fixed | M0 |
| S4-H4 | sm4 | ECB 模式不应暴露为可用选项 | fixed | fixed | M7 |
| S4-H5 | sm4 | 密钥和敏感数据缺乏安全清零 | fixed | documented | M10 |
| HT-H1 | http | TLS 服务端配置缺少 ClientAuth 设置 | fixed | fixed | M6 |
| HT-H2 | http | NewTLCPTransport 不验证 config nil | fixed | fixed | M6 |
| HT-H3 | http | TLS 配置未设置 CurvePreferences | fixed | fixed | M6 |
| HT-H4 | http | CBC 密码套件包含在默认列表中 | fixed | fixed | M9 |
| HT-H5 | http | 混合监听器握手在 Accept 中同步执行 | fixed | fixed | M9 |
| S3-H2 | sm3 | HKDF-Extract 不一致 | fixed | fixed | M7 |
| S3-H3 | sm3 | KDF 函数缺少输入验证 | fixed | fixed | M0 |
| S9-H1 | sm9 | 测试使用全零伪随机数生成密钥 | fixed | fixed | M7 |
| S9-H2 | sm9 | UID 输入缺乏空值验证 | fixed | fixed | M6 |
| S9-H3 | sm9 | Sign 参数命名与语义模糊 | fixed | fixed | M7 |
| Z-H1 | zuc | 测试缺少标准测试向量验证 | fixed | fixed | M6 |
| Z-H2 | zuc | 缺少 IV 复用安全文档警告 | fixed | fixed | M7 |
| Z-H3 | zuc | 密钥内存未安全清除 | fixed | documented | M10 |

## 5. 内存安全（documented 项的解决方案）

5 个通过机制 + 文档完成的内存清零项：

| ID | 模块 | 解决方案 |
|----|------|----------|
| X-H4 | smx509 | `internal/memsecure` + TLCP 自动清零 |
| S2-H2 | sm2 | 清零辅助函数 + 安全文档 |
| S2-H3 | sm2 | 内存管理文档提供最佳实践 |
| S4-H5 | sm4 | `sm4.ZeroKey` / `ZeroNonce` API（GCM 高级封装，原 sm4gcm 已合并） |
| Z-H3 | zuc | `memsecure.ZeroBytes` 适用所有密钥类型 |

详见 [`memory-management.md`](memory-management.md)。

## 6. 架构层面的结论

1. **封装层依赖 gmsm 的正确性**——sm2/sm3/sm4/sm9/zuc 的核心密码运算委托给
   `emmansun/gmsm v0.43.0`，该库实现质量较高（常量时间操作、拒绝采样、标准向量验证）。
   封装层自身的安全问题集中在**输入验证**与**内存管理**两类。

2. **TLCP 当前定位**——自研 TLCP 握手已替换为 gotlcp 封装，包仍标 EXPERIMENTAL
   待独立审计；底层 gotlcp 自身的审计状态决定生产可用性。

3. **模糊测试已引入**——`tlcp` / `smx509` 对握手解析、证书解析、PKCS#8 解密等
   路径提供 fuzz 入口（`FuzzHandshakeMessage`、`FuzzRecord`、`FuzzParseCertificate`、
   `FuzzDecryptPrivateKey` 等）。

## 7. 回归测试覆盖

CRITICAL/HIGH 项主要通过集成测试与黑盒测试覆盖，而非独立的单元测试。关键映射：

| 审计 ID | 覆盖方式 |
|---------|----------|
| T-1 ~ T-4 | TLCP 集成测试（自研阶段） |
| X-1 ~ X-3 | `smx509/decrypt_test.go` |
| X-4 | `cert/cert_test.go` + smx509 CertPool raw DER |
| S4-1 | `test/sm4_extra_test.go: TestBlackBox_SM4_GCM` |
| S4-2 | tlcp CBC `hmac.Equal` 常量时间比较 |
| S2-1 | `test/sm2_compress_test.go: TestBlackBox_SM2_BytesToPrivateKey` |
| H-1 | `test/hybrid_http_test.go` + `test/http_detect_test.go` |
| T-H6/T-H7/X-H1/S3-H2 | `tlcp/audit_test.go` |
| X-H3 | `smx509/audit_test.go` |
| S2-H1 | `sm2/audit_test.go` |
| HT-H1 | `test/tls13_blackbox_test.go` |
| HT-H2/HT-H3 | `http/http_test.go` |
| S9-H1/S9-H2 | `test/sm9_test.go` |
| Z-H1 | `zuc/zuc_test.go`（ZUC-128 / EEA3 标准向量） |

全量回归命令：`go test ./...`（当前 20 包全绿）。

## 8. gosec 配置

gosec 扫描配置见 [`gosec-configuration.md`](gosec-configuration.md)。
