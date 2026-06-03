# pollux-go 密码学代码审计报告

**审计日期**: 2026-05-24
**审计范围**: 全部密码学模块 (sm2, sm3, sm4, sm9, smx509, tlcp, zuc, http, tls)

## 总体统计

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

---

## CRITICAL 级别问题（必须修复）

### [T-1] TLCP ServerKeyExchange 签名完全未验证 — 中间人攻击
**文件**: `tlcp/handshake.go:141-157`

客户端在 ECDHE 模式下收到 ServerKeyExchange 后仅解析临时公钥，**完全忽略签名**。攻击者可伪造临时公钥实施中间人攻击，控制 ECDHE 共享密钥。

### [T-2] TLCP 解密失败时使用全零 preMasterSecret — 密钥可恢复
**文件**: `tlcp/handshake.go:401-403`

ECDHE/ECC 解密失败时，服务端用 `make([]byte, 32)`（全零）作为 preMasterSecret 继续。攻击者可发送任意 ClientKeyExchange，结合公开的 random 值计算 master_secret，解密/篡改通信。正确做法应使用随机假 preMasterSecret。

### [T-3] TLCP CBC 模式 IV 固定重用 — 语义安全性破坏
**文件**: `tlcp/cipher_suites.go:212-225`

SM4-CBC 加密器在整个连接生命周期内使用固定 IV。相同密钥下所有记录使用相同 IV，攻击者可通过 XOR 密文块推断明文关系。应在每次加密后将最后密文块写回 IV。

### [T-4] TLCP 证书验证 fallback 使用自签名根池 — CA 验证绕过
**文件**: `tlcp/handshake.go:686-702`

`verifyOneCert` 在标准验证失败后回退到 smx509，但将待验证证书自身加入根池。这意味着**任何自签名证书都能通过验证**，完全绕过 CA 信任链。

### [X-1] smx509 CBC 解密缺少密文对齐校验 — panic/DoS
**文件**: `smx509/cert.go:410-411`

`decryptBlock` 的 CBC 路径直接将密文传给 `CryptBlocks`，未检查长度是否为块大小整数倍。恶意 PKCS#8 数据可触发 panic 导致进程崩溃。同样问题存在于 legacy PEM 解密路径 (`cert.go:483-484`)。

### [X-2] smx509 Legacy IV 长度未校验 — 越界 panic
**文件**: `smx509/cert.go:466-476`

直接取 `iv[:8]` 但未检查 IV 长度，恶意 DEK-Info 头可导致 slice 越界 panic。

### [X-3] smx509 PBKDF2 迭代次数无下限 — 允许极弱密钥派生
**文件**: `smx509/cert.go:340-350`

攻击者可构造 PKCS#8 文件将 PBKDF2 迭代次数设为 0 或 1，使暴力破解成本极低。OWASP 建议最低 600,000 次。

### [X-4] smx509 证书验证 Roots 转换为空池 — 功能缺陷
**文件**: `smx509/verify.go:69-77`

将 `x509.CertPool.Subjects()` 迁移到 smx509 CertPool 时，迭代 subjects 但什么都没做（`_ = subj`），导致自定义根证书池始终为空。

### [S4-1] SM4 GCM nonce 生成后不返回 — 数据无法解密
**文件**: `sm4/modes.go:243-255`

`encryptGCM` 在 nonce 为空时内部生成 nonce，但生成的 nonce 不包含在返回值中。调用者收到密文后无法解密。

### [S4-2] SM4 CBC padding oracle — 时序侧信道
**文件**: `sm4/modes.go:114-128`

`PKCS7Unpad` 的验证循环执行次数取决于填充值大小（1-16 次），攻击者可通过时序差异逐字节解密密文。

### [S4-3] SM4 GCM/CTR/CFB 无 IV 重用保护
**文件**: `sm4/modes.go` 全部 Encrypt/Decrypt

函数签名不阻止调用者传入已用过的 IV。GCM nonce 重用会导致认证密钥泄露，CTR 重用导致密钥流重用。

### [S3-1] SM3 HKDF-Expand 手工构建 HMAC — 绕过审计过的标准库
**文件**: `sm3/hkdf.go:33-65`

`hkdfExpand` 手动构建 HMAC 计算（ipad/opad XOR），完全绕过已有的 `NewHMAC`（基于 `crypto/hmac`）。过长的 PRK 会被静默截断。RFC 引用编号错误（5866 应为 5869）。

### [S2-1] SM2 BytesToPrivateKey 缺少私钥标量范围验证
**文件**: `sm2/compress.go:85-98`

从字节恢复私钥时不验证 D 是否在 `[1, n-2]` 范围内。零私钥可产生可伪造签名，超范围私钥产生错误公钥。

### [H-1] HTTP 混合监听器协议检测可被伪造 — 降级攻击
**文件**: `http/listener.go:58-75`

仅通过 TLS 记录头 version 字段区分 TLCP 和 TLS。攻击者可构造 0x0101 版本强制走 TLCP 路径，或发送 0x0301 走 TLS 路径，绕过安全策略较宽松的协议。

### [H-2] HTTP NewClient default 分支传入 nil TLCP 配置 — panic
**文件**: `http/client.go:59`

当 mode 不匹配 ModeTLCP 或 ModeTLS 时，将 nil 传给 NewTLCPTransport，导致运行时 panic 或创建不安全连接。

---

## HIGH 级别问题（强烈建议修复）

### TLCP 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| T-H1 | `tlcp/cipher_suites.go:112-135` | GCM 解密不验证显式 Nonce 等于序列号 |
| T-H3 | `tlcp/cipher_suites.go:276-292` | CBC MAC 输入缺少 content_type 和 version 字段 |
| T-H4 | `tlcp/record.go:49-74` | 记录层未验证版本号 |
| T-H5 | `tlcp/handshake.go:94-104` | 客户端不验证 ServerHello 版本号 — 降级攻击 |
| T-H6 | `tlcp/key_exchange.go:22` | ECDHE 曲线类型不明确（P-256 vs SM2） |
| T-H7 | `tlcp/handshake.go` | 无重放攻击防护 — 全零 random 未检查 |

### smx509 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| X-H1 | `smx509/cert.go:44-47` | SM2 公钥识别仅依赖曲线对象实例，无法区分 SM2 与 ECDSA P-256 |
| X-H3 | `smx509/cert.go:178-185` | CSR 类型转换可能不安全，应使用 ParseCertificateRequest 重新解析 |
| X-H4 | `smx509/cert.go` | 密码/密钥材料未在内存中清零 |

### SM2 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| S2-H1 | `sm2/key_exchange.go:59` | API 拼写错误 (RepondKeyExchange)，兼容性风险 |
| S2-H2 | `sm2/key_exchange.go:48-68` | KeyExchangePerformer 未暴露 Destroy 方法，临时私钥未清除 |
| S2-H3 | `sm2/compress.go:79-82` | PrivateKeyToBytes 无内存清理指引 |
| S2-H4 | `sm2/compress.go:50-57` | UnmarshalUncompressed 未验证点是否在曲线上 |

### SM4 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| S4-H4 | `sm4/modes.go:94-95` | ECB 模式不应暴露为可用选项 |
| S4-H5 | 多个文件 | 密钥和敏感数据缺乏安全清零 |

### HTTP 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| HT-H1 | `http/config.go:126-138` | TLS 服务端配置缺少 ClientAuth 设置 |
| HT-H2 | `http/client.go:14-25` | NewTLCPTransport 不验证 config 是否为 nil |
| HT-H3 | `http/config.go:126-138` | TLS 配置未设置 CurvePreferences |
| HT-H4 | `http/config.go:167-174` | CBC 密码套件包含在默认列表中 — Lucky13 风险 |
| HT-H5 | `http/listener.go:62-74` | 混合监听器握手在 Accept 中同步执行 — DoS |

### SM3 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| S3-H2 | `sm3/hkdf.go:10-18` | HKDF-Extract 直接用 H(salt||ikm) 而非 HMAC(salt,ikm)，与 RFC 5869 不一致 |
| S3-H3 | `sm3/kdf.go:9-11` | KDF 函数缺少输入验证，上游大 keyLen 会 panic |

### SM9 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| S9-H1 | `sm9/sm9_test.go:100-101` | 测试使用全零伪随机数生成密钥 |
| S9-H2 | `sm9/sm9.go:48-49` | UID 输入缺乏空值验证 |
| S9-H3 | `sm9/sm9.go:63` | Sign 参数命名为 hash 但实际接收原始消息，API 语义模糊 |

### ZUC 模块

| 编号 | 文件 | 问题 |
|------|------|------|
| Z-H1 | `zuc/zuc_test.go` | 测试缺少标准测试向量验证 |
| Z-H2 | `zuc/zuc.go` | 缺少 IV 复用安全文档警告 |
| Z-H3 | `zuc/zuc.go` | 密钥内存未安全清除 |

---

## 修复优先级建议

### P0 — 立即修复（安全漏洞，可被远程利用）

1. **[T-1]** ServerKeyExchange 签名验证 — 防止中间人攻击
2. **[T-2]** 随机假 preMasterSecret — 防止密钥恢复
3. **[T-3]** CBC IV 链式更新 — 恢复语义安全性
4. **[T-4]** 证书验证 fallback 修复 — 恢复 CA 验证
5. **[X-1][X-2]** CBC 密文对齐和 IV 长度校验 — 防止 DoS
6. **[S4-1]** GCM nonce 返回给调用者 — 修复功能性缺陷

### P1 — 尽快修复（安全加固）

7. **[T-H4]** 记录层版本号验证
8. **[T-H5]** ServerHello 版本号验证
9. **[T-H3]** CBC MAC 输入完整性
10. **[X-3]** PBKDF2 迭代次数下限
11. **[S3-1]** HKDF 使用标准 HMAC 实现
12. **[S2-1]** BytesToPrivateKey 范围验证
13. **[H-1]** 混合监听器安全加固

### P2 — 计划修复（代码质量/安全最佳实践）

14. 敏感数据内存清零（smx509, sm2, sm4, zuc）
15. 输入验证增强（sm9 UID, sm3 HKDF PRK 长度, zuc bearer 范围）
16. API 文档安全警告（sm4 IV 唯一性, zuc IV 复用, smx509 DES/MD5 弱算法标注）
17. 测试补充标准向量（zuc 3GPP TS 35.221）

---

## 架构层面的建议

1. **TLCP 实现尚不适合生产使用**: 4 个 CRITICAL 级别漏洞（签名未验证、全零密钥材料、IV 重用、CA 验证绕过）意味着该实现在当前状态下不应暴露在不可信网络中。

2. **包装层依赖 gmsm 的正确性**: sm2/sm3/sm4/sm9/zuc 的核心密码学运算均委托给 `emmansun/gmsm v0.43.0`，该库实现质量较高（使用常量时间操作、拒绝采样随机数、标准测试向量验证）。封装层本身的安全问题主要是输入验证和内存管理。

3. **建议引入模糊测试**: 对 TLCP 握手解析、smx509 证书解析、PKCS#8 解密等路径进行 fuzz testing，可发现更多边界条件问题。
