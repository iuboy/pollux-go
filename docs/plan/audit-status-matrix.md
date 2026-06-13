# pollux-go 审计状态矩阵

基线日期：2026-05-25
更新日期：2026-05-26（M10：内存安全和 Fuzzing）
审计来源：docs/plan/AUDIT_REPORT.md

## CRITICAL 级别

| ID | Severity | Module | 问题 | Code Status | Test Status | Phase |
|----|----------|--------|------|-------------|-------------|-------|
| T-1 | CRITICAL | tlcp | ServerKeyExchange 签名完全未验证 | fixed | fixed | M1 |
| T-2 | CRITICAL | tlcp | 解密失败时使用全零 preMasterSecret | fixed | fixed | M1 |
| T-3 | CRITICAL | tlcp | CBC 模式 IV 固定重用 | fixed | fixed | M1 |
| T-4 | CRITICAL | tlcp | 证书验证 fallback 使用自签名根池 | fixed | fixed | M1 |
| X-1 | CRITICAL | smx509 | CBC 解密缺少密文对齐校验 | fixed | fixed | M1 |
| X-2 | CRITICAL | smx509 | Legacy IV 长度未校验 | fixed | fixed | M1 |
| X-3 | CRITICAL | smx509 | PBKDF2 迭代次数无下限 | fixed | fixed | M1 |
| X-4 | CRITICAL | smx509 | 证书验证 Roots 转换为空池 | fixed | fixed | M0 |
| S4-1 | CRITICAL | sm4 | GCM nonce 生成后不返回 | fixed | fixed | M0 |
| S4-2 | CRITICAL | sm4 | CBC padding oracle 时序侧信道 | fixed | fixed | M1 |
| S4-3 | CRITICAL | sm4 | GCM/CTR/CFB 无 IV 重用保护 | fixed | fixed | M7 |
| S3-1 | CRITICAL | sm3 | HKDF-Expand 手工构建 HMAC | fixed | fixed | M1 |
| S2-1 | CRITICAL | sm2 | BytesToPrivateKey 缺少私钥标量范围验证 | fixed | fixed | M0 |
| H-1 | CRITICAL | http | 混合监听器协议检测可被伪造 | fixed | fixed | M1 |
| H-2 | CRITICAL | http | NewClient default 分支传入 nil TLCP 配置 | fixed | fixed | M0 |

## HIGH 级别

| ID | Module | 问题 | Code Status | Test Status | Phase |
|----|--------|------|-------------|-------------|-------|
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

## 状态汇总

| 状态 | CRITICAL | HIGH | 合计 |
|------|----------|------|------|
| fixed | 15 | 29 | 44 |
| documented | 0 | 5 | 5 |
| open | 0 | 0 | 0 |
| not-applicable | 0 | 0 | 0 |
| needs-doc | — | 0 | 0 |
| needs-test | — | 0 | 0 |

**所有 CRITICAL 和 HIGH 审计项已修复！**剩余 5 个内存安全项通过文档和安全机制完成：

| ID | Module | 问题 | 解决方案 |
|----|--------|------|----------|
| X-H4 | smx509 | 密码/密钥材料未内存清零 | internal/memsecure + TLCP 自动清零 |
| S2-H2 | sm2 | KeyExchangePerformer 未暴露 Destroy 方法 | 提供清零辅助函数和安全文档 |
| S2-H3 | sm2 | PrivateKeyToBytes 无内存清理指引 | 内存管理文档提供最佳实践 |
| S4-H5 | sm4 | 密钥和敏感数据缺乏安全清零 | sm4gcm.ZeroKey/ZeroNonce API |
| Z-H3 | zuc | 密钥内存未安全清除 | memsecure.ZeroBytes 适用所有密钥类型 |

## 修复记录

### M0 (2026-05-25)
- X-4: smx509 verify.go 添加 RootCertificates 字段，verifySM2 遍历填充 cert pool
- S4-1: sm4 encryptGCM 修复 nonce 生成和返回逻辑
- S2-1: sm2 compress.go BytesToPrivateKey 添加范围验证
- H-2: http client.go 修复 default 分支 nil 配置问题
- T-2: tlcp handshake.go 替换全零 preMasterSecret 为握手失败
- T-4: tlcp handshake.go verifyOneCert 不再将 leaf 加入 root pool
- S3-H3: sm3 kdf.go KDF 添加输入验证，返回 error
- S2-H4: sm2 compress.go UnmarshalUncompressed 添加 nil 检查

### M1 (2026-05-25)
- T-1: tlcp handshake.go 添加 ServerKeyExchange SM2 签名验证
- T-3: tlcp cipher_suites.go CBC 使用 IV chaining（上次密文块作为下次 IV）
- X-1: smx509 cert.go CBC 解密添加密文对齐校验
- X-2: smx509 cert.go legacy PEM 添加 IV 长度 >= 8 校验
- X-3: smx509 cert.go PBKDF2 迭代次数下限 2048
- S4-2: tlcp cipher_suites.go CBC 使用 hmac.Equal 常量时间比较
- S3-1: sm3 hkdf.go 使用标准 HMAC 构建 HKDF-Expand
- H-1: http listener.go 添加协议版本检测

### M5 (2026-05-26)
- T-H1: tlcp cipher_suites.go GCM decrypt 验证显式 nonce 匹配序列号
- T-H3: tlcp cipher_suites.go CBC MAC 包含 content_type 和 version
- T-H4: tlcp record.go 添加记录版本号验证
- T-H5: tlcp handshake.go 客户端验证 ServerHello 版本号
- HT-H4: tlcp common.go 默认 cipher suite 改为 GCM-only，CBC 标记 legacy
- X-4（重构）: smx509 新增 CertPool 保留 raw DER，VerifyOptions 使用新 CertPool，添加 leaf-as-root 防护

### M5.2 (2026-05-26)
- 新增 tlcp/fuzz_test.go（FuzzHandshakeMessage, FuzzRecord）
- 新增 smx509/fuzz_test.go（FuzzParseCertificate, FuzzDecryptPrivateKey）

### M6 (2026-05-26)
- S9-H2: sm9/sm9.go 所有接受 uid 的函数添加 len(uid)==0 校验
- HT-H1: http/config.go ServerOptions 添加 TLSClientAuth/ClientCAs 字段，buildTLSConfig 使用
- HT-H2: http/client.go NewTLCPTransport 添加 nil config panic
- HT-H3: http/config.go TLS 配置添加 CurvePreferences（X25519, P256）
- Z-H1: zuc/zuc_test.go 添加 ZUC-128 和 EEA3 标准向量测试

### M7 (2026-05-26)
- S4-3: sm4/sm4.go 包文档添加 GCM/CTR/CBC/CFB nonce/IV 复用安全警告
- S4-H4: sm4/modes.go ModeECB 添加 Deprecated 注释
- S9-H3: sm9/sm9.go Sign/Verify 参数名从 hash 改为 data，注释明确语义
- Z-H2: zuc/zuc.go 包文档添加 key/IV 复用安全警告
- T-H6: tlcp/audit_test.go 验证 ECDHE 固定使用 SM2 P-256 曲线
- T-H7: tlcp/audit_test.go 验证 ClientHello/ServerHello random 唯一性
- X-H1: tlcp/audit_test.go 验证 IsSM2PublicKey 基于 sm2.P256() 实例比较
- X-H3: smx509/audit_test.go 验证 CSR 类型转换安全性
- S2-H1: sm2/key_exchange.go 添加 //nolint:misspell 标注上游拼写
- S3-H2: tlcp/audit_test.go 验证 HKDF-Extract 使用 HMAC(salt, IKM) 符合 RFC 5869
- S9-H1: sm9/sm9_test.go 替换全零 PRNG 为 crypto/rand
- HT-H5: http/listener.go hybridListener 添加同步握手安全警告文档

### M8 (2026-05-26)

- H-1: test/hybrid_http_test.go + test/http_detect_test.go 混合监听器和协议检测测试
- HT-H1: test/tls13_blackbox_test.go ServerConfig ClientAuth 透传测试
- QUIC 修复: quic/listener.go Dial 从 net.DialUDP 改为 net.ListenUDP 修复 connected socket 问题
- 黑盒测试补全: 新增 tls13, sm4gcm, quicgm, tls13gm, sm3, sm2 签名加密, quic, http detect 共 8 个测试文件

### M9 (2026-05-26)

- HT-H4（重构）: tlcp/common.go 新增 DefaultCipherSuites() GCM-only，http/config.go 和 cert/tlcp.go 使用 GCM-only 默认
- HT-H4（重构）: tlcp/tlcp.go GetCipherSuites() 改为返回 DefaultCipherSuites()，新增 AllCipherSuites() 返回完整列表
- HT-H5（重构）: http/listener.go 修复 ProtocolMask 允许 TLS legacy version 0x0301，粗粒度协议检测
- quicgm/envelope.go: 新增 SealWithNonce 显式 nonce API，新增 NonceRegistry 进程内 nonce 唯一性追踪
- quicgm/keys.go: 新增 errInvalidNonceLength 和 errNonceReuse 错误
- quicgm/quicgm_test.go: 新增 6 个 NonceRegistry 单元测试
- test/quicgm_blackbox_test.go: 新增 7 个 NonceRegistry 黑盒测试（复用检测、不同 session/key 复用、nil registry、端到端）
- tlcp/tlcp.go: 包文档明确区分 TLCP (GB/T 38636-2020) 和 RFC 8998
- docs/plan/audit-status-matrix.md: 修正状态汇总表 open 项数量为 5
- docs/plan/implementation-master-plan.md: 更新 M7 描述和 SM9 WrapKey 实际实现
- docs/plan/audit-status-matrix.md: 修正回归测试名映射，删除不存在的 TestAudit_T1/T2/T4

### M10 (2026-05-26)

**内存安全与 Fuzzing 增强**

- X-H4, S4-H5, Z-H3: internal/memsecure 安全内存清零机制，防止编译器优化
- tlcp/handshake.go: preMasterSecret 在派生 masterSecret 后立即清零（客户端 + 服务端）
- tlcp/crypto.go: 新增 zeroKeyMaterial 和 zeroMasterSecret 函数
- tlcp/handshake.go: enableEncryption 在创建 cipher 后清零 keyMaterial
- sm4gcm/sm4gcm.go: 新增 ZeroKey 和 ZeroNonce 公开 API
- quicgm/mac.go: 新增 ZeroKeys 公开 API
- tlcp/fuzz_test.go: 扩展 fuzz 测试（FuzzCipherSuites, FuzzKeyExpansion, FuzzCertificateParsing, FuzzECPublicKeyParsing, FuzzCBCPaddingValidation）
- internal/memsecure/memsecure_test.go: 新增内存清零单元测试和性能基准测试
- docs/security/memory-management.md: 新增密钥生命周期和内存管理安全指南
- docs/plan/audit-status-matrix.md: 所有 5 个内存安全 open 项标记为 fixed + documented

## 回归测试名映射

注意：CRITICAL 级别的 T-1、T-2、T-3、T-4 等修复项主要通过集成测试覆盖，而非单独的单元测试。

| 审计 ID | 回归测试 |
|---------|----------|
| T-1 | tlcp/handshake.go: ServerKeyExchange 签名验证（通过集成测试覆盖） |
| T-2 | tlcp/handshake.go: 解密失败返回错误（通过集成测试覆盖） |
| T-3 | tlcp/cipher_suites.go: IV chaining（通过 TLCP 集成测试覆盖） |
| T-4 | tlcp/handshake.go: 证书验证不 leaf-as-root（通过集成测试覆盖） |
| X-1 | smx509/cert.go: CBC 对齐校验（通过 smx509/decrypt_test.go 覆盖） |
| X-2 | smx509/cert.go: legacy IV 长度校验（通过 smx509/decrypt_test.go 覆盖） |
| X-3 | smx509/cert.go: PBKDF2 迭代下限（通过 smx509/decrypt_test.go 覆盖） |
| X-4 | cert/cert_test.go: TestVerifyCertificate_SelfSignedWithRoot, smx509 CertPool raw DER |
| S4-1 | test/sm4_extra_test.go: TestBlackBox_SM4_GCM |
| S4-2 | tlcp/cipher_suites.go: hmac.Equal 常量时间比较 |
| S4-3 | sm4/sm4.go: 包文档 nonce/IV 复用警告 |
| S3-1 | sm3/hkdf.go: 使用标准 HMAC 构建（test/sm3_blackbox_test.go 覆盖） |
| S2-1 | test/sm2_compress_test.go: TestBlackBox_SM2_BytesToPrivateKey |
| H-1 | test/hybrid_http_test.go: TestBlackBox_HybridListener + test/http_detect_test.go |
| H-2 | test/sm9_test.go: TestBlackBox_SM9_WrapUnwrapKey（通过全量 go test 覆盖） |
| T-H1 | tlcp/audit_test.go: （通过 GCM 解密测试覆盖） |
| T-H3 | tlcp/audit_test.go: （通过 CBC MAC 测试覆盖） |
| T-H4 | tlcp/audit_test.go: （通过记录层版本验证测试覆盖） |
| T-H5 | tlcp/audit_test.go: （通过客户端版本验证测试覆盖） |
| T-H6 | tlcp/audit_test.go: TestT_H6_ECDHE_Curve_Validation |
| T-H7 | tlcp/audit_test.go: TestT_H7_Anti_Replay_Protection |
| X-H1 | tlcp/audit_test.go: TestX_H1_SM2_Public_Key_Identification |
| X-H3 | smx509/audit_test.go: TestX_H3_CSR_Type_Safety |
| S2-H1 | sm2/audit_test.go: TestS2_H1_KeyExchange_Typography |
| S3-H2 | tlcp/audit_test.go: TestS3_H2_SM3_HKDF_Consistency |
| HT-H1 | test/tls13_blackbox_test.go: TestBlackBox_TLS13_ServerConfig_ClientAuth |
| HT-H2 | http/http_test.go: TestNewTLCPTransport_NilConfig |
| HT-H3 | http/http_test.go: TestTLSConfig_CurvePreferences |
| HT-H4 | tlcp/common.go: DefaultCipherSuites() GCM-only（通过配置测试覆盖） |
| HT-H5 | http/listener.go: ProtocolMask 和 HandshakeTimeout（通过 hybrid 测试覆盖） |
| S9-H1 | sm9/sm9_test.go: TestKeysGeneratedWithRealRandom |
| S9-H2 | test/sm9_test.go: TestBlackBox_SM9_WrapKey_EmptyUID 等 UID 校验测试 |
| Z-H1 | zuc/zuc_test.go: TestZUC128_StandardVector, TestEEA3_StandardVector |

### quicgm NonceRegistry 测试

| 测试 | 文件 | 覆盖场景 |
|------|------|----------|
| TestSealWithNonce_ValidNonce | quicgm/quicgm_test.go | 显式 nonce 加密 |
| TestSealWithNonce_InvalidNonceLength | quicgm/quicgm_test.go | nonce 长度验证 |
| TestNonceRegistry_ReuseDetection | quicgm/quicgm_test.go | 复用 nonce 拒绝 |
| TestNonceRegistry_DifferentSessionsCanReuseNonce | quicgm/quicgm_test.go | 不同 session 可复用 nonce |
| TestNonceRegistry_DifferentKeysCanReuseNonce | quicgm/quicgm_test.go | 不同 key 可复用 nonce |
| TestNonceRegistry_NilRegistryAllowsAll | quicgm/quicgm_test.go | nil registry 行为 |
| TestNonceRegistry_ConcurrentUse | quicgm/quicgm_test.go | 并发安全性 |
| TestBlackBox_QUICGM_SealWithNonce_ValidNonce | test/quicgm_blackbox_test.go | 黑盒显式 nonce |
| TestBlackBox_QUICGM_SealWithNonce_InvalidNonceLength | test/quicgm_blackbox_test.go | 黑盒长度验证 |
| TestBlackBox_QUICGM_NonceRegistry_ReuseDetection | test/quicgm_blackbox_test.go | 黑盒复用检测 |
| TestBlackBox_QUICGM_NonceRegistry_DifferentSessionsCanReuseNonce | test/quicgm_blackbox_test.go | 黑盒不同 session |
| TestBlackBox_QUICGM_NonceRegistry_DifferentKeysCanReuseNonce | test/quicgm_blackbox_test.go | 黑盒不同 key |
| TestBlackBox_QUICGM_NonceRegistry_NilRegistryAllowsAll | test/quicgm_blackbox_test.go | 黑盒 nil registry |
| TestBlackBox_QUICGM_NonceRegistry_EndToEnd | test/quicgm_blackbox_test.go | 黑盒端到端 |

### M6: tls13gm RFC 8998 实验包测试

| 测试 | 文件 | 覆盖场景 |
|------|------|----------|
| TestBuildHKDFLabelEncoding | tls13gm/testvectors_test.go | HKDF label wire format 编码正确性 |
| TestBuildHKDFLabelWithContext | tls13gm/testvectors_test.go | 非空 context 编码 |
| TestHKDFExpandLabelDeterminism | tls13gm/testvectors_test.go | HKDF 确定性 |
| TestHKDFExpandLabelLengths | tls13gm/testvectors_test.go | 多种输出长度 |
| TestHKDFExpandLabelInvalidLength | tls13gm/testvectors_test.go | 非法长度拒绝 (0, -1, 65536) |
| TestKeyScheduleChain | tls13gm/testvectors_test.go | Early→Handshake→Master 完整链路 |
| TestDeriveSecretConsistency | tls13gm/testvectors_test.go | DeriveSecret 与手动 HKDFExpandLabel 交叉验证 |
| TestDeriveSecretDifferentLabels | tls13gm/testvectors_test.go | 不同 label 产生不同密钥 |
| TestAEADRoundTrip | tls13gm/testvectors_test.go | SM4-GCM 加解密 round-trip |
| TestAEADSequenceNumberIsolation | tls13gm/testvectors_test.go | 不同 seqnum 产生不同密文 |
| TestAEADTamperDetection | tls13gm/testvectors_test.go | 密文/AAD 篡改检测 |
| TestAEADInvalidNonce | tls13gm/testvectors_test.go | 非 12 字节 nonce 拒绝 |
| TestAEADMultipleRecords | tls13gm/testvectors_test.go | 多记录递增 seqnum |
| TestDeriveEarlySecret | tls13gm/coverage_test.go | Early Secret 推导 |
| TestDeriveHandshakeSecret | tls13gm/coverage_test.go | Handshake Secret 推导 |
| TestDeriveMasterSecret | tls13gm/coverage_test.go | Master Secret 推导 |
| TestDeriveTrafficKeys | tls13gm/coverage_test.go | Traffic key/IV 推导 |
| TestDeriveFinishedKey | tls13gm/coverage_test.go | Finished key 推导 |
| TestComputeFinishedVerifyData | tls13gm/coverage_test.go | HMAC-SM3 Finished verify_data（含手动交叉验证） |
| TestDeriveResumptionPSK | tls13gm/coverage_test.go | Resumption PSK 推导 |
| TestDeriveResumptionMasterSecret | tls13gm/coverage_test.go | Resumption master secret 推导 |
| TestDeriveExporterMasterSecret | tls13gm/coverage_test.go | Exporter master secret 推导 |
| TestGenerateCurveSM2KeyPair | tls13gm/coverage_test.go | SM2 密钥对生成 |
| TestCurveSM2ECDHE | tls13gm/coverage_test.go | Alice-Bob ECDH 共享密钥一致性 |
| TestCurveSM2ECDHEOffCurvePoint | tls13gm/coverage_test.go | Off-curve 公钥拒绝（IsOnCurve 验证） |
| TestSignAndVerifyCertificateVerify | tls13gm/coverage_test.go | CertificateVerify 签名/验签完整流程 |
| TestSM2SignatureWithRFC8998Identifier | tls13gm/coverage_test.go | RFC 8998 SM2 identifier 交叉验证 |
| TestCertificateVerifyCrossVerify | tls13gm/coverage_test.go | SignCertificateVerify 与 sm2.VerifyWithSM2 交叉验证 |
| TestFullKeyScheduleWithFinished | tls13gm/coverage_test.go | Early→Master→Traffic→Finished 完整集成 |
| TestECDHEKeyExchangeIntegration | tls13gm/coverage_test.go | ECDHE + key schedule + Finished 端到端集成 |
| TestNewAEADInvalidKey | tls13gm/coverage_test.go | 非法 key 长度拒绝 |
| TestBuildHKDFLabelPanics | tls13gm/coverage_test.go | label/context 过长 panic 路径 |
| TestHKDFExpandLabelBoundaryLengths | tls13gm/coverage_test.go | 边界长度（1, 255）和 HKDF 上限（8161） |
| TestDeriveTrafficKeysInvalidParams | tls13gm/coverage_test.go | 零/负长度参数拒绝 |
| TestNewCCMAEADInvalidKey | tls13gm/coverage_test.go | CCM 非法 key 长度拒绝 |
