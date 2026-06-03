# pollux-go test 目录黑盒 API 测试实施计划

## 0. 文档定位

本文是 `test/` 目录黑盒 API 测试的详细实施计划，承接：

- `docs/plan/test-blackbox-completion-plan.md`
- `docs/plan/implementation-master-plan.md`
- `docs/plan/AUDIT_REPORT.md`

本文只规划 `test/` 目录中的跨包黑盒测试。各模块内部白盒、半白盒、fuzz 测试仍放在对应包目录中。

当前基线日期：2026-05-25。

## 1. 测试边界

`test/` 目录测试必须满足：

1. 只通过 `github.com/ycq/pollux/<package>` 的公开 API 调用功能。
2. 不访问未导出函数、未导出类型、内部字段或构造未导出协议消息。
3. 不复用包内测试 helper，除非 helper 本身位于 `test/` 目录。
4. 网络测试只使用 `127.0.0.1`、临时端口、短超时。
5. 外部进程、外网、Tongsuo 互通测试默认跳过，必须显式启用。
6. 对随机输出只验证长度、格式、可逆性、唯一性抽样和拒绝行为，不断言固定密文。
7. 每个公开 API 至少覆盖一个成功路径；安全敏感 API 必须覆盖失败路径。

## 2. 当前 test 目录状态

当前文件：

```text
test/cert_chain_test.go
test/cross_library_test.go
test/decrypt_test.go
test/gmstd_test.go
test/hybrid_http_test.go
test/interop_crypto_test.go
test/sm2_extra_test.go
test/sm2_key_test.go
test/sm4_extra_test.go
test/sm9_test.go
test/testutil_test.go
test/tlcp_http_test.go
test/tls_http_test.go
test/zuc_test.go
```

当前基线问题：

- `go test ./...` 失败在 `github.com/ycq/pollux/test`。
- 失败集中在 SM9 Wrap/Unwrap：
  - `TestBlackBox_SM9_WrapUnwrapKey`
  - `TestBlackBox_SM9_WrapKeyASN1`
  - `TestBlackBox_SM9_WrapKey_DifferentKeyLengths`
- 根因是 `sm9.WrapKey` wrapper 公开返回语义和底层 `gmsmSM9.WrapKey` 返回语义不一致。

M0 必须先修复 SM9 语义并恢复全量测试基线，再继续扩展测试矩阵。

## 3. 目标目录结构

建议逐步把 `test/` 目录调整为按模块和场景命名：

```text
test/
  testutil_test.go
  fixtures_test.go

  gmstd_blackbox_test.go
  sm2_blackbox_test.go
  sm2_key_blackbox_test.go
  sm2_envelope_blackbox_test.go
  sm3_blackbox_test.go
  sm4_blackbox_test.go
  sm4_modes_blackbox_test.go
  sm4_keywrap_blackbox_test.go
  sm9_blackbox_test.go
  cert_blackbox_test.go
  cert_tlcp_blackbox_test.go
  smx509_blackbox_test.go
  smx509_chain_blackbox_test.go
  zuc_blackbox_test.go
  tls_registry_blackbox_test.go
  tlcp_blackbox_test.go
  http_blackbox_test.go
  hybrid_http_blackbox_test.go

  interop_crypto_test.go
  cross_library_test.go

  tls13_blackbox_test.go      // Phase M2 新增
  quic_blackbox_test.go       // Phase M3 新增
  sm4gcm_blackbox_test.go     // Phase M4 新增
  quicgm_blackbox_test.go     // Phase M4 新增
  tls13gm_blackbox_test.go    // Phase M6 新增，experimental
```

迁移原则：

- 现有文件不必一次性重命名，避免无意义 churn。
- 新增测试优先落到目标命名文件。
- 当某个旧文件被集中修改时，再顺手迁移到目标命名。

## 4. 命名规范

测试名：

```text
TestBlackBox_<Module>_<API>_<Scenario>
TestBlackBox_<Module>_<Feature>_<FailureReason>
TestBlackBox_<Module>_<AuditID>_<Regression>
TestInterop_<Module>_<Peer>_<Scenario>
```

示例：

```text
TestBlackBox_SM9_WrapKey_RoundTrip
TestBlackBox_SM9_WrapKey_WrongUID
TestBlackBox_SMX509_Verify_LeafAsRootRejected
TestBlackBox_TLCP_T1_ServerKeyExchangeTamperRejected
TestInterop_SM9_GMSM_RawWrapUnwrap
```

断言风格：

- 成功路径用 `t.Fatalf` 阻断后续断言。
- 多 case 输入验证用 table test。
- 错误路径必须检查 `err != nil` 或 `ok == false`。
- 不检查错误字符串作为主断言，除非错误类型是公开契约。
- panic 只在“必须不 panic”的测试里用 recover 包装。

## 5. testutil 实施计划

现有 `test/testutil_test.go` 已包含：

- `certPath`
- `readCert`
- `loadSM2KeyPair`
- `buildTLCPConfig`
- `echoHandler`
- `getFreeAddr`

需要补充的 helper：

| Helper | 用途 |
|--------|------|
| `mustSM2Key(t)` | 生成 SM2 私钥和公钥 |
| `mustSM9SignKeys(t, uid)` | 生成 SM9 签名主密钥和用户密钥 |
| `mustSM9EncryptKeys(t, uid)` | 生成 SM9 加密主密钥和用户密钥 |
| `mustRandom(t, n)` | 生成测试随机字节 |
| `tamperCopy(in []byte)` | 返回篡改后的副本，避免原地污染 |
| `requireNotPanic(t, fn)` | malformed 输入测试 |
| `newLocalHTTPServer(t, handler)` | 标准 HTTP/TLS 本地测试 |
| `newTLCPHTTPServer(t, cfg, handler)` | TLCP HTTP 本地测试 |
| `buildCertChain(t, opts)` | 生成 root/intermediate/leaf 测试链 |
| `rootPoolFromCerts(t, certs...)` | 构建标准 x509 root pool |
| `skipExternalInterop(t)` | 统一处理外部依赖跳过 |

完成定义：

- helper 只服务黑盒测试，不暴露到生产包。
- helper 不隐藏被测 API 的错误语义。
- helper 名称清楚表达测试意图。

## 6. M0：恢复 test 包绿色基线

### 6.1 SM9 WrapKey 当前失败修复

目标文件：

```text
test/sm9_test.go
```

必须通过的用例：

| 测试名 | 公开 API | 断言 |
|--------|----------|------|
| `TestBlackBox_SM9_WrapKey_RoundTrip` | `WrapKey`, `UnwrapKey` | `cipher` 非空，`key` 长度等于 keyLen，unwrap 后等于 key |
| `TestBlackBox_SM9_WrapKey_DifferentKeyLengths` | `WrapKey`, `UnwrapKey` | keyLen 16/24/32 均通过 |
| `TestBlackBox_SM9_WrapKey_WrongUID` | `UnwrapKey` | 错误 UID 解封装失败 |
| `TestBlackBox_SM9_WrapKey_TamperedCipher` | `UnwrapKey` | 篡改 raw cipher 解封装失败 |
| `TestBlackBox_SM9_WrapKey_InvalidKeyLen` | `WrapKey` | keyLen 0、-1 返回错误 |
| `TestBlackBox_SM9_WrapKeyASN1_RoundTrip` | `WrapKeyASN1` | ASN.1 格式走正确解封装路径 |
| `TestBlackBox_SM9_WrapKey_RawAndASN1NotConfused` | raw/ASN.1 APIs | raw 和 ASN.1 格式混用必须失败或显式报错 |

验收：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

完成定义：

- `test` 包不再失败。
- 包内测试和黑盒测试对 `WrapKey` 公开语义一致。
- raw 和 ASN.1 格式边界被测试固定。

## 7. M1：现有公开 API 黑盒矩阵

### 7.0 cert 统一证书 facade

详细实施计划见：

- `docs/plan/cert-x509-abstraction-implementation-plan.md`

目标文件：

```text
test/cert_blackbox_test.go
test/cert_tlcp_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `ParseCertificate` / `ParseCertificatePEM` | 标准和 SM2 证书均可解析 | invalid DER/PEM |
| `Pool.AppendCertsFromPEM` | root raw DER 不丢失 | 空 PEM、非证书 PEM |
| `VerifyCertificate` | 正确 root 验证成功 | wrong root、leaf-as-root、nil roots 策略 |
| `LoadKeyPairPEM` | 标准/SM2 cert key 加载成功 | cert/key 不匹配 |
| `LoadDualCertificatePEM` | TLCP sign/enc 双证书加载成功 | 缺失 PEM、key mismatch |
| `VerifyDualCertificate` | sign/enc KeyUsage 正确时成功 | wrong KeyUsage、wrong CA |
| `BuildTLCPConfig` | 同时填充 root pool 和 raw root certs | 缺 sign/enc cert 失败 |

测试名：

```text
TestBlackBox_Cert_ParseCertificate_StandardAndSM2
TestBlackBox_Cert_Pool_RawDERRoundTrip
TestBlackBox_Cert_Verify_WithCorrectRoot
TestBlackBox_Cert_Verify_WithWrongRoot
TestBlackBox_Cert_Verify_LeafAsRootRejected
TestBlackBox_Cert_LoadDualCertificatePEM
TestBlackBox_Cert_BuildTLCPConfig_PopulatesRootCertificates
```

验收：

```text
go test ./cert ./test -run 'Cert'
```

### 7.1 gmstd

目标文件：

```text
test/gmstd_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `SM3Hash` | 输出 32 字节、确定性、不同输入不同 hash | nil/empty 输入有明确结果 |
| `SM3HashHex` | 输出 64 字符 hex、与 `SM3Hash` 一致 | empty 输入 |
| `SM3HashForPublicKey` | SM2 公钥可 hash | nil、非公钥类型失败 |
| `ComputeSM2UserID` | SM2 公钥输出确定性 UID | nil、非公钥类型失败 |
| `GenerateSM4Key` | 输出 16 字节，两次不同 | 无 |
| `GenerateNonce` | 指定长度输出 | 0、负数失败 |
| `SM2KDF` | 指定长度、确定性、prefix 行为 | 0 长度、nil z |

补充测试名：

```text
TestBlackBox_GMSTD_SM3Hash_EmptyInput
TestBlackBox_GMSTD_SM3HashHex_MatchesBytes
TestBlackBox_GMSTD_SM3HashForPublicKey_InvalidInput
TestBlackBox_GMSTD_ComputeSM2UserID_InvalidInput
TestBlackBox_GMSTD_SM2KDF_NilInput
```

验收：

```text
go test ./test -run 'GMSTD|SM3Hash|SM2KDF|GenerateNonce|GenerateSM4Key'
```

### 7.2 sm2 基础签名、加密、PEM 和点编码

目标文件：

```text
test/sm2_blackbox_test.go
test/sm2_key_blackbox_test.go
test/sm2_envelope_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `GenerateKey` | 返回可签名私钥 | nil reader 或失败 reader |
| `GenerateKeyDefault` | 返回有效私钥 | 无 |
| `SignASN1` / `VerifyASN1` | 签名验签通过 | 错 hash、错公钥、篡改签名 |
| `SignWithSM2` / `VerifyWithSM2` | UID 绑定验签通过 | 错 UID、错消息、篡改签名 |
| `EncryptASN1` / `Decrypt` | 明文 round trip | 错私钥、篡改密文、nil key |
| `SM2SignerOption` / `NewSM2SignerOption` | 可用于签名 | nil UID、force 标志行为 |
| `P256` | 返回非 nil 曲线 | 曲线参数基础检查 |
| `NewPrivateKey` / `NewPublicKey` | DER round trip | nil、短 DER、随机 DER |
| `PrivateKeyToBytes` / `BytesToPrivateKey` | 私钥字节 round trip | 0、n、n+1、长度错误 |
| `PublicKeyToBytes` / `BytesToPublicKey` | 公钥字节 round trip | 无效点、长度错误 |
| `CompressPublicKey` / `DecompressPublicKey` | 压缩点 round trip | 无效前缀、短输入 |
| `MarshalUncompressed` / `UnmarshalUncompressed` | 非压缩点 round trip | 不在曲线上的点 |
| `ParsePrivateKeyFromPEM` / `WritePrivateKeyToPEM` | PEM round trip | invalid PEM、wrong type |
| `ParsePublicKeyFromPEM` / `WritePublicKeyToPEM` | PEM round trip | invalid PEM、wrong type |
| `EnvelopeEncrypt` / `EnvelopeDecrypt` | envelope round trip | nil key、篡改 encrypted key/ciphertext |
| `EnvelopeEncryptSM4` / `EnvelopeDecryptSM4` | SM4 envelope round trip | nil key、wrong key、篡改 nonce/ciphertext |
| `NewKeyExchangePerformer` | 双方派生相同 key | nil peer、错误 keyLen、UID 不匹配 |

优先补充测试名：

```text
TestBlackBox_SM2_BytesToPrivateKey_RejectsZero
TestBlackBox_SM2_BytesToPrivateKey_RejectsOrder
TestBlackBox_SM2_UnmarshalUncompressed_RejectsOffCurvePoint
TestBlackBox_SM2_SignWithSM2_WrongUID
TestBlackBox_SM2_EncryptASN1_TamperedCiphertext
TestBlackBox_SM2_PEM_InvalidBlocks
TestBlackBox_SM2_EnvelopeSM4_TamperedNonce
TestBlackBox_SM2_KeyExchange_UIDMismatch
```

验收：

```text
go test ./test -run 'SM2'
```

### 7.3 sm3

目标文件：

```text
test/sm3_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `New` | 实现 hash.Hash，Size=32，BlockSize 合理 | Reset 后可复用 |
| `Sum` | 标准向量、确定性 | empty input |
| `NewHMAC` | HMAC 确定性，key/message 改变输出改变 | nil key、empty message |
| `KDF` | 指定长度、确定性 | 0 长度、nil z、大长度 |
| `HKDF` | extract+expand 输出指定长度 | 0、负数、超过 RFC 上限 |
| `HKDFExtract` | 输出 32 字节 | empty salt、empty ikm |
| `HKDFExpand` | 多 block 输出 | prk 空、length 超限 |

优先补充测试名：

```text
TestBlackBox_SM3_Sum_StandardVectors
TestBlackBox_SM3_New_StreamingMatchesSum
TestBlackBox_SM3_HMAC_VerifyWithCryptoHMAC
TestBlackBox_SM3_KDF_ZeroLength
TestBlackBox_SM3_HKDF_OverMaxLength
TestBlackBox_SM3_HKDF_NegativeLength
```

验收：

```text
go test ./test -run 'SM3|HKDF|KDF|HMAC'
```

### 7.4 sm4

目标文件：

```text
test/sm4_blackbox_test.go
test/sm4_modes_blackbox_test.go
test/sm4_keywrap_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `NewCipher` | 标准向量、BlockSize=16 | key 长度错误 |
| `GenerateKey` | 16 字节，两次不同 | 无 |
| `NewGCM` | AEAD round trip | key 长度错误 |
| `NewCBCEncrypter` / `NewCBCDecrypter` | block mode round trip | key/iv 长度错误 |
| `NewCTR` | stream round trip | key/iv 长度错误 |
| `NewCFBEncrypter` / `NewCFBDecrypter` | stream round trip | key/iv 长度错误 |
| `GenerateIV` | 16 字节，两次不同 | 无 |
| `PKCS7Pad` / `PKCS7Unpad` | pad/unpad round trip | padding 篡改、blockSize 错误 |
| `Encrypt` / `Decrypt` | ECB/CBC/CTR/CFB/GCM round trip | unsupported mode、wrong IV、tamper |
| `KeyWrap` / `KeyUnwrap` | 16/24/32 key round trip | wrong KEK、tamper、长度错误 |
| `NewCMAC` / `ComputeCMAC` | MAC 确定性 | wrong key、tamper |
| `VerifyCMAC` | 正确 MAC true | wrong MAC/key/message false |
| `NewCMACHash` | hash.Hash 行为 | invalid key |
| `DeriveKey` | 指定长度、label/context 影响输出 | length 0/负数、key 为空 |

优先补充测试名：

```text
TestBlackBox_SM4_Block_StandardVector
TestBlackBox_SM4_GCM_AADTamperRejected
TestBlackBox_SM4_GCM_TagTamperRejected
TestBlackBox_SM4_CBC_InvalidPaddingRejected
TestBlackBox_SM4_Encrypt_UnsupportedMode
TestBlackBox_SM4_KeyWrap_TamperedCiphertext
TestBlackBox_SM4_CMAC_WrongKeyRejected
TestBlackBox_SM4_KDF_InvalidLength
```

验收：

```text
go test ./test -run 'SM4|CMAC|KeyWrap'
```

### 7.5 sm9

目标文件：

```text
test/sm9_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `GenerateSignMasterKey` | 返回 master/public | 无 |
| `GenerateSignUserKey` | UID 派生 user key | nil master、empty UID 策略 |
| `Sign` / `Verify` | 签名验签通过 | wrong UID、wrong message/hash、tamper |
| `GenerateEncryptMasterKey` | 返回 master/public | 无 |
| `GenerateEncryptUserKey` | UID 派生 user key | nil master、empty UID 策略 |
| `Encrypt` / `Decrypt` | 明文 round trip | wrong UID、wrong key、tamper |
| `WrapKey` / `UnwrapKey` | raw KEM round trip | wrong UID、tamper、invalid keyLen |
| `WrapKeyASN1` | ASN.1 KEM round trip | raw/ASN.1 混用失败 |
| `GenerateSignMasterKeyFromReader` | reader 注入成功 | failing reader |
| `GenerateEncryptMasterKeyFromReader` | reader 注入成功 | failing reader |

优先补充测试名：

```text
TestBlackBox_SM9_SignVerify_WrongUID
TestBlackBox_SM9_EncryptDecrypt_TamperedCiphertext
TestBlackBox_SM9_WrapKey_RoundTrip
TestBlackBox_SM9_WrapKey_InvalidKeyLen
TestBlackBox_SM9_WrapKey_RawAndASN1NotConfused
TestBlackBox_SM9_GenerateSignMasterKeyFromReader_FailingReader
```

验收：

```text
go test ./sm9 ./test -run 'SM9'
```

### 7.6 smx509

目标文件：

```text
test/smx509_blackbox_test.go
test/smx509_chain_blackbox_test.go
test/decrypt_test.go
test/cert_chain_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `IsSM2Key` / `IsSM2PublicKey` | SM2 key true | RSA/ECDSA/nil false |
| `CreateCertificate` | root/intermediate/leaf 生成 | nil args、wrong signer |
| `CreateCertificateRequest` | CSR 生成 | nil template/key |
| `ParseCertificate` / `ParseCertificatePEM` | DER/PEM round trip | invalid DER/PEM |
| `ParseCertificateRequest` | CSR parse | invalid DER |
| `CheckCertificateRequestSignature` | valid CSR 成功 | tampered CSR 失败 |
| `SignatureAlgorithmForPrivateKey` | SM2/RSA/ECDSA 映射 | unknown key |
| `PublicKeyAlgorithmForPrivateKey` | key algorithm 映射 | unknown key |
| `ExtractPublicKey` | 从私钥提公钥 | nil/unknown key |
| `MarshalPKIXPublicKey` | public key DER | nil/unknown key |
| `MarshalECPrivateKey` / `ParseECPrivateKey` | EC private key round trip | invalid DER |
| `DecryptPEMPrivateKey` / `DecryptPEMPrivateKeyDER` | encrypted PEM 解密 | wrong password、malformed PEM、bad IV |
| `Verify` | 正确 root chain 成功 | wrong root、nil root、自签 leaf |
| `VerifyDualCerts` | 签名/加密双证书成功 | mismatched CA、wrong KeyUsage |
| `CreateRevocationList` | CRL 生成 | nil issuer/signer |
| `CreateOCSPResponse` / parse helpers | OCSP round trip | invalid request/response |

审计回归优先测试名：

```text
TestBlackBox_SMX509_X1_PKCS8CBCMisalignedCiphertextRejected
TestBlackBox_SMX509_X2_LegacyPEMShortIVRejected
TestBlackBox_SMX509_X3_WeakPBKDF2IterationsRejected
TestBlackBox_SMX509_X4_CustomRootPoolVerifiesChain
TestBlackBox_SMX509_Verify_LeafAsRootRejected
TestBlackBox_SMX509_Verify_WrongRootRejected
```

验收：

```text
go test ./smx509 ./test -run 'SMX509|Cert|X509|Decrypt|OCSP|CRL'
```

### 7.7 zuc

目标文件：

```text
test/zuc_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `NewCipher` | stream 加解密 round trip | key/iv 长度错误 |
| `NewEEACipher` | EEA stream 输出 | invalid key、bearer/direction 边界 |
| `NewEIAHash` | EIA MAC 输出 | invalid key、bearer/direction 边界 |
| `NewHash` | MAC hash 输出 | key/iv 长度错误 |
| `Encrypt` | plaintext round trip 或 deterministic keystream | invalid key |
| `MAC` | 输出长度、确定性 | wrong key/data 变化 |

优先补充测试名：

```text
TestBlackBox_ZUC_StandardVectors
TestBlackBox_ZUC_NewCipher_InvalidIVSize
TestBlackBox_ZUC_EEA_DifferentBearerChangesOutput
TestBlackBox_ZUC_EIA_TamperedDataChangesMAC
TestBlackBox_ZUC_MAC_InvalidKey
```

验收：

```text
go test ./zuc ./test -run 'ZUC'
```

### 7.8 tls registry

目标文件：

```text
test/tls_registry_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `GetCipherSuites` | national/international/hybrid 返回预期集合 | invalid mode 返回错误 |
| `IsNationalCipherSuite` | 国密 suite true | 非国密 suite false |
| `CipherSuiteName` | 已知 suite 返回名称 | unknown suite 返回明确名称 |
| `NationalCipherSuites` | 返回副本，不可被外部修改污染 | 修改返回 slice 不影响下一次调用 |

补充测试名：

```text
TestBlackBox_TLSRegistry_NationalCipherSuites_ReturnsCopy
TestBlackBox_TLSRegistry_CipherSuiteName_Unknown
TestBlackBox_TLSRegistry_GetCipherSuites_InvalidMode
```

验收：

```text
go test ./tls ./test -run 'TLSRegistry|CipherSuite'
```

### 7.9 tlcp

目标文件：

```text
test/tlcp_blackbox_test.go
test/tlcp_http_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `NewConfig` | 默认配置字段合理 | 默认不跳过验证 |
| `VersionFromString` | 已知版本 parse 成功 | invalid version 失败 |
| `IsAvailable` | 返回 true | 无 |
| `GetCipherSuites` | 返回支持 suite | 返回副本 |
| `IsCipherSuite` | 已知 suite true | unknown false |
| `GetCipherSuiteName` | 已知 suite 名称 | unknown suite |
| `Client` / `Server` | net.Pipe 本地握手 | 错证书、版本错误 |
| `NewListener` / `Listen` / `Dial` | 本地 round trip | 证书验证失败 |
| `DialWithDialer` | 自定义 dialer 成功 | timeout/failing dialer |
| `LoadConfigFile` | 配置加载 | invalid path/json |
| `Enable` / `Disable` | tls.Config 标记行为 | nil tls.Config |
| `LoadDualCertPair` / `LoadDualCertPairFromPEM` | 双证书加载 | missing/mismatched cert |
| `ValidateDualCertPair` / `VerifyDualCertPair` | 双证书验证 | wrong CA/KeyUsage |

审计回归测试名：

```text
TestBlackBox_TLCP_T1_ServerKeyExchangeTamperRejected
TestBlackBox_TLCP_T2_ClientKeyExchangeFailureNotPredictable
TestBlackBox_TLCP_T3_CBCRecordsDoNotReuseFixedIV
TestBlackBox_TLCP_T4_SelfSignedLeafRejectedWithoutRoots
TestBlackBox_TLCP_RecordVersionMismatchRejected
TestBlackBox_TLCP_ServerHelloVersionMismatchRejected
```

说明：

- 如果某些审计回归无法纯黑盒构造，应在 `tlcp/` 包内做半白盒测试，并在 `test/` 中覆盖可观察行为。
- `test/` 中的 TLCP 测试应优先验证真实连接的成功/失败结果。

验收：

```text
go test ./tlcp ./test -run 'TLCP'
```

### 7.10 http

目标文件：

```text
test/http_blackbox_test.go
test/tls_http_test.go
test/tlcp_http_test.go
test/hybrid_http_blackbox_test.go
```

公开 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `DetectMode` | sign cert 判定 TLCP/TLS | nil cert、非 SM2 cert |
| `NewTLCPTransport` | TLCP client round trip | nil config 行为明确 |
| `NewTLSTransport` | TLS client round trip | nil config 行为明确 |
| `NewClient` | mode TLCP/TLS 成功 | invalid mode 返回错误，不 panic |
| `ListenAndServe` / `Serve` | TLCP/TLS/hybrid 服务 | invalid opts、nil handler |
| `ListenAndServeTLCP` | TLCP HTTP 成功 | missing cert/config |
| `ListenAndServeTLSNat` | TLS HTTP 成功 | invalid cert/config |
| `NewHybridListener` | TLCP/TLS 分流成功 | unknown record version 拒绝、ProtocolMask 过滤、HandshakeTimeout 超时 |

优先补充测试名：

```text
TestBlackBox_HTTP_NewClient_InvalidModeReturnsError
TestBlackBox_HTTP_NewTLCPTransport_NilConfigRejected
TestBlackBox_HTTP_TLS_RoundTrip
TestBlackBox_HTTP_TLCP_RoundTrip
TestBlackBox_HTTP_Hybrid_UnknownRecordVersionRejected
TestBlackBox_HTTP_Hybrid_SlowHandshakeTimeout
```

验收：

```text
go test ./http ./test -run 'HTTP|Hybrid|TLS'
```

## 8. 新功能黑盒测试矩阵

### 8.1 tls13

目标文件：

```text
test/tls13_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `ServerConfig` | TLS1.3 server config | 空证书失败 |
| `ClientConfig` | TLS1.3 client config | 默认不跳过验证 |

测试名：

```text
TestBlackBox_TLS13_ServerConfig_RequiresCertificate
TestBlackBox_TLS13_ClientConfig_DefaultVerifyEnabled
TestBlackBox_TLS13_HTTPRoundTrip
TestBlackBox_TLS13_TLS12PeerRejected
```

### 8.2 quic

目标文件：

```text
test/quic_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `Listen` / `Dial` | echo round trip | 空 ALPN、ALPN mismatch、wrong root |
| stream helpers | bidirectional stream | context timeout |

测试名：

```text
TestBlackBox_QUIC_EchoRoundTrip
TestBlackBox_QUIC_EmptyALPNRejected
TestBlackBox_QUIC_ALPNMismatchRejected
TestBlackBox_QUIC_UntrustedServerCertRejected
TestBlackBox_QUIC_MTLSRequired
TestBlackBox_QUIC_DoesNotImportTLCP
```

### 8.3 sm4gcm

目标文件：

```text
test/sm4gcm_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `GenerateKey` | 16 字节随机 key | 无 |
| `GenerateNonce` | 12 字节随机 nonce | failing reader |
| `Seal` / `Open` | round trip | wrong key、wrong nonce、AAD/tag tamper |
| `SealRandomNonce` | 返回 nonce + ciphertext | nonce 唯一性抽样 |

测试名：

```text
TestBlackBox_SM4GCM_SealOpen_RoundTrip
TestBlackBox_SM4GCM_Open_AADTamperRejected
TestBlackBox_SM4GCM_Open_TagTamperRejected
TestBlackBox_SM4GCM_Seal_InvalidNonceLength
TestBlackBox_SM4GCM_SealRandomNonce_ReturnsNonce
```

### 8.4 quicgm

目标文件：

```text
test/quicgm_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| `GenerateSessionKeys` | key sizes and IDs valid | failing reader |
| `Seal` / `Open` | envelope round trip | wrong key、payload/AAD/MAC tamper |
| `MACSM3` / `VerifyMACSM3` | valid MAC true | wrong MAC false |

测试名：

```text
TestBlackBox_QUICGM_Envelope_RoundTrip
TestBlackBox_QUICGM_Envelope_MetadataTamperRejected
TestBlackBox_QUICGM_Envelope_PayloadTamperRejected
TestBlackBox_QUICGM_Envelope_WrongKeyRejected
TestBlackBox_QUICGM_MACSM3_WrongMACRejected
```

### 8.5 tls13gm experimental

目标文件：

```text
test/tls13gm_blackbox_test.go
```

计划 API：

| API | 成功路径 | 失败/边界路径 |
|-----|----------|---------------|
| constants | RFC8998 suite ID 正确 | 不提供 handshake builder |
| HKDF-SM3 wrapper | 向量对齐 | length 超限 |
| SM4-GCM AEAD wrapper | round trip | tamper |

测试名：

```text
TestBlackBox_TLS13GM_CipherSuiteConstants
TestBlackBox_TLS13GM_HKDFSM3_KnownVector
TestBlackBox_TLS13GM_SM4GCM_TamperRejected
TestBlackBox_TLS13GM_NoProductionTLSBuilder
```

## 9. 互通和跨库测试

目标文件：

```text
test/interop_crypto_test.go
test/cross_library_test.go
```

分类：

| 类型 | 默认行为 | 启用方式 |
|------|----------|----------|
| gmsm 库内互通 | 默认运行 | `go test ./test -run 'Interop'` |
| Tongsuo 进程互通 | 默认跳过 | 环境变量显式启用 |
| 外网 TLS 测试 | 默认跳过或 short 跳过 | 环境变量显式启用 |
| 长耗时互通 | `testing.Short()` 跳过 | 不加 `-short` |

建议环境变量：

```text
POLLUX_RUN_TONGSUO=1
POLLUX_RUN_EXTERNAL=1
POLLUX_TONGSUO_BIN=/path/to/tongsuo
```

互通测试命名：

```text
TestInterop_SM2_GMSM_SignVerify
TestInterop_SM4_GMSM_GCM
TestInterop_SM9_GMSM_RawWrapUnwrap
TestInterop_TLCP_Tongsuo_Client
TestInterop_TLCP_Tongsuo_Server
```

## 10. 执行批次

### Batch 0：恢复基线

任务：

1. 修复 SM9 WrapKey 公开语义。
2. 修正或补齐 SM9 raw/ASN.1 黑盒测试。
3. 运行全量测试。

验收：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

### Batch 1：补齐现有算法 API

任务：

1. gmstd 边界用例。
2. sm2 key/sign/encrypt/PEM/envelope/key exchange。
3. sm3 hash/HMAC/KDF/HKDF。
4. sm4 block/modes/CMAC/KeyWrap/KDF。
5. sm9 sign/encrypt/wrap。
6. zuc vectors 和错误输入。

验收：

```text
go test ./test -run 'GMSTD|SM2|SM3|SM4|SM9|ZUC'
go test ./...
```

### Batch 2：补齐证书和协议 API

任务：

1. smx509 证书链、CSR、PEM 解密、dual cert。
2. tls registry。
3. tlcp config/listener/dial/dual cert。
4. http TLS/TLCP/hybrid。

验收：

```text
go test ./test -run 'SMX509|Cert|X509|TLSRegistry|TLCP|HTTP|Hybrid'
go test ./...
```

### Batch 3：补齐审计回归

任务：

1. TLCP T-1/T-2/T-3/T-4。
2. SMX509 X-1/X-2/X-3/X-4。
3. SM4 S4-1/S4-2/S4-3。
4. SM2 S2-1。
5. SM3 S3-1/S3-H2。

验收：

```text
go test ./test -run 'T[0-9]|X[0-9]|S4|S3|S2|Audit'
go test ./...
```

### Batch 4：新增功能黑盒测试

任务：

1. tls13。
2. quic。
3. sm4gcm。
4. quicgm。
5. tls13gm experimental。

验收：

```text
go test ./test -run 'TLS13|QUIC|SM4GCM|QUICGM|TLS13GM'
go test ./...
```

## 11. 覆盖率和完成度追踪

建议维护一个 `test/coverage-matrix.md` 或在本文追加状态表。

字段：

| 字段 | 说明 |
|------|------|
| Module | 模块 |
| API | 公开 API |
| Success Test | 成功路径测试名 |
| Failure Test | 失败路径测试名 |
| Security Test | 篡改/错误身份/审计回归 |
| Interop Test | 互通测试名 |
| Status | missing/partial/done |

完成标准：

- 每个公开函数至少一个 success test。
- 返回 error 的 API 至少一个 failure test。
- 密码学认证、签名、加密 API 至少一个 tamper/wrong-key/wrong-identity test。
- 网络 API 至少覆盖 success、cert failure、timeout 或 invalid config。
- 审计项 fixed 前必须有 regression test。

## 12. CI 命令建议

默认 PR：

```text
go test ./...
```

黑盒专项：

```text
go test ./test -run 'BlackBox'
```

算法专项：

```text
go test ./test -run 'GMSTD|SM2|SM3|SM4|SM9|ZUC'
```

证书和协议专项：

```text
go test ./test -run 'SMX509|Cert|X509|TLCP|HTTP|TLS|Hybrid'
```

互通专项：

```text
go test ./test -run 'Interop' -short
```

发布前：

```text
go test ./...
go test -race ./...
go test ./test -run 'BlackBox|Interop'
```

## 13. 测试实现规则

必须：

1. 使用 `t.Helper()` 标记 helper。
2. 使用本地生成或 `test/cert` 固定 fixture，不依赖外网。
3. 修改输入前先 copy，避免污染后续断言。
4. 对 goroutine/server 使用 cleanup，避免端口泄露。
5. 网络测试设置短 timeout。
6. 对 skipped 测试写明跳过原因和启用条件。

禁止：

1. 在 `test/` 中 import 包内未导出路径。
2. 通过反射访问未导出字段。
3. 把 `InsecureSkipVerify` 当作默认成功路径。
4. 测试依赖执行顺序。
5. 对随机密文做固定值断言。
6. 让外网或外部进程测试阻塞默认 `go test ./...`。

## 14. 当前下一步

立即执行顺序：

1. 修复 `sm9.WrapKey` wrapper 的公开返回语义。
2. 更新 `test/sm9_test.go` 的测试名和 raw/ASN.1 边界用例。
3. 增加 `tamperCopy`、SM9 key helper、failing reader helper。
4. 运行：

```text
go test ./sm9 ./test -run 'SM9'
go test ./...
```

完成后进入 Batch 1，优先补 `sm2`、`sm3`、`sm4`、`zuc` 的公开 API 边界测试。
