# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — 依赖升级与 Go 1.26 加解密适配（破坏性 API，无向后兼容）

- vendored quic-go fork：subtree 升级到上游 **v0.62.0**（根模块 require 同步 v0.62.0）。适配上游事件枚举拆分：`GMCryptoSetup` 按 0-RTT/Handshake/1-RTT 三级分别发出读密钥事件；服务端 `EventReceived1RTTReadKeys` 推迟到客户端 Finished 验证后（对齐 crypto/tls 语义，避免提前 `Finish` Handshake CRYPTO 流）。上游同版本带来的改进随之生效：`errors.AsType`、流优先级调度（RFC 9218）、`dropEncryptionLevel` 简化、pre-Go1.26 构建标签清理。注意：v0.60→v0.61 曾手工同步导致本次 subtree 合并基线偏旧，17 个 fork 零增量文件的冲突已逐一验证取上游侧，此后合并基线恢复正常（见 quic-go/PATCHES.md）

- 依赖：`emmansun/gmsm` v0.44.0→v0.44.1、`golang.org/x/crypto` v0.54.0→v0.57.0、`stretchr/testify` v1.11.1→v1.12.1（间接 `x/net`/`x/sys` 随升；vendored quic-go fork 不变）
- `tls13gm`：`GenerateCurveSM2KeyPair` **去掉 `io.Reader` 参数**——对齐 Go 1.26 随机数硬化语义（`crypto/ecdh.Curve.GenerateKey` 等已忽略调用方 reader），临时密钥恒取 `crypto/rand`
- `tls13gm`：`CurveSM2ECDHE` 内部从废弃的 `elliptic.Curve.ScalarMult` 手工裸乘迁移到 gmsm `ecdh`（`crypto/ecdh` 的 SM2 等价实现，常数时间点运算）：私钥标量校验 [1, N-1]、对端点在曲线校验、无穷远点拒绝、输出定长 32 字节；行为等价（KAT/互通测试不变）
- `tls13gm`：`DeriveEarlySecret` 返回 `([]byte, error)`（随 `sm3.HKDFExtract` 签名变化级联）
- `sm3`：HKDF 构造从 `golang.org/x/crypto/hkdf` 迁移到标准库 `crypto/hkdf`（Go 1.25+）；`HKDFExtract` 返回 `([]byte, error)`。`GODEBUG=fips140=only` 下按标准库语义 fail-closed（拒绝在 FIPS-only 进程内做 SM3 派生）
- `kdf`：PBKDF2 从 `golang.org/x/crypto/pbkdf2` 迁移到标准库 `crypto/pbkdf2`（Go 1.24+），导出签名不变
- `smx509`：PBES2 解密同迁标准库 `crypto/pbkdf2`；新增攻击者可控 PBKDF2 迭代次数上界（10,000,000，对齐 `kdf` 包 `maxIteration` 的 CPU 耗尽防护，此前仅有下界）
- 已核验（Go 1.27.1 实测）：smx509 枚举守卫共享前缀仍然准确（SignatureAlgorithm≤16 / PublicKeyAlgorithm≤4 / ExtKeyUsage≤13），stdlib ML-DSA 值冲突防护不变

## [v0.5.0] - 2026-08-22

> 本版本为**破坏性安全加固版本**：对全库进行对抗性 Go 最佳实践审查后，根治全部 High/Medium 缺陷及配套 Low/Info 项。多处公共 API 有破坏性变更（见文末清单）。

### Fixed — 第三轮对抗性审查（5 项 High）

- `https`：HybridListener.Accept 对客户端可触发错误（连上即断/明文字节/握手失败）直接返回，而 `http.Server.Serve` 对非临时 Accept 错误会退出整个服务循环——**单个 TCP 包即可永久杀死 Hybrid 服务器**。根治：重写为惰性连接（对齐 `crypto/tls.Listener` 语义），Accept 零 I/O、永不因客户端行为失败，嗅探+握手推迟到首次 Read/Write，慢速客户端不再占用 accept 循环
- `tlcp`：握手消息 3 字节长度无上限——恶意对端每连接可驻留 ~16MB。对齐 crypto/tls：非证书消息 16KB、Certificate 128KB 硬上限
- `tlcp`：Listener.Accept 同步握手且无 deadline——单个不发数据的连接永久阻塞全部后续连接。改为惰性握手；`DialWithDialer` 的 Timeout 现在也约束握手；新增 `DialContext`
- `tlcp`：客户端 Finished 校验失败泄露期望 verify_data（master_secret 派生材料）——与服务端既有反 oracle 策略对齐
- `sshca`：maxDuration 检查被 uint64 溢出精确绕过（delta=2^55 时乘积≡0），可签出 ~10^12 年有效期 SSH 证书。全 uint64 域比较 + int64 范围守卫

### Fixed — 第三轮对抗性审查（Medium）

- `tlcp`：加密 alert 记录此前按密文解析（CCS 后的 close_notify 被误报为错误而非 `io.EOF`）→ 先解密后解析，close_notify 映射 io.EOF；Read 路径补读锁满足 `net.Conn` 并发契约；Close 的 close_notify 写入有界化（5s deadline，任何传输不再挂起）；CBC 填充校验整体移植 crypto/tls 常量时间算法（定长扫描、统一错误、MAC 时间均衡）；会话恢复从不可达死代码接线为可用功能（`Config.SessionCache` + 导出 API + 24h 过期）；握手失败发送 fatal alert；每条记录校验版本字节；`Close` 清零 halfConn 密钥
- `tls13gm`：客户端在服务端拒绝 PSK 时按 RFC 8446 §7.1 用全零重算 early secret（此前任何票据被拒都导致硬失败）；服务端票据解密失败优雅降级继续完全握手（§4.2.11）；`Zero()` 补 ECDHE 临时私钥清零（PFS 兜底）；pinning 模式（nil Roots + 回调）真正可用；线上中间证书参与链构建；服务端补 phase guard + 双端 Failed 终态（transcript 中途失败拒绝重试）；ECDHE 标量副本/票据明文 PSK/binder 失败路径密钥全部用后清零；扩展列表解析 fail-closed
- `quicgm`：`Listen` 的 ctx 真正传播取消；packet protector 构造时快照密钥（解除与 `Handshaker.Zero()` 的共享别名竞争）；`Conn.Close` 清零复用材料；防重放缓存按到期分桶（`Check` 摊还 O(1)，消除持锁全量扫描延迟尖峰）
- `smx509`：`copyCertFields` 三条静默跳过路径全部可观测（skipped 列表 + `CopyFieldDriftHook`），CRL 签发前断言撤销条目数一致（fail-closed 阻止"空名单 CRL"）；`mapEnumField` 重做 fail-closed 并补 ExtKeyUsage 守卫；OCSP ResponderID 补 ASN.1 Class 校验；`ToSMX509Certificate` 补 stdlib 回退；新增 `IsSM3CertID`（SM3 响应的 IssuerHash 谎报问题的显式判别）
- `crl`：标准 CA 路径 nil key panic（落在无 recover 的后台 goroutine 即崩进程）、`opts==nil` panic、`GetCRLNumber` 截断全部修复；fanout 全部子生成器停止后自动退出（停机泄漏）
- `https`：Transport 补 TLSHandshakeTimeout/IdleConnTimeout/ResponseHeaderTimeout；TLCP 拨号真传播 ctx 取消；客户端 nil Timeout 从无限改为默认 120s；删除服务端无效且误导的 `ServerOptions.InsecureSkipVerify`
- `jwt`：HMAC signer 深拷贝 secret（`Zeroize` 不再清调用方数组）；`NewSM2SM3` 曲线 fail-fast；`IssueWithExpiry` 拒绝 ttl<=0
- `kmc`：CSR 补默认 keyUsage 扩展；`https.DetectMode` 增加证书公钥回落判别（只配证书的客户端不再走错协议）

### Changed（破坏性 API，无向后兼容）

- `tlcp`：`NewLRUSessionCache`（原 `NewTLCPLRUSessionCache`）返回导出 `SessionCache`/`SessionState`；删除 `GetCipherSuites`/`IsAvailable`/`GetStandardSummary`/`Version12`；`GetCipherSuiteName`→`CipherSuiteName`；`ConnectionState` 删 `VerifiedChains`（永不填充的契约谎言）、增 `DidResume`/`NegotiatedProtocol`；`Config` 增 `SessionCache`
- `https`：`HybridListener` 导出（主路径调用者可用调优方法）；`ServerOptions` 删 `InsecureSkipVerify`；客户端 nil Timeout 语义变更
- `smx509`：`SMX509ToStdCertificate(s)`→`ToStdCertificate(s)`；`NewOCSPResponseTemplate` 签名变更；新增 `CopyFieldDriftHook`/`IsSM3CertID`
- `crl`：`CRLCache`→`Cache`、`CRLRecord`→`Record`、`NewMemoryCRLCache`→`NewMemoryCache`；`GetCRLNumber` 返回 `*big.Int`
- `tls`：`GetCipherSuites`→`CipherSuites`
- `tlcp` 行为变更：Listener.Accept 不再内联握手（crypto/tls 语义）

### Added

- CI 新增 golangci-lint 门禁（errcheck/revive/gocritic/errorlint/nilerr 等，v2.13.1）+ 仓库级 `.golangci.yml`（每条豁免附理由）；当前全仓 0 告警
- 新增约 20 个回归测试锁定本全部修复行为

### Removed

- `tlcp`：死代码清理（未用方法/类型/保 import 变量/冗余 Get* 包装）；`randReader` 包级可变全局；冗余 `nolint:staticcheck`（SA1019 已配置层统一豁免）

### Fixed — 第二轮审查剩余项(Low/Info 补完)

- `smx509`:OCSP `RevocationReason` 取值域校验(RFC 5280 §5.3.1:0-6/8-10,7 未分配);无 `NextUpdate` 响应对 `ThisUpdate` 施加 7 天本地 max-age(封住无界重放窗口);内嵌 responder 证书自身有效期校验;`ExtractOCSPRequestNonce` 拒绝尾部垃圾与重复 nonce 扩展;`CurrentTime` SM2 路径限制文档标注
- `sshca`:新增 `NewAuthorityWithRevocation`(吊销谓词接入 `CertChecker.IsRevoked`,验证端点不再仅依赖消费端 sshd 兜底);`SignCertificate` 校验 `req.Type` 与签名器类型一致(此前 user 签名器静默签出 HostCert 语义的 user 证书)
- `crl`:撤销原因码取值域校验(同 RFC 5280 §5.3.1);`Get()` 共享数组文档标注
- `tlcp`:session 缓存键 SNI 规范化(RFC 6066 大小写不敏感,消除缓存碎片)
- `sm2`:导出 `ErrDecryptFailed`(调用方可 `errors.Is` 匹配信封解密失败);空消息/可变全局/`from==to` 别名行为文档标注
- `sm4`:CMAC O(n) 缓冲内存特征文档标注(大输入调用方决策依据)
- `tls13gm`:session ticket 注释与 newest-first 约定对齐

### Fixed — 第二轮安全审查修复（18 项 Medium + 关键 Low，逐模块审查）

**crl**（fail-closed 与健壮性）：
- 空撤销列表（非 nil 空切片）回源存储——此前误传 `[]` 会签发"空名单"权威 CRL，所有已撤销证书在依赖方恢复有效
- 非法/非正数序列号拒绝整轮签发（此前 fail-open 静默跳过 = 漏撤销）
- 显式 CRL number 强制单调且拒绝负数（RFC 5280 §5.2.3）
- `StartAutoUpdate` 非正 interval 返回错误（此前 ticker panic 于子 goroutine 不可 recover，崩溃进程）；接口签名变更为返回 error
- `validity`/`numberSource` 读写纳入锁（数据竞争）；fanout stop 通道构造期创建（stop-before-start 泄漏）+ 刷新循环超时

**sm2**：
- `NewPrivateKeyFromInt` 标量域校验 [1, n-1]——越界 panic（不可信输入 DoS）与负数静默取绝对值均转为错误
- `AdjustCipherOrder` 对 ASN.1 输入显式拒绝（此前静默输出 Plain 编码，契约违背）
- `PlainToASN1` 拒绝压缩点输入（此前静默产出损坏 ASN.1）
- `NewEncrypterOpts(EncodingASN1, OrderC1C2C3)` 显式报错（此前静默忽略 order）

**sshca**：
- `ValidateCertificate` 放行 force-command（`CertChecker.SupportedCriticalOptions` 此前为空，所有带 force-command 的合法证书被误拒，手写白名单成死代码）
- 签发边界应用 critical option 白名单（force-command 非空/source-address 校验/未知拒绝——签发与验证对称）
- `ValidateSourceAddresses` 拒绝空串与非规范 CIDR（此前签出 OpenSSH 拒收的"死证书"）
- `BuildKRL` 预校验 CA wire 格式（非法 KRL 被 OpenSSH 整体拒收，sshd 对 KRL 解析错误拒绝所有密钥）
- host 证书不再写 permit-* 扩展（PROTOCOL.certkeys 规定 host 证书无扩展）；`NewCertificateSigner` 校验 certType

**smx509**：
- OCSP 签名分流：SM2 曲线的 `*ecdsa.PrivateKey` 显式拒绝（此前静默降级为普通 ECDSA-SHA256，违反包内自身约定）
- 新增 `VerifyOCSPResponseNonce`：客户端发出 nonce 后响应缺失/不匹配必须拒绝（RFC 6960 §4.4.1 完整绑定，防剥离重放）
- nonce 最小长度 16 字节（RFC 8954 §2.3，构造与解析双侧）；空 nonce 扩展报错而非空切片

**keycrypt / kmc**：
- PBKDF2 迭代 100k → 600k（对齐仓库 smx509 自定的 MUST 标准；此前库内自相矛盾）
- 密码副本与私钥中间态清零（memsecure 惯例对齐）；RSA <2048 位与 nil curve 构造期拒绝

**tls13gm**：
- 0-RTT age 改为 RFC 8446 §4.2.10 的 mod 2^32 语义（此前显式回绕守卫误拒约 14% ticket 生命末段的诚实客户端 0-RTT；新鲜度策略交还 acceptor）

### Added

- **`smx509`: OCSP 响应级扩展支持**（自 mekbuda 的 vendored fork 上移，消除双端维护）：
  - `CreateOCSPResponseExt`：RFC 6960 §4.4.1 nonce 回显（responseExtensions 标准位置）+
    统一签名分流（SM2 SM2+SM3 / RSA / ECDSA / Ed25519；`x/crypto/ocsp.CreateResponse`
    不支持响应级扩展，其验签表亦无 Ed25519/SM2 条目）
  - `ExtractOCSPRequestNonce` / `ResponseNonce`：请求与响应侧 nonce 提取
  - `OCSPErrorResponse`：responseStatus-only 错误响应
  - 互操作实测：带 nonce 响应可被 `x/crypto` `ParseResponse`、本包 SM2 解析器与
    `openssl ocsp` 解析（Go `encoding/asn1` 宽松忽略尾部元素，无需双位置模式）
- **`kmc` 包**：国密双证模型 KMC 抽象（`Manager` 接口 + `LocalKMC` 占位实现，
  GM/T 0018 SDF 实现方可直接接入；CSR subject 参数化）
- **`crl` 包**：CRL 生成 / 缓存 / fan-out / 解析（接口注入式 `Authority` /
  `CRLCache` / `NumberSource`；SM2 密钥自动 SM2+SM3 签名；RFC 5280 §5.2.3
  CRL number 单调性语义）
- **`keycrypt` 包**：私钥加密落盘（PKCS#8 PBES2 AES-256-GCM + PBKDF2-SHA256，
  与 `smx509.DecryptPEMPrivateKey` 格式闭环、明文一律拒绝）+ RSA/ECDSA/Ed25519/SM2
  密钥生成器族（默认算法选择属应用策略，库不预设）
- **`sshca` 包**：SSH 证书 CA——用户/主机证书签发（maxDuration 强制）、
  `CertChecker` 完整验签、**KRL 生成**（`x/crypto/ssh` 只有解析无生成，Go 生态
  稀缺能力）
- `smx509,sm2`：补全 PKIX 公钥解析与标量私钥构造 API（#21）
- `sm2`：C1C2C3 拼接顺序与 Plain 密文编码支持（#19）

### Fixed

- `smx509`：OCSP `revokedInfo` reason=unspecified(0) 时省略 reason 字段
  （RFC 5280 §5.3.1 SHOULD be absent；新旧构造 API 一致生效，行为变更）
- `sm4`：CMAC 迁移至 `gmsm/cbcmac`，keywrap 状态文档化

### Changed

- `sm3`/`kdf`/`sha`：HKDF / PBKDF2 迁移至 `golang.org/x/crypto` 参考实现
- 四个新包补齐 `doc.go`（英文 godoc 规范，与既有包对齐）；README 能力矩阵与
  根 `doc.go` Sub-packages 清单同步
- `sshca` KRL 默认 comment 中性化（应用名 → `pollux-go SSH KRL`）
- `sm4` 一键封装测试覆盖 47% → 91%

### Removed

- **`http/` deprecation shim（破坏性变更）**：`http`→`https` 重命名的兼容层，
  自 v0.1.1 起在全部已发布版本中提供，迁移窗口远超弃用政策。下游将
  `github.com/iuboy/pollux-go/http` 的 import 迁移到 `github.com/iuboy/pollux-go/https`
  （API 面除包名外完全一致）
- `sha` 包中无消费者的死代码入口

## [v0.4.2] - 2026-07-31

tlcp resume 缓存键修复（SNI 优先绑定），修复 `TestNative_Resume_NativeServer`
在端口不复用场景下的 flaky。详见 tag 注释。

## [v0.4.1] - 2026-07-31

安全审计加固：H1-H3 / M1-M8 / P3 共 15 项（GCM nonce panic DoS、0-RTT
fail-closed、resume 缓存键绑定 SNI、OCSP 时效校验、信封错误脱敏、密钥缓冲区
清零、JWT audience 等）。详见 tag 注释。
