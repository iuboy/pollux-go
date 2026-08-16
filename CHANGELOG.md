# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
