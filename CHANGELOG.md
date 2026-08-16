# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
