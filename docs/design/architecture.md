# pollux-go 架构与设计

本文是 pollux-go 的架构参考：项目定位、概念边界、传输/安全路线、包职责、
标准依据与关键设计约束。

## 1. 项目定位

pollux-go 是 **Go 语言国密（GM）算法与协议的集成工具包，不是密码学实现**。

- 核心算法（SM2/SM3/SM4/SM9/ZUC）全部委托 [`emmansun/gmsm`](https://github.com/emmansun/gmsm)，
  继承其实现质量（常量时间操作、拒绝采样、标准测试向量）。
- pollux-go 在原语之上补充：协议集成（TLCP 1.1、RFC 8998 栈、QUIC）、SM2 感知
  的 X.509 处理、Go 习惯封装 API 与密钥材料安全清零。

封装层自身的安全工作主要是**输入验证**与**密钥内存管理**。

## 2. 概念边界

三组容易混淆的概念：

| 概念 | 定义 | pollux-go 包 |
|------|------|--------------|
| **TLCP** | GB/T 38636-2020，国标传输层密码协议，基于 TLS 1.2 框架，采用**双证书**（签名 + 加密）体系 | `tlcp`（基于 gotlcp） |
| **RFC 8998** | IETF 标准 *ShangMi Cipher Suites for TLS 1.3*，在 TLS 1.3 框架内注册国密套件，不改握手流程 | `tls13gm` + `quicgm` |
| **标准 TLS 1.3 / QUIC** | RFC 8446 / RFC 9000-9001，非国密 | `tls13` / `quic` / `tls` |

- **TLCP 与 RFC 8998 不兼容**——TLCP 基于 TLS 1.2，RFC 8998 基于 TLS 1.3，密码套件 ID 与握手流程都不同。
- **`tls` 包只是套件 ID/名称注册表**，不实现握手，常量不能传给 `crypto/tls.Config.CipherSuites`——Go 标准库不识别国密套件。
- **QUIC 强制 TLS 1.3 握手**（RFC 9001），所以 TLCP 不能直接用于 QUIC。

## 3. 传输与安全路线

pollux-go 的传输栈均已达生产或互通可用，按是否使用国密分三类：

### 路线 A — 标准 TLS 1.3 / QUIC（✅ 生产）

基于 `crypto/tls` + `quic-go`，非国密。包：`quic`、`tls13`、`http`（TLS13 profile）。标准完备，Go 生态完全支持。

### 路线 B — 应用层国密（✅ 生产）

QUIC TLS 1.3 传输安全 + 应用层 SM2 证书认证、HMAC-SM3、SM4-GCM 负载加密。适合在不依赖传输层国密标准时使用国密算法。包：`sm2`/`sm3`/`sm4` 原语 + `sm2/envelope.go`。

### 路线 C — RFC 8998 国密栈（✅ 互通已验证）

`TLS_SM4_GCM_SM3`（0x00C6）+ SM3 transcript + HKDF-SM3 + SM2-SM3 签名 + curveSM2 + SM4-GCM QUIC 包保护。包：`tls13gm`（握手引擎 + 密码原语）、`quicgm`（RFC 9001 §5 packet protection + Listen/Dial/DialEarly 连接层）。Go `crypto/tls` 与 `quic-go` 上游不原生支持 RFC 8998，pollux-go 自带完整 `tls13gm` 握手引擎，并通过 vendored `quic-go/` fork 注入 GMCryptoSetup 驱动状态机。TLS 握手层已与 BabaSSL/Tongsuo 全场景互通（见 [互通矩阵](../security/interop-matrix.md)）。

## 4. 包职责

```
算法原语（封装 gmsm）
  sm2        SM2 签名 / 加密 / 密钥交换
  sm3        SM3 哈希 / HMAC / KDF / HKDF
  sm4        SM4 分组密码（GCM/CBC/CTR/CFB）+ GCM 高级封装（SealRandomNonce + 密钥清零）
  sm9        SM9 基于身份加密
  zuc        ZUC 序列密码

证书
  smx509     SM2 感知 X.509 解析 / CSR / 验证（底层 helper）
  cert       面向调用方的统一证书门面

协议（标准 TLS/QUIC）
  tls        仅国密/TLS 套件 ID 与名称注册表
  tls13      标准 TLS 1.3 配置 builder
  quic       标准 QUIC（基于 quic-go）
  http       TLS / TLCP / TLS1.3 HTTP 辅助（保守默认值）

协议（国密 RFC 8998 栈）
  tls13gm    RFC 8998 TLS 1.3 GM 握手引擎 + 密码原语
  quicgm     RFC 9001 §5 QUIC packet protection + Listen/Dial/DialEarly 连接层
  quic-go/   vendored fork：注入 GMCryptoSetup，让 quic-go 状态机跑 RFC 8998 握手

协议（待审计）
  tlcp       TLCP 1.1（GB/T 38636-2020，基于 gotlcp 封装）

基础设施
  gmstd                GM/T 标准辅助函数
  internal/memsecure   密钥材料安全清零（防编译器优化）
  internal/panicsafe   panic 安全辅助
```

## 5. 关键设计约束

1. **QUIC 用标准 TLS 1.3，不复用 TLCP**——TLCP 与 TLS 1.3 不兼容，QUIC 强制 TLS 1.3。
2. **`tls` 包 registry-only**——只登记套件 ID/名称，不实现握手，常量不进 `crypto/tls.Config`。
3. **默认配置安全收敛**——HTTP/cert/TLCP 默认 GCM-only，CBC 标记 legacy 须显式启用；默认不启用 `InsecureSkipVerify`、hybrid listener、CBC。
4. **TLCP 在独立审计前保持 EXPERIMENTAL**——底层 gotlcp 未审计，不应暴露于不可信网络。
5. **不误导**——README 与 package doc 不宣称 crypto/tls 不具备的能力，experimental 能力明确标记。
6. **smx509 验证不做 leaf-as-root fallback**——CertPool 保留 raw DER，不从 `Subjects()` 反推证书。

## 6. 标准依据

### 国际标准（IETF）

| 标准 | 标题 | 用于 |
|------|------|------|
| RFC 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport (2021-05) | QUIC 传输层 |
| RFC 9001 | Using TLS to Secure QUIC (2021-05) | QUIC packet protection / 握手集成 |
| RFC 8446 | The Transport Layer Security Protocol Version 1.3 (2018-08) | TLS 1.3 框架 |
| RFC 8998 | ShangMi (SM) Cipher Suites for TLS 1.3 (2021-03) | 中国 IETF 国密标准，路线 C 依据 |

### 国内标准

| 标准 | 标题 | 用于 |
|------|------|------|
| GB/T 38636-2020 | 信息安全技术 传输层密码协议（TLCP），前身 GM/T 0024-2014 | `tlcp` 包 |
| GB/T 32918-2016 | SM2 椭圆曲线公钥密码（ISO/IEC 14888-3:2018） | `sm2` |
| GB/T 32905-2016 | SM3 密码哈希（ISO/IEC 10118-3:2018） | `sm3` |
| GB/T 32907-2016 | SM4 分组密码（ISO/IEC 18033-3:2010/AMD1:2021） | `sm4` |

### QUIC + 国密的标准化现状

- 没有独立的「QUIC 国密」IETF 标准。QUIC + 国密通过标准链间接实现：RFC 8998 → RFC 8446 → RFC 9001 → RFC 9000。TLS 实现支持 RFC 8998 套件，QUIC 即可用国密做传输层加密。
- TLCP 暂无 QUIC 版本（GB/T 38636-2020 为现行有效版）。
- 相关实现：NJet（HTTP/3 国密）、BabaSSL/Tongsuo（OpenSSL 分支，RFC 8998 TLS 1.3 套件）。

标准链接见各 RFC 的 datatracker 页；GB/T 38636-2020 见 std.samr.gov.cn。

## 7. 后续工作（非阻塞）

- 第三方安全审计、性能优化。
