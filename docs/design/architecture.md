# pollux-go 架构与设计

本文是 pollux-go 的架构参考：项目定位、概念边界、传输/安全路线、包职责、
标准依据、以及关键设计约束。

## 1. 项目定位

pollux-go 是 **Go 语言国密（GM）算法与协议的集成工具包，不是密码学实现**。

- 核心算法（SM2/SM3/SM4/SM9/ZUC）全部委托给 [`emmansun/gmsm`](https://github.com/emmansun/gmsm)，
  pollux-go 继承其审计状态与实现质量（常量时间操作、拒绝采样、标准测试向量）。
- pollux-go 在原语之上补充：协议集成（TLCP 1.1、RFC 8998 栈、QUIC）、SM2 感知
  的 X.509 处理、符合 Go 习惯的封装 API、以及密钥材料安全清零机制。

封装层本身的安全职责集中在两点：**输入验证**与**密钥内存管理**。

## 2. 概念边界

这是 pollux-go 设计中最易混淆的三组概念，必须严格区分：

| 概念 | 定义 | pollux-go 包 |
|------|------|--------------|
| **TLCP** | GB/T 38636-2020，中国国标传输层密码协议，基于 TLS 1.2 框架，采用**双证书**（签名 + 加密）体系 | `tlcp`（基于 gotlcp） |
| **RFC 8998** | IETF 标准 *ShangMi Cipher Suites for TLS 1.3*，在 TLS 1.3 框架内注册国密套件，不改握手流程 | `tls13gm` + `quicgm` |
| **标准 TLS 1.3 / QUIC** | RFC 8446 / RFC 9000-9001，非国密 | `tls13` / `quic` / `tls` |

关键事实：

- **TLCP 与 RFC 8998 不兼容、不可互换**——TLCP 是基于 TLS 1.2 的独立协议，RFC 8998
  寄生于 TLS 1.3。两者密码套件 ID、握手流程均不同。
- **`tls` 包只是套件 ID/名称注册表**，不实现任何 TLS 握手，其常量**不能**直接传给
  `crypto/tls.Config.CipherSuites`——Go 标准库不认识国密套件。
- **QUIC 强制要求 TLS 1.3 握手**（RFC 9001），因此 TLCP **不能**直接用于 QUIC。

## 3. 传输与安全路线

pollux-go 的传输栈均已生产/互通可用：

### 标准 TLS 1.3 / QUIC（生产）

```
quic-go → crypto/tls TLS 1.3 → ALPN → RSA/ECDSA/Ed25519 证书
```

- 包：`quic`、`tls13`、`http`（TLS13 profile）
- 状态：✅ 生产可用。标准完备，Go 生态（`crypto/tls` + `quic-go`）完全支持。

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

这些约束是 pollux-go 在审计与重构中确立的不可违反的边界：

1. **QUIC 使用标准 TLS 1.3，不复用 TLCP**——TLCP 与 TLS 1.3 不兼容，QUIC 强制要求 TLS 1.3。
2. **`tls` 包是 registry-only**——只登记套件 ID/名称，不实现握手，其常量不进 `crypto/tls.Config`。
3. **默认配置安全收敛**——HTTP/cert/TLCP 默认 GCM-only，CBC 标记 legacy 须显式启用；
  默认不启用 `InsecureSkipVerify`、不启用 hybrid listener、不启用 CBC。
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
| RFC 8998 | ShangMi (SM) Cipher Suites for TLS 1.3 (2021-03) | 🇨🇳 中国首个 IETF 国密标准，路线 C 依据 |

### 国内标准

| 标准 | 标题 | 用于 |
|------|------|------|
| GB/T 38636-2020 | 信息安全技术 传输层密码协议（TLCP），前身 GM/T 0024-2014 | `tlcp` 包 |
| GB/T 32918-2016 | SM2 椭圆曲线公钥密码（ISO/IEC 14888-3:2018） | `sm2` |
| GB/T 32905-2016 | SM3 密码哈希（ISO/IEC 10118-3:2018） | `sm3` |
| GB/T 32907-2016 | SM4 分组密码（ISO/IEC 18033-3:2010/AMD1:2021） | `sm4` |

### QUIC + 国密的标准化现状

- **不存在独立的「QUIC 国密」IETF 标准**。QUIC + 国密通过标准链间接实现：
  RFC 8998 →（注册到）RFC 8446 →（被）RFC 9001 →（用于保护）RFC 9000。只要
  TLS 实现支持 RFC 8998 套件，QUIC 即可用国密做传输层加密，无需新 QUIC 扩展。
- **TLCP 暂无 QUIC 版本**——GB/T 38636-2020 为现行有效版，TC260 公开渠道无 QUIC 立项信息。
- **业界实践**：NJet（HTTP/3 国密）、BabaSSL/Tongsuo（OpenSSL 分支，RFC 8998 TLS 1.3 套件）。

标准链接见各 RFC 的 datatracker 页；GB/T 38636-2020 见 std.samr.gov.cn。

## 7. 后续工作（非阻塞）

- 第三方安全审计、性能优化。
