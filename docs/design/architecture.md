# pollux-go 架构与设计

本文是 pollux-go 的架构参考：项目定位、概念边界、传输/安全路线、包职责、
标准依据、以及关键设计约束。它整合了历史路线图与实施总计划中仍有长期价值的
部分；已完成的里程碑执行记录见文末「里程碑摘要」，详细安全审计见
[`../security/audit.md`](../security/audit.md)。

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

pollux-go 围绕三条路线组织，成熟度递进：

### 路线 A — 标准 TLS 1.3 / QUIC（生产）

```
quic-go → crypto/tls TLS 1.3 → ALPN → RSA/ECDSA/Ed25519 证书
```

- 包：`quic`、`tls13`、`http`（TLS13 profile）
- 状态：✅ 生产可用。标准完备，Go 生态（`crypto/tls` + `quic-go`）完全支持。

### 路线 B — QUIC + 标准 TLS 1.3 + 应用层国密（生产）

```
QUIC TLS 1.3 传输安全
+ 应用层 profile：SM2 证书认证、HMAC-SM3、SM4-GCM 负载加密、SM3-HKDF
```

- 适合上层协议（如 MBTA）在不依赖传输层国密标准的前提下使用国密算法。
- 状态：✅ 生产可用。SM2/SM3/SM4 已标准化（ISO + GB/T），应用层 envelope 不依赖传输层标准。

### 路线 C — RFC 8998 TLS 1.3 国密（实验）

```
TLS_SM4_GCM_SM3 + SM3 transcript + HKDF-SM3 + SM2-SM3 签名 + curveSM2 + SM4-GCM QUIC 包保护
```

- 包：`tls13gm`（握手引擎 + 密码原语）、`quicgm`（RFC 9001 §5 packet protection）
- 状态：🔬 **实验**。原语与握手引擎、QUIC packet protection 已完整实现（见
  [`route-c-quic-gm.md`](route-c-quic-gm.md)），但 Go `crypto/tls` 与 `quic-go`
  上游尚不原生支持 RFC 8998，生产部署前需独立的互通验证。

> **演进说明**：路线 C 最初定位为「experimental 模型包，不提供完整 handshake」。
> 实际实现已超越该定位——`tls13gm` 提供完整 TLS 1.3 GM 握手引擎
> （`ClientHandshaker`/`ServerHandshaker`），`quicgm` 提供 transport-level
> packet protection。两者构成完整的 RFC 8998 GM 栈，但仍保留 experimental 标签
> 待互通验证与独立审计。

## 4. 包职责

```
算法原语（封装 gmsm）
  sm2        SM2 签名 / 加密 / 密钥交换
  sm3        SM3 哈希 / HMAC / KDF / HKDF
  sm4        SM4 分组密码（GCM/CBC/CTR/CFB）
  sm4gcm     安全的 SM4-GCM AEAD 辅助（推荐 API）
  sm9        SM9 基于身份加密
  zuc        ZUC 序列密码

证书
  smx509     SM2 感知 X.509 解析 / CSR / 验证（底层 helper）
  cert       面向调用方的统一证书门面

协议（路线 A — 生产）
  tls        仅国密/TLS 套件 ID 与名称注册表
  tls13      标准 TLS 1.3 配置 builder
  quic       标准 QUIC（基于 quic-go）
  http       TLS / TLCP / TLS1.3 HTTP 辅助（保守默认值）

协议（路线 C — 实验）
  tls13gm    RFC 8998 TLS 1.3 GM 握手引擎 + 密码原语
  quicgm     RFC 9001 §5 QUIC packet protection

协议（待审计）
  tlcp       TLCP 1.1（GB/T 38636-2020，基于 gotlcp 封装）

基础设施
  gmstd                GM/T 标准辅助函数
  internal/memsecure   密钥材料安全清零（防编译器优化）
  internal/panicsafe   panic 安全辅助
```

## 5. RFC 8998 组成

完整支持 RFC 8998 需要把标准 TLS 1.3 的每个组件替换为国密等价物：

| 组件 | 标准 TLS 1.3 | RFC 8998 国密 |
|------|-------------|---------------|
| CipherSuite | `TLS_AES_128_GCM_SHA256` | `TLS_SM4_GCM_SM3`（0x00C6）/ `TLS_SM4_CCM_SM3`（0x00C7） |
| Transcript Hash | SHA-256/SHA-384 | SM3 |
| HKDF | HKDF-SHA256/SHA384 | HKDF-SM3 |
| Signature | ECDSA/RSA-PSS/Ed25519 | SM2-SM3（方案 ID 0x0708，identifier `TLSv1.3+GM+Cipher+Suite`） |
| Key Exchange | X25519/P-256 | curveSM2（0x0029） |
| AEAD | AES-GCM/ChaCha20-Poly1305 | SM4-GCM / SM4-CCM |

## 6. 关键设计约束

这些约束是 pollux-go 在审计与重构中确立的不可违反的边界：

1. **QUIC 使用标准 TLS 1.3，不复用 TLCP**——TLCP 与 TLS 1.3 不兼容，QUIC 强制要求 TLS 1.3。
2. **`tls` 包是 registry-only**——只登记套件 ID/名称，不实现握手，其常量不进 `crypto/tls.Config`。
3. **默认配置安全收敛**——HTTP/cert/TLCP 默认 GCM-only，CBC 标记 legacy 须显式启用；
  默认不启用 `InsecureSkipVerify`、不启用 hybrid listener、不启用 CBC。
4. **TLCP 在独立审计前保持 EXPERIMENTAL**——底层 gotlcp 未审计，不应暴露于不可信网络。
5. **Route C 生产前需独立互通验证**——Go/quic-go 上游不支持 RFC 8998，需自行验证互通性。
6. **不误导**——README 与 package doc 不宣称 crypto/tls 不具备的能力，experimental 能力明确标记。
7. **smx509 验证不做 leaf-as-root fallback**——CertPool 保留 raw DER，不从 `Subjects()` 反推证书。

## 7. 标准依据

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

## 8. 里程碑摘要

完整里程碑执行记录已完成，这里仅保留对理解架构演进有用的摘要：

| 里程碑 | 内容 | 关键产出 |
|--------|------|----------|
| M0–M1 | 基线恢复 + 安全回归 | SM9 语义修复；TLCP/SMX509/SM4 全部 CRITICAL 修复 |
| M2–M3 | 标准 TLS 1.3 / QUIC（路线 A） | `tls13`、`cert` 门面、`quic` 包 + 黑盒测试 |
| M4 | 应用层国密（路线 B 基础） | `sm4gcm`、`quicgm` 包 |
| M5–M7 | 证书/TLCP 收敛 + 审计收尾 | smx509 CertPool raw DER、GCM-only 默认、fuzz、内存清零 |
| M8–M9 | 黑盒测试补全 + 文档收尾 | 279 黑盒测试、quicgm nonce registry |
| M6 → M10 | RFC 8998 从模型包演进到完整握手引擎 | `tls13gm` ClientHandshaker/ServerHandshaker、fail-closed PKI |
| M11 | Route C QUIC packet protection | `quicgm` RFC 9001 §5 Initial/Handshake/1-RTT + CRYPTO frame |

详见 [`../security/audit.md`](../security/audit.md) 的修复记录与回归测试映射。

## 9. 后续工作（非阻塞）

- Route C 留待后续迭代：QUIC 连接状态机（ACK/重传/流复用/拥塞，归 quic-go）、
  TCP record layer/Dial/Listen（独立传输层）。
- 第三方安全审计、RFC 8998 互通测试、性能优化。
