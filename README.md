# pollux-go

> Go 语言国密（GM）算法与协议集成工具包。所有核心算法由
> [`github.com/emmansun/gmsm`](https://github.com/emmansun/gmsm) 提供，pollux-go
> 在其之上补充协议集成、SM2 感知的 X.509 处理、以及符合 Go 习惯的封装 API。

pollux-go 是**集成工具包，不是密码学实现**。它把 gmsm 的原语封装成协议层能力，
并对外暴露一致、Go 风格的 API。

## 能力矩阵

| 能力 | 包 | 状态 | 说明 |
|------|----|------|------|
| SM2 签名 / 加密 / 密钥交换 | `sm2` | ✅ | 封装 gmsm/sm2 |
| SM3 哈希 / HMAC / KDF / HKDF | `sm3` | ✅ | 封装 gmsm/sm3 |
| SM4 分组密码（GCM/CBC/CTR/CFB） | `sm4` | ✅ | 封装 gmsm/sm4 |
| SM9 基于身份加密 | `sm9` | ✅ | 封装 gmsm/sm9 |
| ZUC 序列密码 | `zuc` | ✅ | 封装 gmsm/zuc |
| SM2 感知 X.509 | `smx509`、`cert` | ✅ | 证书创建 / 解析 / 验证 |
| **路线 A** — 标准 TLS 1.3 | `tls13`、`http` | ✅ 生产 | 基于 `crypto/tls` |
| **路线 A** — 标准 QUIC | `quic` | ✅ 生产 | 基于 `quic-go` |
| **路线 C** — RFC 8998 TLS 1.3 GM | `tls13gm` | ✅ 互通已验证 | 完整握手引擎，与 Tongsuo/BabaSSL 互通（见 [互通矩阵](docs/security/interop-matrix.md)） |
| **路线 C** — RFC 9001 QUIC GM | `quicgm` | ✅ 互通已验证 | transport-level packet protection，端到端 + 0-RTT 测试 |
| TLCP 1.1（GB/T 38636-2020） | `tlcp` | ⚠️ 实验 | 基于 `gotlcp`，待第三方安全审计 |
| 国密套件注册 | `tls` | ✅ | 仅套件 ID/名称注册，非完整 TLS |

## 包结构

```
sm2 sm3 sm4 sm9 zuc           # 国密算法封装
smx509 cert                   # SM2 感知 X.509
gmstd                         # GM/T 标准辅助函数
tlcp                          # TLCP 1.1（GB/T 38636-2020）
tls13gm quicgm                # RFC 8998 / RFC 9001 GM 栈（Route C，已与 Tongsuo 互通验证）
tls tls13 quic                # 标准 TLS/QUIC（Route A）
http                          # TLS / TLCP / TLS1.3 HTTP 辅助
internal/memsecure            # 密钥材料安全清零
internal/panicsafe            # panic 安全辅助
```

## 快速上手

```bash
go get github.com/iuboy/pollux-go@latest
```

SM4-GCM 加解密（高级便捷封装，含一次性随机 nonce 与密钥清零）：

```go
import "github.com/iuboy/pollux-go/sm4"

key, _ := sm4.GenerateKey()
defer sm4.ZeroKey(key)
// SealRandomNonce 自动生成随机 nonce 并随密文返回
sealed, _ := sm4.SealRandomNonce(key, plaintext, additionalData)
pt, _ := sm4.OpenWithNonce(key, sealed, additionalData)
```

底层等价写法：`sm4.NewCipher(key)` + `cipher.NewGCM(block)`，再配合 `sm4.GenerateNonce()` 逐次生成 nonce。

标准 TLS 1.3 HTTP 服务（路线 A）：

```go
import "github.com/iuboy/pollux-go/http"

srv, err := http.NewTLS13Server(opts)  // MinVersion 强制 TLS 1.3
```

各包更详细的使用与设计见包内 `doc.go` 与 `docs/`。

## 构建与测试

```bash
make test         # 等价于 go test ./...
make vet          # go vet
make gosec        # 安全扫描
make cover-html   # 生成覆盖率报告
```

## 安全状态

- **算法原语**（sm2/sm3/sm4/sm9/zuc）委托 gmsm，继承其审计状态。
- **TLCP**（`tlcp`）尚未通过独立第三方安全审计，标记 EXPERIMENTAL，不建议未经评估用于生产。
- **RFC 8998 栈**（`tls13gm`/`quicgm`，Route C）已实现完整握手引擎与 QUIC packet
  protection，TLS 握手层已与 Tongsuo/BabaSSL 互通验证（见
  [互通矩阵](docs/security/interop-matrix.md)）。Go / quic-go 上游尚不原生支持
  RFC 8998，QUIC 层为 pollux-go 自有实现。
- **密钥更新职责**：pollux 仅提供 key update 原语（`tls13gm.QUICKeyUpdate`），
  **不强制**更新阈值——由传输层（quic-go）或直接集成方负责在阈值临近时发起更新，
  避免长连接 SM4-GCM nonce 复用风险。详见
  [Route C 设计 §8](docs/design/route-c-quic-gm.md#8-安全注意事项)。
- 安全审计的完整记录见 [`docs/security/audit.md`](docs/security/audit.md)。

## 文档

- [架构与设计](docs/design/architecture.md) — 项目定位、概念边界、路线 A/B/C、包职责、标准依据
- [Route C 设计（RFC 8998 QUIC Packet Protection）](docs/design/route-c-quic-gm.md)
- [安全审计报告](docs/security/audit.md) — 问题清单、修复状态、回归测试映射
- [内存与密钥管理](docs/security/memory-management.md)
- [RFC 8998 互通矩阵](docs/security/interop-matrix.md) — pollux-go × Tongsuo/BabaSSL 合规验证
- [gosec 配置](docs/security/gosec-configuration.md)

## License

MIT — 详情见 [LICENSE](LICENSE)。
