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
| **路线 C** — RFC 8998 TLS 1.3 GM | `tls13gm` | 🔬 实验 | 完整握手引擎，需独立互通验证 |
| **路线 C** — RFC 9001 QUIC GM | `quicgm` | 🔬 实验 | transport-level packet protection |
| TLCP 1.1（GB/T 38636-2020） | `tlcp` | ⚠️ 实验 | 基于 `gotlcp`，待第三方安全审计 |
| 国密套件注册 | `tls` | ✅ | 仅套件 ID/名称注册，非完整 TLS |

## 包结构

```
sm2 sm3 sm4 sm4gcm sm9 zuc   # 国密算法封装
smx509 cert                   # SM2 感知 X.509
gmstd                         # GM/T 标准辅助函数
tlcp                          # TLCP 1.1（GB/T 38636-2020）
tls13gm quicgm                # RFC 8998 / RFC 9001 GM 栈（Route C，实验）
tls tls13 quic                # 标准 TLS/QUIC（Route A）
http                          # TLS / TLCP / TLS1.3 HTTP 辅助
internal/memsecure            # 密钥材料安全清零
internal/panicsafe            # panic 安全辅助
```

## 快速上手

```bash
go get github.com/iuboy/pollux-go@latest
```

SM4-GCM 加解密：

```go
import "github.com/iuboy/pollux-go/sm4gcm"

key := make([]byte, 16)   // 实际使用 crypto/rand 生成
nonce := make([]byte, 12)
cipher, _ := sm4gcm.NewCipher(key)
ct := cipher.Seal(nil, nonce, plaintext, additionalData)
pt, _ := cipher.Open(nil, nonce, ct, additionalData)
```

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
  protection，但 Go / quic-go 上游尚不原生支持 RFC 8998，生产部署前需独立的互通验证。
- 安全审计的完整记录见 [`docs/security/audit.md`](docs/security/audit.md)。

## 文档

- [架构与设计](docs/design/architecture.md) — 项目定位、概念边界、路线 A/B/C、包职责、标准依据
- [Route C 设计（RFC 8998 QUIC Packet Protection）](docs/design/route-c-quic-gm.md)
- [安全审计报告](docs/security/audit.md) — 问题清单、修复状态、回归测试映射
- [内存与密钥管理](docs/security/memory-management.md)
- [gosec 配置](docs/security/gosec-configuration.md)

## License

见仓库 LICENSE（如有）。
