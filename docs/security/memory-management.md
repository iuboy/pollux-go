# pollux-go 内存管理与密钥生命周期安全指南

## 1. 概述

pollux-go 处理大量敏感密钥材料（SM2/SM4 会话密钥、握手预主密钥、QUIC 包保护密钥）。
本文档说明密钥生命周期管理、`internal/memsecure` 安全清零机制，以及各模块的自动清零位置。

封装层的密码运算委托 `emmansun/gmsm`；pollux-go 自身在内存安全上的职责集中在两点：
**密钥使用后及时清零**与**避免不必要的密钥复制**。

> 模块路径统一为 `github.com/iuboy/pollux-go/...`（见仓库 `go.mod`）。

## 2. 密钥生命周期

### 2.1 密钥生成

密钥生成使用 `crypto/rand` 作为随机源：

```go
import "github.com/iuboy/pollux-go/sm4"

// SM4 密钥（16 字节）
key, err := sm4.GenerateKey()

// SM4-GCM 随机 nonce（12 字节）
nonce, err := sm4.GenerateNonce()
```

> Route C 的 QUIC 包保护密钥不由调用方直接生成——它们由 `tls13gm` 握手引擎从
> traffic secret 派生（`tls13gm.DeriveQUICPacketKeys`），调用方拿到的是
> `*tls13gm.QUICPacketKeys`，用完应调用其 `Zero()`。

### 2.2 密钥使用

密钥在使用期间以明文驻留内存。三条原则：

1. **最小化暴露范围**：密钥只在必要函数内可见，不向日志/错误信息泄露。
2. **限制生命周期**：使用完毕立即清零，优先用 `defer`。
3. **避免复制**：传切片引用，不要 `append`/`copy` 出副本。

### 2.3 密钥清零

`internal/memsecure` 提供防编译器优化的安全清零：

```go
import "github.com/iuboy/pollux-go/internal/memsecure"

memsecure.ZeroBytes(key)        // 清零字节切片
memsecure.ZeroUint32(words)     // 清零 []uint32
memsecure.ZeroUint64(words)     // 清零 []uint64
```

`ZeroBytes` 通过 `unsafe` 指针写入 + `runtime.KeepAlive` 确保清零不被编译器优化删除
（见 §5.1）。模块导出的便捷封装：`sm4.ZeroKey`、`sm4.ZeroNonce` 内部即调用
`memsecure.ZeroBytes`。

## 3. 自动清零位置

以下位置已在库内实现自动清零，调用方无需额外处理：

### 3.1 SM4-GCM 辅助（`sm4`）

- **密钥 / Nonce**：`sm4.ZeroKey(key)`、`sm4.ZeroNonce(nonce)` —— 内部 `memsecure.ZeroBytes`。
- `SealRandomNonce` 生成的密文结构在使用后应连同密钥一并清零。

```go
key, _ := sm4.GenerateKey()
defer sm4.ZeroKey(key)
nonce, _ := sm4.GenerateNonce()
defer sm4.ZeroNonce(nonce)

sealed, _ := sm4.SealRandomNonce(key, plaintext, aad)
defer sm4.ZeroKey(key) // 密文用完后清零密钥
```

### 3.2 SM2 信封与压缩（`sm2`）

- **`sm2/envelope.go`**：SM4 内容加密密钥（`sm4Key`）在加解密结束后 `defer memsecure.ZeroBytes(sm4Key)`。
- **`sm2/compress.go`**：压缩中间态字节 `s.bytes` 在归还池前 `memsecure.ZeroBytes`。
- **`sm2/key_exchange.go`**：密钥交换返回的共享密钥切片由调用方负责清零（函数文档已标注）。

### 3.3 SM2 感知 X.509（`smx509`）

- **`smx509/cert.go`**：PKCS#8 / 证书密钥派生出的 `derivedKey` 用完即 `defer memsecure.ZeroBytes(derivedKey)`。

### 3.4 Route C 握手与 QUIC 包保护（`tls13gm` / `quicgm`）

- **`tls13gm.QUICPacketKeys.Zero()`**：清零 `AEADKey` / `AEADIV` / `HeaderKey` 三项。
- **`tls13gm.HandshakeSecrets.Zero()`**：清零三级（Initial / Handshake / Application）全部 QUIC 密钥。
- **`quicgm.QUICPacketProtector.Zero()`**：清零其持有的 `QUICPacketKeys`。

```go
keys, err := tls13gm.DeriveQUICPacketKeys(trafficSecret)
if err != nil { return err }
defer keys.Zero()
```

> 注意：`quicgm` 已从早期的 Route B「应用层 envelope」重构为 Route C transport-level
> RFC 8998 包保护。Route B 的 `Envelope`/`GenerateSessionKeys`/`ZeroKeys` API 已不存在；
> 当前密钥来自 `tls13gm.DeriveQUICPacketKeys`，清零通过 `QUICPacketKeys.Zero()` /
> `HandshakeSecrets.Zero()` / `QUICPacketProtector.Zero()`。

## 4. 开发者指南

### 4.1 临时密钥材料的 defer 清零

```go
func processKey() error {
    key, err := sm4.GenerateKey()
    if err != nil { return err }
    defer sm4.ZeroKey(key)

    aead, err := sm4.NewGCM(key)
    if err != nil { return err }
    pt, err := aead.Open(nil, nonce, ct, aad)
    _ = pt
    return nil
}
```

### 4.2 长期会话密钥

对长期运行的会话（如 QUIC 连接），应：

1. **定期轮换**：长连接依赖 QUIC key update（`tls13gm.QUICKeyUpdate`）规避 nonce 复用。
2. **错误路径清零**：握手失败时确保 `HandshakeSecrets.Zero()` 被调用（fail-closed）。
3. **连接关闭清零**：`QUICPacketProtector.Zero()` 在连接 Close 时执行。

### 4.3 日志与调试

切勿输出敏感密钥材料：

```go
// ❌ 错误
log.Printf("key=%x", key)

// ✅ 正确
log.Printf("key length=%d bytes", len(key))
```

## 5. 内存安全机制

### 5.1 防止编译器优化

`memsecure.ZeroBytes` 通过 `unsafe` 指针写入 + `runtime.KeepAlive` 确保清零不被优化掉：

```go
for i := range data {
    *(*byte)(unsafe.Pointer(&data[i])) = 0
}
runtime.KeepAlive(data)
```

- **unsafe 指针写入**：绕过「赋值后不再读取即死存储」的优化判定。
- **runtime.KeepAlive**：保证清零后数据仍被视为存活，避免提前回收绕过写入。

### 5.2 常量时间比较

MAC / Finished 校验使用常量时间比较（`crypto/subtle.ConstantTimeCompare` 或等价实现），
防止时序侧信道。tls13gm 的 Finished 验证、sm4 CBC 的 MAC 比较均走此路径。

## 6. 已知限制

### 6.1 Go 垃圾回收

Go GC 可能移动对象，但不修改对象内容——清零后的内容保持为零。

### 6.2 堆转储 / 核心转储

进程崩溃的 core dump 可能包含密钥。生产建议：

1. 禁用 core dump：`ulimit -c 0`。
2. 内存锁定（`mlock`）需平台特定实现，pollux-go 未提供跨平台封装。
3. 定期轮换密钥。

### 6.3 交换文件

操作系统可能将内存页换出到磁盘。建议禁用 swap 或使用加密 swap；`mlock` 锁定同样需平台特定实现。

## 7. 安全检查清单

处理密钥时核对：

- [ ] 密钥是否用 `crypto/rand` 生成？
- [ ] 密钥使用后是否立即清零（优先 `defer`）？
- [ ] 错误路径是否也清零（fail-closed）？
- [ ] 日志是否泄露密钥字节？
- [ ] 是否避免了不必要的密钥复制？
- [ ] 长连接是否启用 key update 规避 nonce 复用？

## 8. 相关文档

- [安全审计报告](./audit.md)
- [gosec 配置](./gosec-configuration.md)
- [架构与设计](../design/architecture.md)
- [Route C 设计（RFC 8998 QUIC Packet Protection）](../design/route-c-quic-gm.md)
