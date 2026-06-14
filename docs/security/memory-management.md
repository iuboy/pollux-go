# pollux-go 内存管理与密钥生命周期安全指南

## 1. 概述

pollux-go 是一个国密算法库，处理大量敏感密钥材料。本文档说明密钥生命周期管理和内存安全机制。

## 2. 密钥生命周期

### 2.1 密钥生成

密钥生成使用 `crypto/rand` 作为随机源，确保密码学安全：

```go
import (
    "crypto/rand"
    "github.com/ycq/pollux/sm4"
    "github.com/ycq/pollux/quicgm"
)

// SM4 密钥生成
key, err := sm4gcm.GenerateKey(rand.Reader)

// QUICGM 会话密钥生成
keys, err := quicgm.GenerateSessionKeys(rand.Reader)
```

### 2.2 密钥使用

密钥在使用过程中保持内存中的明文形式。重要原则：

1. **最小化密钥暴露范围**：密钥只在必要的函数中可见
2. **限制密钥生命周期**：密钥在使用完毕后应立即清零
3. **避免密钥复制**：优先使用引用而非复制密钥字节

### 2.3 密钥清零

pollux-go 提供了 `internal/memsecure` 包用于安全内存操作：

```go
import "github.com/ycq/pollux/internal/memsecure"

// 清零字节切片
memsecure.ZeroBytes(key)

// 清零会话密钥
quicgm.ZeroKeys(&keys)

// 清零 SM4 密钥和 nonce
sm4gcm.ZeroKey(key)
sm4gcm.ZeroNonce(nonce)
```

**重要**：`ZeroBytes` 使用了防止编译器优化的技术，确保清零操作不会被优化掉。

## 3. 自动清零位置

以下位置已实现自动密钥清零：

### 3.1 TLCP 握手

- **preMasterSecret**：在派生 masterSecret 后立即清零（`handshake.go:211, 434`）
- **keyMaterial**：在创建 cipher 后立即清零（`handshake.go:665-669`）

```go
// 派生主密钥
hs.masterSecret = masterSecret(preMasterSecret, hs.clientRandom[:], hs.serverRandom[:])

// 清零 preMasterSecret（敏感密钥材料）
memsecure.ZeroBytes(preMasterSecret)
```

### 3.2 QUICGM 加密

- **SessionKeys**：提供 `ZeroKeys` 函数用于显式清零
- **Envelope**：密文密钥材料在验证失败时不会被解密

### 3.3 SM4-GCM

- **密钥和 Nonce**：提供 `ZeroKey` 和 `ZeroNonce` 函数

## 4. 开发者指南

### 4.1 密钥管理最佳实践

#### ✅ 推荐

```go
// 使用 defer 确保密钥清零
func processKey() {
    key, _ := sm4gcm.GenerateKey(rand.Reader)
    defer sm4gcm.ZeroKey(key)

    // 使用密钥...
    plaintext, _ := sm4gcm.Open(key, nonce, ciphertext, aad)
    _ = plaintext
}
```

#### ❌ 避免

```go
// 密钥在函数返回后仍然存在于内存中
func processKey() {
    key, _ := sm4gcm.GenerateKey(rand.Reader)
    // 使用密钥...
    // 忘记清零！
}
```

### 4.2 会话密钥管理

对于长期运行的会话（如 QUIC 连接），应考虑：

1. **定期轮换**：定期生成新的会话密钥
2. **安全存储**：使用时才解密，使用后立即清零
3. **错误处理**：发生错误时确保密钥被清零

```go
func handleSession() error {
    keys, err := quicgm.GenerateSessionKeys(rand.Reader)
    if err != nil {
        return err
    }
    defer quicgm.ZeroKeys(&keys)

    // 使用会话密钥...
    return nil
}
```

### 4.3 临时密钥材料

对于临时密钥材料（如 nonce、IV）：

```go
// nonce 应在加密/解密完成后清零
nonce, _ := sm4gcm.GenerateNonce(rand.Reader)
defer sm4gcm.ZeroNonce(nonce)

ciphertext, _ := sm4gcm.Seal(key, nonce, plaintext, aad)
```

### 4.4 日志和调试

**切勿在日志中输出敏感密钥材料**：

```go
// ❌ 错误
log.Printf("Key: %x", key)

// ✅ 正确
log.Printf("Key length: %d bytes", len(key))
```

## 5. 内存安全机制

### 5.1 防止编译器优化

`memsecure.ZeroBytes` 使用以下技术防止编译器优化：

```go
for i := range data {
    *(*byte)(unsafe.Pointer(&data[i])) = 0
}
runtime.KeepAlive(data)
```

- **unsafe 指针写入**：防止编译器优化掉写入操作
- **runtime.KeepAlive**：确保数据在清零后仍被视为存活

### 5.2 常量时间比较

密钥比较使用常量时间算法，防止时序攻击：

```go
import "crypto/subtle"

// MAC 验证使用常量时间比较
func VerifyMACSM3(key, data, mac []byte) bool {
    expected := MACSM3(key, data)
    return subtle.ConstantTimeCompare(expected, mac) == 1
}
```

## 6. 已知限制

### 6.1 Go 垃圾回收

Go 的垃圾回收器可能会移动对象，但不会修改对象内容。密钥清零后，即使对象被移动，清零的内容仍保持为零。

### 6.2 堆转储

进程崩溃时，堆转储可能包含敏感密钥材料。建议在生产环境中：

1. 禁用核心转储：`ulimit -c 0`
2. 使用安全的内存锁（mlock）机制（需平台特定实现）
3. 定期轮换密钥

### 6.3 交换文件

操作系统可能将内存页交换到磁盘。建议：

1. 使用 `mlock` 系统调用锁定敏感内存（需平台特定实现）
2. 配置操作系统禁用交换或使用加密交换

## 7. 安全检查清单

在处理密钥时，请检查：

- [ ] 密钥是否使用 `crypto/rand` 生成？
- [ ] 密钥是否在使用完毕后立即清零？
- [ ] 是否使用了 `defer` 确保密钥清零？
- [ ] 日志中是否包含敏感密钥材料？
- [ ] 错误处理路径是否正确清零密钥？
- [ ] 是否避免了不必要的密钥复制？
- [ ] 长期运行的会话是否定期轮换密钥？

## 8. 相关文档

- [安全审计报告](./audit.md)
- [gosec 配置](./gosec-configuration.md)
- [架构与设计](../design/architecture.md)

## 9. 联系方式

如发现内存安全问题，请通过 GitHub Issues 报告。
