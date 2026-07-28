# pollux-go 内存管理与密钥生命周期

pollux-go 处理大量敏感密钥材料（SM2/SM4 会话密钥、握手预主密钥、QUIC 包保护密钥）。封装层的密码运算委托 gmsm；pollux-go 自身负责密钥使用后清零，并避免不必要的密钥复制。

## 1. 密钥生命周期

**生成**：用 `crypto/rand`。

```go
key, err := sm4.GenerateKey()       // SM4 密钥（16 字节）
nonce, err := sm4.GenerateNonce()   // SM4-GCM nonce（12 字节）
```

> Route C 的 QUIC 包保护密钥不由调用方生成——由 `tls13gm` 握手引擎从 traffic secret 派生（`tls13gm.DeriveQUICPacketKeys`），调用方拿到 `*tls13gm.QUICPacketKeys`，用完应调 `Zero()`。

**使用**：密钥使用期间以明文驻留内存。三条原则——最小化暴露范围（不进日志/错误信息）、限制生命周期（用完立即清零，优先 `defer`）、避免复制（传切片引用，不 `append`/`copy`）。

**清零**：`internal/memsecure` 提供防编译器优化的安全清零。

```go
memsecure.ZeroBytes(key)       // 字节切片
memsecure.ZeroUint32(words)   // []uint32
memsecure.ZeroUint64(words)   // []uint64
```

`ZeroBytes` 通过 `unsafe` 指针写入 + `runtime.KeepAlive` 确保清零不被编译器优化删除（绕过「赋值后不再读取即死存储」判定）。`sm4.ZeroKey` / `sm4.ZeroNonce` 内部即调用 `memsecure.ZeroBytes`。

```go
key, _ := sm4.GenerateKey()
defer sm4.ZeroKey(key)
nonce, _ := sm4.GenerateNonce()
defer sm4.ZeroNonce(nonce)
sealed, _ := sm4.SealRandomNonce(key, plaintext, aad)
```

## 2. 自动清零位置

库内已自动清零的位置，调用方无需额外处理：

| 模块                  | 位置                  | 清零对象                                         |
| --------------------- | --------------------- | ------------------------------------------------ |
| `sm4`                 | GCM 高级封装          | 密钥 / nonce（`sm4.ZeroKey` / `sm4.ZeroNonce`）  |
| `sm2/envelope.go`     | SM2 信封              | SM4 内容加密密钥 `sm4Key`                        |
| `sm2/compress.go`     | 公钥压缩              | 压缩中间态 `s.bytes`（归还池前）                 |
| `smx509/cert.go`      | PKCS#8 / 证书密钥派生 | `derivedKey`                                     |

Route C 握手与 QUIC 包保护：

- `tls13gm.QUICPacketKeys.Zero()` — 清零 `AEADKey` / `AEADIV` / `HeaderKey`
- `tls13gm.HandshakeSecrets.Zero()` — 清零三级（Initial / Handshake / Application）全部 QUIC 密钥
- `quicgm.QUICPacketProtector.Zero()` — 清零其持有的 `QUICPacketKeys`

```go
keys, err := tls13gm.DeriveQUICPacketKeys(trafficSecret)
if err != nil { return err }
defer keys.Zero()
```

## 3. 长期会话密钥

对长期运行的会话（如 QUIC 连接）：

1. **定期轮换**：长连接用 QUIC key update（`tls13gm.QUICKeyUpdate`）规避 nonce 复用。
2. **错误路径清零**：握手失败时确保 `HandshakeSecrets.Zero()` 被调用（fail-closed）。
3. **连接关闭清零**：`QUICPacketProtector.Zero()` 在连接 Close 时执行。

切勿输出密钥字节：`log.Printf("key length=%d bytes", len(key))` ✅，而非 `log.Printf("key=%x", key)` ❌。

## 4. 内存安全机制

- **防编译器优化**：`unsafe` 指针写入绕过死存储判定，`runtime.KeepAlive` 保证清零后数据仍被视为存活。
- **常量时间比较**：MAC / Finished 校验用 `crypto/subtle.ConstantTimeCompare` 或等价实现，防时序侧信道。tls13gm Finished 验证、sm4 CBC MAC 比较均走此路径。

## 5. 已知限制

- **Go GC**：可能移动对象但不修改内容，清零后保持为零。
- **core dump**：进程崩溃的 core dump 可能含密钥。生产建议 `ulimit -c 0` 禁用；`mlock` 内存锁定需平台特定实现，pollux-go 未提供跨平台封装。
- **swap**：OS 可能换出内存页。建议禁用 swap 或用加密 swap。

## 6. 相关文档

- [gosec 配置](./gosec-configuration.md)
- [架构与设计](../design/architecture.md)
