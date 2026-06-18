# QUIC SM4-GCM Packet Protection 设计文档

> 状态：**已实施 + 互通已验证**（密码原语层 + transport 组装层 + Initial 包端到端 + packet-number 截断 + 性能基线 + BabaSSL/Tongsuo 互操作 1-RTT/PSK resume/0-RTT） | 路线：Route C (QUIC + RFC 8998) | 优先级：P2
>
> **分层**: QUIC SM4-GCM Packet Protection 按「tls13gm 密码原语层 + quicgm transport 组装层」分层实现，镜像 crypto/tls 与 quic-go 的关系。tls13gm 提供 QUIC 标签、`DeriveQUICPacketKeys`、`QUICKeyUpdate`、`HeaderProtectionMask` 原语；quicgm 消费这些原语组装 `QUICPacketProtector`（payload AEAD + header protection apply/remove）。

## 1. 概述

本文档描述如何在 QUIC 协议中使用 SM4-GCM 进行 Packet Protection（数据包保护），符合以下标准：

- **RFC 9001** §5: "Using TLS Keys to Protect QUIC Packets" — 定义 QUIC AEAD 加密框架
- **RFC 8998**: "ShangMi (SM) Cipher Suites for TLS 1.3" — 定义 TLS_SM4_GCM_SM3 (0x00C6)
- **RFC 8446** §7: TLS 1.3 Key Schedule — 密钥派生流程
- **GM/T 0002-2012**: SM4 分组密码算法
- **GM/T 0009-2012**: SM2 密码算法（用于密钥交换）

## 2. 密码套件参数

| 参数 | 值 | 来源 |
|------|-----|------|
| Cipher Suite ID | 0x00C6 (TLS_SM4_GCM_SM3) | RFC 8998 §3 |
| AEAD Algorithm | SM4-GCM | RFC 8998 §3 |
| Hash Function | SM3 | RFC 8998 §2 |
| Key Exchange | ECDHE with curveSM2 (0x0029) | RFC 8998 §4 |
| Signature | SM2SigSM3 (0x0708) | RFC 8998 §5 |
| AEAD Key Length | 16 bytes (128 bits) | SM4 密钥长度 |
| AEAD IV Length | 12 bytes | TLS 1.3 / RFC 9001 |
| AEAD Tag Length | 16 bytes (128 bits) | GCM tag |
| Hash Output Length | 32 bytes (256 bits) | SM3 输出 |

## 3. Key Schedule 映射

### 3.1 标准映射（替换 SHA-256 → SM3）

TLS 1.3 Key Schedule 中所有使用 SHA-256 的位置替换为 SM3：

```
HKDF-Hash = SM3
Hash.Length = 32
```

### 3.2 密钥派生链路

```
    0
    |
    v
  PSK -> HKDF-Extract = Early Secret
    |
    v
  Derive-Secret(., "derived", "") -> HKDF-Extract(., ECDHE) = Handshake Secret
    |                                              |
    |                    +--> Derive-Secret(., "c hs traffic", CH->SH)
    |                    |        -> QUIC client handshake keys
    |                    +--> Derive-Secret(., "s hs traffic", CH->SH)
    |                             -> QUIC server handshake keys
    v
  Derive-Secret(., "derived", "") -> HKDF-Extract(., 0) = Master Secret
    |
    v
    +--> Derive-Secret(., "c ap traffic", CH->SF)
    |        -> QUIC client 1-RTT keys
    +--> Derive-Secret(., "s ap traffic", CH->SF)
             -> QUIC server 1-RTT keys
```

### 3.3 密钥和 IV 派生

对每个 traffic secret，QUIC 使用 HKDF-Expand-Label 派生 AEAD 密钥和 IV：

```go
key = HKDF-Expand-Label(Secret, "quic key", "", key_len)   // 16 bytes for SM4-GCM
iv  = HKDF-Expand-Label(Secret, "quic iv", "", iv_len)     // 12 bytes
hp  = HKDF-Expand-Label(Secret, "quic hp", "", hp_len)     // 16 bytes
ku  = HKDF-Expand-Label(Secret, "quic ku", "", key_len)    // 16 bytes (key update)
```

> **关键差异**: RFC 9001 使用 `"quic key"` / `"quic iv"` / `"quic hp"` 标签（而非 TLS 的 `"key"` / `"iv"`）。

## 4. QUIC Packet Protection 实现

### 4.1 Nonce 构造

与 TLS 1.3 一致，QUIC 使用 96-bit (12-byte) nonce，通过 XOR 方式组合 IV 和数据包号：

```
nonce[0..3] = iv[0..3] ^ 0
nonce[4..11] = iv[4..11] ^ packet_number
```

其中 `packet_number` 为 62-bit 整数，以大端序填充到 8 字节后与 `iv` 的低 8 字节异或。

```go
func computeNonce(iv []byte, pn uint64) []byte {
    nonce := make([]byte, 12)
    copy(nonce, iv)
    nonce[4]  ^= byte(pn >> 56)
    nonce[5]  ^= byte(pn >> 48)
    nonce[6]  ^= byte(pn >> 40)
    nonce[7]  ^= byte(pn >> 32)
    nonce[8]  ^= byte(pn >> 24)
    nonce[9]  ^= byte(pn >> 16)
    nonce[10] ^= byte(pn >> 8)
    nonce[11] ^= byte(pn)
    return nonce
}
```

### 4.2 Header Protection

QUIC 使用 Packet Protection Key 派生单独的 Header Protection Key (`hp`)：

- **Long Header**: 掩码首个字节低 4 位 + Packet Number 字段
- **Short Header**: 掩码首个字节低 5 位 + Packet Number 字段

SM4-GCM 的 Header Protection 使用 AES-ECB 等价方式（这里用 SM4-ECB）：

```go
hp_key = HKDF-Expand-Label(Secret, "quic hp", "", 16)

// 采样密文前 16 字节作为输入
mask = SM4_ECB_Encrypt(hp_key, sample[0:16])

// Long Header: 首字节 ^= (mask[0] & 0x0f)
// Short Header: 首字节 ^= (mask[0] & 0x1f)
// Packet Number: pn_bytes[i] ^= mask[1+i]
```

### 4.3 加密流程

```
1. 构造 QUIC 数据包 (Header + Payload + Padding)
2. 计算 AEAD nonce = iv XOR packet_number
3. AAD = 包头（含未加密的 Packet Number）
4. 加密: ciphertext = SM4-GCM-Seal(key, nonce, payload, AAD)
5. Header Protection: 用 hp key 掩码头部敏感字段
```

### 4.4 解密流程

```
1. 用 hp key 去除 Header Protection，恢复真实首字节和 Packet Number
2. 计算 AEAD nonce = iv XOR packet_number
3. AAD = 恢复后的包头
4. 解密: payload = SM4-GCM-Open(key, nonce, ciphertext, AAD)
```

## 5. 实现架构

### 5.1 文件组织

采用两层分层：tls13gm 提供密码原语，quicgm 组装 transport 层，镜像 crypto/tls 与 quic-go 的关系。

```
tls13gm/                          # 密码原语层（≈ crypto/tls 的密码能力）
├── labels.go                     # LabelQUICKey / LabelQUICIV / LabelQUICHP / LabelQUICKU
├── quic_keys.go                  # DeriveQUICPacketKeys, QUICKeyUpdate, QUICPacketKeys.Zero
└── quic_header.go                # HeaderProtectionMask (SM4-ECB on 16-byte sample)

quicgm/                           # transport 组装层（≈ quic-go 消费 crypto/tls）
├── doc.go                        # transport-level RFC 8998 定位
├── packet.go                     # QUICPacketProtector (EncryptPayload/DecryptPayload/ApplyHeaderProtection/RemoveHeaderProtection)
├── varint.go                     # QUIC 变长整数编解码 AppendVarint/ReadVarint (RFC 9000 §16)
├── initial.go                    # QUIC v1 Initial packet 端到端 SealInitialPacket/OpenInitialPacket
├── packetnumber.go               # packet-number 截断编解码 ChoosePacketNumberLen/TruncatePacketNumber/DecodePacketNumber (RFC 9000 §17.1)
├── packet_test.go                # 包内白盒测试
├── varint_test.go                # varint 边界/往返测试
├── packetnumber_test.go          # packet-number 截断往返/阈值/重建分支测试
├── initial_test.go               # Initial 包端到端/篡改/隔离测试
├── bench_test.go                 # SM4-GCM vs AES-128-GCM 性能基线
└── test/quicgm_blackbox_test.go  # 黑盒测试
```

### 5.2 核心接口

密码原语层（`tls13gm`）与 transport 组装层（`quicgm`）的完整 API 见各包的 godoc
（`go doc ./tls13gm`、`go doc ./quicgm`）。关键符号：

- `tls13gm.QUICPacketKeys`（`AEADKey` / `AEADIV` / `HeaderKey`）+ `DeriveQUICPacketKeys`、`QUICKeyUpdate`、`HeaderProtectionMask`
- `quicgm.QUICPacketProtector`（`EncryptPayload` / `DecryptPayload` / `ApplyHeaderProtection` / `RemoveHeaderProtection`）+ `NewQUICPacketProtectorFromKeys`

### 5.3 QUIC 包编码与 Initial packet 端到端

```go
// varint.go — RFC 9000 §16 变长整数
func AppendVarint(b []byte, v uint64) ([]byte, error)   // 编码（选最小长度 1/2/4/8）
func ReadVarint(b []byte) (value uint64, n int, err error)
func VarintLen(v uint64) int
const MaxVarint uint64 = 1<<62 - 1

// initial.go — QUIC v1 Initial packet 端到端保护（dcid 派生 client initial secret）
func SealInitialPacket(dcid, scid, token []byte, pn uint64, payload []byte) ([]byte, error)
func OpenInitialPacket(dcid, packet []byte) (version uint32, scid, token []byte, pn uint64, payload []byte, err error)
const QUICVersion1 uint32 = 0x00000001
```

`SealInitialPacket` 内部完成：`dcid → DeriveQUICInitialSecrets → client in → NewQUICPacketProtector`，构造 long-header Initial 包（首字节 `0xC3`、version、dcid/scid/token/length varint、packet number 固定 4 字节），SM4-GCM 加密 payload（AAD = 首字节至 packet number 末尾），再施加 header protection。`OpenInitialPacket` 反向：解析未保护字段 → 去 header protection 恢复 packet number → SM4-GCM 解密。

**packet-number 截断**：`packetnumber.go` 提供 RFC 9000 §17.1 的完整截断原语：`ChoosePacketNumberLen`（发送端据 largestAcked 选最小字节数，阈值 `2^7/2^15/2^23/2^31`，nil 反馈→4 字节）、`TruncatePacketNumber`、`DecodePacketNumber`（接收端重建，int64 运算规避 uint64 下溢）、`AppendPacketNumber`（大端低 N 字节）。Initial 包因首个包无 ACK 反馈，始终用 4 字节（`ChoosePacketNumberLen(pn, nil)` 等价），其余加密级别（Handshake/1-RTT）由未来连接层在收到 ACK 后调用截断原语以节省字节。

**注意**：上述 API 覆盖 Initial 包的密码保护全链路与 packet-number 截断原语。配套的 TLS 1.3 GM 握手引擎（`tls13gm` 的协议常量/transcript/握手消息编解码/`ClientHandshaker`+`ServerHandshaker` 状态机）与 quicgm 的 CRYPTO frame + Handshake 长头部包 + 1-RTT 短头部包已实现；握手产出 Initial/Handshake/Application 三级密钥，经 `NewQUICPacketProtectorFromKeys` 喂入对应加密级别的包保护器。TLS 握手层已与 BabaSSL/Tongsuo 完成全场景互通验证（见 [`../security/interop-matrix.md`](../security/interop-matrix.md)）。仍留作后续迭代的是 QUIC 连接状态机（ACK/重传/流复用/拥塞，归 quic-go）。

## 6. Key Update

QUIC 支持 Key Update 机制（RFC 9001 §6），使用 `"quic ku"` 标签：

```
next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.Length)
next_keys   = DeriveQUICPacketKeys(next_secret)
```

## 7. 与 Route A / Route B 的关系

| 维度 | Route A (标准 TLS 1.3) | Route B (应用层 GM) | Route C (RFC 8998) |
|------|------------------------|--------------------|--------------------|
| QUIC 传输加密 | AES-128-GCM | AES-128-GCM | **SM4-GCM** |
| 密钥交换 | X25519 | X25519 | **curveSM2** |
| 签名 | ECDSA/RSA | ECDSA/RSA | **SM2-SM3** |
| Hash | SHA-256 | SHA-256 | **SM3** |
| 应用数据加密 | 标准 | SM4-GCM 应用层 | SM4-GCM 传输层 |
| 部署状态 | ✅ 生产 | ✅ 生产 | ✅ 互通已验证 |

## 8. 安全注意事项

1. **Nonce 唯一性**: SM4-GCM 要求相同密钥下绝不重复使用 nonce。QUIC 的 XOR-IV-with-PN 方案确保了这一点，前提是 PN 不回绕（QUIC 已有此保证）。

2. **Header Protection**: 必须使用独立的 `hp` 密钥，不可复用 AEAD key。

3. **密钥更新（Key Update）**: QUIC 的 Key Phase 变更必须正确更新所有密钥
   （AEAD key + IV + HP key）。

   > **职责边界**：pollux **不强制**密钥更新阈值。`tls13gm.QUICKeyUpdate` /
   > `tls13gm.AEAD.Seal` 仅提供更新原语与文档约定，**由传输层（quic-go）负责
   > 在阈值临近时主动发起更新**。AEAD nonce 是 `IV XOR packet_number`，在单一
   > 密钥代内只要 PN 单调不回绕就不会重复；但单一密钥代不得保护无上限数量的包，
   > 否则 nonce 空间或计数器将面临碰撞风险。
   >
   > 参考阈值：
   > - **TLS 1.3 记录层**：~2^24.5 条记录后必须更新（RFC 8446 §5.5，
   >   通过 `"traffic upd"` label）。
   > - **QUIC 数据包**：遵循 RFC 9001 §6（通过 `tls13gm.QUICKeyUpdate` +
   >   `"quic ku"` label 重建 protector），具体阈值由 quic-go 的 AEAD 限制驱动。
   >
   > 集成方若直接使用 `tls13gm` / `quicgm` 而不经 quic-go，**必须自行实现**
   > 阈值监控并在到达时调用 `QUICKeyUpdate` + 重建 `QUICPacketProtector`，
   > 否则长连接存在 nonce 复用（→ SM4-GCM 密钥恢复）风险。

4. **连接 ID 隐私**: Short Header 的 Connection ID 不加密，应避免在 Header Protection 中泄露信息。

5. **状态机一致性**: QUIC 加密级别切换（Initial → Handshake → 1-RTT）必须严格按序，丢弃越级数据包。

## 9. 性能基线（Apple M5, darwin/arm64, go 1.26, benchtime=2s）

| 操作 | 大小 | 吞吐 (MB/s) | 说明 |
|------|------|-------------|------|
| SM4-GCM 加密 | 1200 B | 476.6 | Route C payload AEAD |
| SM4-GCM 解密 | 1200 B | 491.7 | Route C payload AEAD |
| AES-128-GCM 加密 | 1200 B | 5406.2 | Route A baseline |
| AES-128-GCM 解密 | 1200 B | 5382.0 | Route A baseline |
| SM4-GCM 加密 | 16384 B | 534.1 | 大包接近 SM4 理论吞吐 |
| AES-128-GCM 加密 | 16384 B | 7239.7 | AES 硬件加速 |
| Header Protection | 1200 B | 655.8 ns/op | apply+remove（含 buffer 拷贝） |
| DeriveQUICPacketKeys | — | 2.21 µs/op | 一次 traffic secret → 三密钥 |
| DeriveQUICInitialSecrets | — | 2.10 µs/op | dcid → client/server in |

SM4-GCM 吞吐约为 AES-128-GCM 的 1/11（1200 B：476 vs 5406 MB/s）。**这并非纯软件实现**：项目的 `sm4` 包是 `emmansun/gmsm` v0.43.0 的薄封装，gmsm 的硬件加速策略（`internal/sm4/cipher_asm.go`）为 `cpu.ARM64.HasSM4`（原生 SM4 指令）→ `cpuid.HasAES`（用 AES 指令等价实现 SM4）→ 纯软件。Apple M5 无原生 SM4 指令，实际走 AES 指令等价路径（已硬件加速，单 block ≈ 76 ns，约为纯软件查表的 1/2）。11× 差距是算法固有开销：SM4 为 32 轮、AES-128 为 10 轮，且用 AES 指令模拟 SM4 每轮需多条 AESE/AESMC，单 block 即慢约 7-8×（76 vs ~10 ns），叠加 GCM 调度。在具备原生 SM4 指令（`HasSM4`）的国产 CPU 上差距会显著缩小，可据此衡量优化收益。
