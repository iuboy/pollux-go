# QUIC SM4-GCM Packet Protection 设计文档

> 状态：**草案** | 路线：Route C (QUIC + RFC 8998) | 优先级：P2

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

```
tls13gm/
├── keyschedule.go     # Key Schedule (已有: DeriveEarlySecret 等)
├── labels.go          # 标签常量 (已有: LabelKey, LabelIV 等)
├── aead.go            # SM4-GCM AEAD (已有)
├── aead_ccm.go        # SM4-CCM AEAD (占位)
├── keyexchange.go     # curveSM2 ECDHE (已有)
├── signature.go       # SM2-SM3 签名 (已有)
├── hkdf.go            # SM3 HKDF (已有)
├── constants.go       # 密码套件 ID (已有)
│
├── quic_keys.go       # [新增] QUIC 密钥派生 (quic key/iv/hp/ku labels)
├── quic_protection.go # [新增] QUIC Packet Protection (encrypt/decrypt)
└── quic_protection_test.go  # [新增] QUIC 保护测试
```

### 5.2 核心接口

```go
// quic_keys.go

// QUIC label constants per RFC 9001 §5.1.
const (
    LabelQUICKey = "quic key"
    LabelQUICIV  = "quic iv"
    LabelQUICHP  = "quic hp"
    LabelQUICKU  = "quic ku"
)

// QUICPacketKeys holds the AEAD key, IV, and header protection key.
type QUICPacketKeys struct {
    AEADKey   []byte // 16 bytes (SM4-GCM)
    AEADIV    []byte // 12 bytes
    HeaderKey []byte // 16 bytes (SM4-ECB for header protection)
}

// DeriveQUICPacketKeys derives all QUIC packet protection keys from a traffic secret.
func DeriveQUICPacketKeys(trafficSecret []byte) (*QUICPacketKeys, error) {
    key, _ := HKDFExpandLabel(trafficSecret, LabelQUICKey, nil, 16)
    iv, _  := HKDFExpandLabel(trafficSecret, LabelQUICIV, nil, 12)
    hp, _  := HKDFExpandLabel(trafficSecret, LabelQUICHP, nil, 16)
    return &QUICPacketKeys{AEADKey: key, AEADIV: iv, HeaderKey: hp}, nil
}
```

```go
// quic_protection.go

// QUICPacketProtector provides QUIC packet protection using SM4-GCM.
type QUICPacketProtector struct {
    keys *QUICPacketKeys
    aead *AEAD
}

// NewQUICPacketProtector creates a protector from a traffic secret.
func NewQUICPacketProtector(trafficSecret []byte) (*QUICPacketProtector, error) {
    keys, err := DeriveQUICPacketKeys(trafficSecret)
    if err != nil { return nil, err }
    aead, err := NewAEAD(keys.AEADKey, keys.AEADIV)
    if err != nil { return nil, err }
    return &QUICPacketProtector{keys: keys, aead: aead}, nil
}

// EncryptPacket encrypts a QUIC packet payload with header protection.
func (p *QUICPacketProtector) EncryptPacket(pn uint64, header, payload []byte) ([]byte, error)

// DecryptPacket decrypts a QUIC packet (removes header protection first).
func (p *QUICPacketProtector) DecryptPacket(pn uint64, header, ciphertext []byte) ([]byte, error)

// ApplyHeaderProtection applies QUIC header protection using SM4-ECB.
func ApplyHeaderProtection(hpKey, header, sample []byte) error

// RemoveHeaderProtection removes QUIC header protection.
func RemoveHeaderProtection(hpKey, header, sample []byte) (uint64, error)
```

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
| 部署状态 | ✅ 生产 | ✅ 生产 | 🔬 实验 |

## 8. 安全注意事项

1. **Nonce 唯一性**: SM4-GCM 要求相同密钥下绝不重复使用 nonce。QUIC 的 XOR-IV-with-PN 方案确保了这一点，前提是 PN 不回绕（QUIC 已有此保证）。

2. **Header Protection**: 必须使用独立的 `hp` 密钥，不可复用 AEAD key。

3. **密钥更新**: QUIC 的 Key Phase 变更必须正确更新所有密钥（AEAD key + IV + HP key）。

4. **连接 ID 隐私**: Short Header 的 Connection ID 不加密，应避免在 Header Protection 中泄露信息。

5. **状态机一致性**: QUIC 加密级别切换（Initial → Handshake → 1-RTT）必须严格按序，丢弃越级数据包。

## 9. 下一步行动

| 步骤 | 任务 | 优先级 |
|------|------|--------|
| 1 | 创建 `quic_keys.go` — QUIC 标签常量和密钥派生 | P2 |
| 2 | 创建 `quic_protection.go` — Packet Protection 实现 | P2 |
| 3 | 集成 Header Protection（需 SM4-ECB） | P2 |
| 4 | Key Update 支持 | P2 |
| 5 | 端到端 QUIC + SM4-GCM 握手测试 | P3 |
| 6 | 性能基准测试（对比 AES-128-GCM） | P3 |
