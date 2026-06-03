<!-- /autoplan restore point: /Users/ycq/.gstack/projects/pollux-go/HEAD-autoplan-restore-20260527-220126.md -->

# TLCP 握手 Bug 修复计划

## 问题概述

TLCP 握手实现有三个 bug，多次修复尝试均失败。根因是消息顺序逻辑和证书验证逻辑有结构性错误。

## Bug 1 (Critical): 服务端重复发送 ServerKeyExchange

**文件**: `tlcp/handshake.go` 服务端 `serverHandshake()` 方法

**根因**: 第 378-387 行正确发送了一次 ServerKeyExchange，但第 405-414 行在 ServerHelloDone 之前又重复调用了一次 `serverECDHE()` 或 `serverECCSKE()`。

**修复**: 删除第 405-414 行的重复调用。ServerHelloDone 之前不需要再发送密钥交换消息。

正确消息顺序（无 ClientAuth）:
```
Server → Client: ServerHello → Certificate → ServerKeyExchange → ServerHelloDone
```

正确消息顺序（有 ClientAuth）:
```
Server → Client: ServerHello → Certificate → ServerKeyExchange → CertificateRequest → ServerHelloDone
```

## Bug 2 (High): ClientAuth 消息顺序错误

### 客户端问题

**文件**: `tlcp/handshake.go` 客户端 `clientHandshake()` 方法

**根因**: 收到 CertificateRequest 后，客户端没有发送 Certificate 和 CertificateVerify。

正确消息顺序（客户端收到 CertificateRequest 后）:
```
Client → Server: Certificate → ClientKeyExchange → CertificateVerify → CCS → Finished
```

**修复**:
1. 用变量跟踪是否收到 CertificateRequest: `certRequested`
2. 收到 ServerHelloDone 后，如果 certRequested，发送客户端 Certificate
3. 发送 ClientKeyExchange 后，如果 certRequested，发送 CertificateVerify（签名握手摘要）

### 服务端问题

**文件**: `tlcp/handshake.go` 服务端 `serverHandshake()` 方法

**根因**: 服务端先读 ClientKeyExchange（第 422 行），然后才尝试读客户端 Certificate（第 455 行）。但 TLCP 规范要求客户端先发 Certificate，再发 ClientKeyExchange。

正确消息顺序（服务端期望）:
```
read (optional) Certificate → read ClientKeyExchange → read (optional) CertificateVerify → read CCS → read Finished
```

**修复**:
1. 如果配置了 ClientAuth，先尝试读取客户端 Certificate
2. 然后读取 ClientKeyExchange
3. 如果客户端发了 Certificate，再尝试读取 CertificateVerify（并实现签名验证）

### CertificateVerify 签名验证

**文件**: `tlcp/handshake.go` 第 494-503 行

**根因**: CertificateVerify 的验证是 TODO，未实现。

**修复**: 实现完整的 CertificateVerify 验证逻辑：
1. 解析 CertificateVerify 消息中的签名
2. 使用客户端签名证书公钥验证签名
3. 签名内容是除 CertificateVerify 本身之外的所有握手消息的 SM3 摘要

## Bug 3 (Medium): 证书 roots 检查不完整

**文件**: `tlcp/handshake.go` `verifyOneCert()` 函数

**根因**: 当 `roots == nil` 但 `rootCerts != nil` 时，函数不调用 `verifyCertWithSMX509`，直接跳到 hostname 验证。

**修复**: 在 `roots == nil` 分支添加对 `rootCerts` 的检查：
```go
} else if len(rootCerts) > 0 {
    if err := verifyCertWithSMX509(cert, rootCerts, dnsName); err != nil {
        return err
    }
}
```

## Eng 审查发现的额外问题

### E1: 服务端 post-CKE 读取逻辑在非 ClientAuth 模式下也会失败

当前第 455 行 `readHandshakeMessage()` 在非 ClientAuth 模式下也会执行。
客户端发送 CCS（record type 20），而 `readHandshakeMessage` 只接受 handshake
记录（record type 22），会返回 `errUnsupportedRecord`。

Bug 1 掩盖了这个问题——因为重复 SKE 导致客户端在 ServerHelloDone 阶段就失败，
服务端根本到不了第 455 行。

**修复**: 将第 453-518 行的 ClientAuth 逻辑重构。读取顺序改为：
```
if ClientAuth configured:
  read msg → if Certificate, process → read next msg
→ must be ClientKeyExchange
if client sent Certificate:
  read CertificateVerify → verify
read CCS via readRecord()  // 必须用 readRecord，不能用 readHandshakeMessage
enable encryption
read Finished
```

### E2: certificateVerifyMsg 缺少 unmarshal 方法

`handshake_messages.go` 中 `certificateVerifyMsg` 只有 `marshal()` 没有 `unmarshal()`。
实现 CertificateVerify 验证需要先解析消息。

**修复**: 在 `handshake_messages.go` 添加 `unmarshal` 方法。

### E3: CertificateVerify 哈希时序问题

第 496 行在验证签名前就调用了 `updateHash(typeCertificateVerify, certBody)`。
但 CertificateVerify 的签名覆盖的是**不包含** CertificateVerify 的握手摘要。

**修复**: 先保存哈希快照 `hashForVerify := hs.handshakeHash.Sum(nil)`，
然后 `updateHash`，然后用快照验证签名。

### E4: TestCertificateVerify_SelfSigned 可能需要更新

该测试 `InsecureSkipVerify: false` 但没有配置 roots，会被第 800 行守卫条件拒绝。

## 修改文件清单

- `tlcp/handshake.go` — 主要修改文件，修复所有三个 bug + E1/E3
- `tlcp/handshake_messages.go` — 添加 certificateVerifyMsg.unmarshal (E2)

## 修复策略

1. 先修复 Bug 1（删除重复 SKE）+ E1（重构 post-CKE 逻辑），确保基本握手正常
2. 再修复 Bug 3（roots 检查），独立于其他 bug
3. 最后修复 Bug 2（ClientAuth）+ E2（unmarshal）+ E3（hash 时序）
4. 运行测试确认全部通过
5. 添加 ClientAuth 集成测试

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|
| 1 | CEO | Accept all 3 bugs as real | Mechanical | P1 | CEO subagent confirmed each bug in code |
| 2 | CEO | Fix Bug 1 first (simplest) | Mechanical | P3 | Delete 10 lines, no side effects |
| 3 | CEO | Fix Bug 3 second (independent) | Mechanical | P3 | Single else-if branch, isolated |
| 4 | CEO | Fix Bug 2 last (most complex) | Mechanical | P5 | Requires client+server+new test |
| 5 | Eng | Restructure post-CKE server logic (E1) | Mechanical | P1 | readHandshakeMessage can't read CCS |
| 6 | Eng | Add certificateVerifyMsg.unmarshal (E2) | Mechanical | P1 | Required for CertificateVerify verification |
| 7 | Eng | Fix hash timing for CertificateVerify (E3) | Mechanical | P1 | Sign covers hash excluding CertificateVerify |
| 8 | Eng | Note TestCertificateVerify_SelfSigned issue | Mechanical | P1 | Guard condition blocks test |

## GSTACK REVIEW REPORT
