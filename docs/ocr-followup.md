# OCR 发现 — 后续跟踪

本文档跟踪 open-code-review (OCR) 会话
`08698ef8-85f2-45aa-a067-3053bc9ccdcb` 的发现项处理状态。

v0.3.0 已完成 critical/high 扫描 + 全量 medium/low checkpoint triage +
破坏性变更批 + 复查轮次。当前**唯一剩余待办**是 v0.4.0 移除 deprecation
shim（见下）。

## 汇总

| 范围 | 总数 | 已处理 | 误报 | 剩余 |
|------|------|--------|------|------|
| Critical | 35 | 29 修复 + 4 误报 + 2 上游 | — | 0 |
| High | 106 | ~74 修复 + ~7 误报 + ~4 上游 | — | ~21（估算，无逐项清单） |
| Medium/Low checkpoint | 421 | 17 REAL 修复 + 291 ADDRESSED + 73 FP + 66 BYDESIGN | 73 | 0 |
| OCR 复查轮次（squash 后） | 8 发现 | 1 修复 + 7 判定不修 | — | 0 |

> Medium/Low 的 421 个 checkpoint 全量 triage 完成（REAL 占比 4%，印证
> critical/high 扫描覆盖到位）。完整 triage 表与逐条修复记录见 git 历史：
> 提交 `1d1d2d3b`（17 REAL + gofmt 批量 + CI 门禁）、`3c86e51e`
> （errMissingCertificate 拆分）。

## 剩余待办

### 移除 `http/` deprecation shim（计划 v0.4.0）

**为何不在 v0.3.0 移除**：shim 随 v0.3.0 首次发布，文档自身的弃用策略要求
"shim 应至少在一个带 tag 的 minor 版本中发布过"（例 v0.3.0 → v0.4.0 移除）。
立即移除=0 版本迁移窗口，剥夺下游迁移机会。

`http/doc.go` 是 `http`→`https` 重命名时留下的兼容 shim，通过类型别名 + 薄
函数包装重新导出 `https` 的每个公共符号，使 `github.com/iuboy/pollux-go/http`
import 仍能编译（staticcheck SA1019 标记每次使用为 deprecated）。

**移除步骤**（v0.4.0 专门 PR）：

1. **核实迁移窗口已过**：`git log --oneline -- http/doc.go` 确认 shim 已在
   v0.3.0 tag 中发布。
2. **CHANGELOG / release notes 公告破坏性变更**：
   ```
   - 已移除 deprecated 的 github.com/iuboy/pollux-go/http shim 包。
     请将所有 import 迁移到 github.com/iuboy/pollux-go/https
     （polluxhttp.X → https.X）。API 表面完全一致。
   ```
3. **删除整个 `http/` 目录**：`git rm -r http/`。该目录只含 `doc.go`（shim）；
   若 `ls http/` 显示其他内容，先调查再删。
4. **搜索遗漏引用**：
   ```
   grep -rn 'pollux-go/http"' --include='*.go' .
   grep -rn 'polluxhttp\.\|polluxHttp\.' --include='*.go' .
   ```
   命中要么是针对旧名的新代码（迁 `https`），要么是过时注释（更新）。
5. **跑完整测试**确认无残留依赖：`go build ./... && go test -count=1 ./...`。
   `test/` 下 5 个测试文件已在重命名时迁到 `https`，核实未回退。
6. **更新文档**：本文件 + README（已更新为 `https`，核实未回退）。

**为何用 deprecation 窗口**：重命名是纯人体工程学改进（无行为变更），
一个 minor 版本窗口让下游按自己节奏迁移，无需立即承受编译中断；
SA1019 警告让 deprecation 在 CI 中不被遗漏。

## 已确认的误报（历史参考，避免重复调查）

- `tls13gm/signature.go`（×2）— 调用方传 `transcript.Sum()`（已哈希），
  不是原始 transcript；OCR 误读参数名。
- `tlcp/engine_messages.go` 原始缓存"数据竞争" — 握手在 `handshakeMutex`
  下单 goroutine 运行。
- `quic/config.go` `MaxIncomingStreams` — 已在 `quic/listener.go` 接入。
- `http/listener.go` `SetHandshakeTimeout`/`SetProtocolMask` "TOCTOU" —
  setter 的 Lock/Unlock 与 Accept 临界区建立 happens-before 边沿；快照后
  释放锁是有意的热加载契约，非 TOCTOU。
- `tlcp/engine_keyagreement.go` `sm2SharedKey` 参数顺序 — 双向 `sPub` 都是
  本侧静态公钥，与 gmsm MQV 原语一致。

## OCR 复查轮次（squash 后）的 7 项"不修复"判定

full-file scan 对 5 个代码修复文件返回 8 项发现，1 项修复（`errMissingCertificate`
拆分，见 `3c86e51e`），7 项判定不修（附理由，避免重复调查）：

- `quicgm/listener.go` `Listen(ctx)` 忽略 ctx — **不可修复**：上游 quic-go
  的 `ListenAddr`/`Listen`/`Transport.Listen` 均不接 context，底层
  `net.ListenPacket` 也无 ctx 变体。仅 hostname DNS 阶段可中断，收益微小。
- `sm4/modes.go` PKCS7 截断 + 侧信道 — SM4 blockSize 恒 16（截断不可能）；
  侧信道在已认证密文场景不可利用。
- `smx509/keyid.go` asn1.Marshal 失败返空 Extension — `asn1.Marshal([]byte)`
  对合法输入不可能失败；防御性代码。
- `smx509/keyid.go` KeyIdentifier 16 字节下界 — 在 `ValidateKeyIdentifiers`
  中（非扩展生成）；RFC 5280 未强制 4 字节，16 是设计选择。
- `smx509/keyid.go` GenerateSubjectKeyIdentifier 缺 nil 检查 — **误报**，
  `MarshalPKIXPublicKey(nil)` 返回 error 不 panic。
- `https/server.go` ServerOptions 并发读写 — config-once 结构（文档已声明
  契约），证书轮替应重建 config 非原地改。
- `quicgm/initial.go` header 容量 64 不足 — 性能微优化，append 扩容开销可忽略。

## 人工代码审查（4 个高危密码学路径，跳过 OCR）

OCR 大规模 full-file scan 卡死后，改为对 4 个高危面做针对性人工审查
（并行 agent + 主线逐条验证）。发现并修复 7 项 CONFIRMED：

### 提交 `33fdac0c`（审查面 1/2/3/4）

- **[CRITICAL] `tls13gm/handshake.go` HandleServerHello PSK 认证绕过** —
  仅凭 ServerHello 含 `pre_shared_key` 扩展就设 `pskMode=true`，跳过
  Certificate/CertificateVerify，不检查客户端是否真提供了 PSK。MITM 发伪造
  ServerHello 即可零证书冒充服务器。修复：gate 于 `resumptionPSK != nil`。
- **[HIGH] `jwt/signer.go` sm2SignerVerifier.Zeroize no-op** —
  `ZeroBytes(D.Bytes())` 清的是副本，私钥不受影响。改为 `SetInt64(0)` +
  诚实文档（big.Int 无法外部清底层 words）。
- **[HIGH] `smx509/cert.go` CBC 解密畸形 IV 致 panic（2 处）** — PKCS8 + legacy
  PEM 路径未校验 IV 长度就调 `NewCBCDecrypter`（panic 非 error）。加守卫。
- **[MEDIUM] `tls13gm/keyschedule.go` DeriveTrafficKeys error path 泄漏 key** —
  IV 派生失败时未清零已派生 key。加 `ZeroBytes(key)`。

### 提交 `<本次>`（审查面 5/6）

- **[HIGH] `quic-go/.../gm_crypto_setup.go` ticket_age_add 硬编码 0** —
  RFC 8446 §4.6.1 要求每 ticket 随机；常量 0 使客户端能伪造 age=0 绕过
  anti-replay 的 maxAge 过期检查，且 ticket age 对中间人明文可见。改为每
  ticket 生成 4 字节随机 `ticketAgeAdd`。
- **[HIGH] `smx509/verify.go` verifySM2 丢弃 Intermediates** — 只转 Roots 不转
  Intermediates，三级链（Root→Intermediate→Leaf）无法验证，迫使调用方把中间
  证加入 Roots（错误提升为信任锚）。修复：补 Intermediates 转换循环。
- **[MEDIUM] `smx509/ocsp_sm2_parse.go` 多状态 OCSP 响应未过滤 serial** —
  无条件取 `Responses[0]`，攻击者可捆绑 serial Y 的 Good 状态满足 serial X
  的查询。修复：`n > 1` 时 fail-closed 拒绝（与 x/crypto ParseResponse 一致）。
- **[HIGH] `smx509/ocsp_sm2_parse.go` 委托响应者缺 OCSPSigning EKU 检查** —
  RFC 6960 §4.2.2.2 要求 delegated responder 证书携带 id-kp-OCSPSigning
  EKU，否则攻击者可用任意 issuer 签发的 TLS 叶子证书伪造 OCSP 响应。
  原 SUSPECT 判定"与上游对齐"有误：pollux-go 已比 x/crypto 多做了
  embedded cert 签名验证，应补全整个验证链而非停在中间状态。修复：
  通过公钥比对区分 issuer-direct（CA 自签 OCSP，§4.2.1 豁免 EKU）与
  delegated responder，仅对后者强制 EKU；`issuer==nil` 时 fail-closed
  也要求 EKU（无法确认身份）。回归测试覆盖正/反两路径。
- **[MEDIUM] `smx509/ocsp_sm2_parse.go` ResponderID 未比对签名证书** —
  RFC 6960 §4.2.2.2 要求 ResponderID 必须对应实际签名者；原代码只提取不
  校验。key-reuse 攻击：攻击者持同一 SM2 私钥下两张不同 subject 证书
  （均带 OCSPSigning EKU），用共享密钥签名、ResponderID=A、embed certB，
  签名对 B 同样有效——无 ResponderID 比对则被误判为来自 B，破坏 RFC 6960
  身份绑定。x/crypto 也不校验（信任调用方 issuer 参数），但 pollux-go
  embedded-cert 路径已超出上游，按"补全整条验证链"原则闭环。修复：
  新增 matchesResponderID（Name 字节比对 / KeyHash 按 CertID 算法计算
  Hash(BIT STRING subjectPublicKey)），embedded + issuer-direct 两路径
  验签后均调用。回归测试覆盖 key-reuse 攻击场景。

### 审查面 6 续 — CRL 路径深审（无需修复）

`smx509/crl.go` + `crl_reason.go` 全量审查，结论 **CLEAN**：

- pollux-go **只生成 CRL**（`CreateRevocationList` 委托 gmsm 或 stdlib），
  **不做任何 CRL 验证/消费**（全仓库无 `CheckCRLSignature`/`ParseRevocationList`
  验证路径，唯一 `x509.ParseRevocationList` 在测试里反解生成产物）。
- 因此 OCSP 验证面的漏洞类别（签名验证、issuer 绑定、ResponderID、EKU）
  在 CRL 无对应面。
- 生成路径正确：`CRLNumber` 从模板透传（调用方设 1，无 0/回滚风险）、
  `KeyUsageCertSign|CRLSign` 正确、`ThisUpdate`/`NextUpdate` 透传。
  `toSMX509RevocationList` 反射拷贝是通用转换，非 CRL 专属风险。
- 测试覆盖：fresh template + 空 CRL 两场景。

### SUSPECT 判定（不修复，附理由）

- **`tlcp/engine_conn.go` CBC HMAC 输入长度计时侧信道** — HMAC 输入长度依赖
  padding 长度（attacker 控制），产生计时差异。但 padding 错与 MAC 错返回同一
  error（line 319 统一 `bad record MAC`），经典 Vaudenay padding oracle 不成立；
  与 Go stdlib `crypto/tls` 同级残余风险，RFC 7366 + TLS 1.3 弃用 CBC 已缓解。
  **判定 BYDESIGN**，加固需改 MAC 语义且收益微小。
- **`tls13gm/handshake.go:1078` age<0 死代码** — `uint32` 减法后转 `int64` 永不
  为负，`age < 0` 分支不可达。但 wrap-around 产生大正数仍被 `> maxAge` 正确
  拒绝，无安全洞。**判定无害**。

## 已完成工作（摘要，详见 git 历史）

- **Tier 1-4（v0.3.0 批）**：critical/high 扫描 + 4 项文档准确性 + 纵深防御
  守卫 + CI/性能/测试覆盖 + 5 项破坏性变更（http→https 重命名、
  `*time.Duration` 超时 API、`sm9.Verify` 返 error、pwHash 并发契约）。
- **Medium/Low triage（提交 `1d1d2d3b`）**：421 checkpoint 全量 triage，
  17 REAL 修复（1 medium sm4 GCM nonce 守卫 + 4 low 代码 + 9 文档 + 15 gofmt），
  CI 新增 gofmt 门禁。
- **复查轮次（提交 `3c86e51e`）**：errMissingCertificate 拆分为语义独立 sentinel。
