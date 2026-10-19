# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.5.1] - 2026-10-18

### Added — 第三轮安全审查遗留项收尾(5 项功能/加固)

- **tls13 `CipherSuites` 选项**:`ServerOptions/ClientOptions.CipherSuites` 可选限定 TLS 1.3 套件偏好(三个套件均 AEAD;空=stdlib 默认序)。非 TLS 1.3 套件 ID 报错——Min=Max=TLS1.3 下它们只会静默清空偏好集
- **https 会话票据控制**:`ServerOptions.SessionTicketKeys`(32 字节键,配置期校验——stdlib SetSessionTicketKeys 对错误长度直接 panic;多实例部署共享票据键,替代每进程 24h 独立轮换)与 `DisableSessionTickets`(合规禁恢复)
- **smx509 传统 PEM DES 策略门**:传统 Proc-Type/DEK-Info 信封的 DES-CBC(56 位)/DES-EDE3-CBC 默认拒绝,`DecryptPEMPrivateKey(DER)WithOptions + DecryptOptions.AllowLegacyDESPEM` 显式 opt-in(合规姿态可整体禁用;AES-CBC 传统信封不在此列——MD5 KDF 是整个遗留格式固有的,非可选密码)。原两函数保持签名、策略变严
- **tls13gm CCM 构造器标注**:文档明确 EXPERIMENTAL/NOT WIRED TO NEGOTIATION——无套件常量、无握手路径、无 Tongsuo 互通测试;接线前任何使用它的套件应视为不可互通
- **tlcp `configToNative` 套件校验**:垃圾/非 TLCP 套件 ID(如 stdlib 套件)此前静默入引擎、只在握手深处模糊失败,现入口即拒(套件校验不再依赖要求叶子证书的 `Validate()`);静态 ECC 套件常量与 `LegacyCipherSuites` 补无前向保密警告(遗留互通仍刻意保留)

### Fixed — 第三轮安全审查 P2 低危批(12 项 LOW 修复 + 8 项 INFO 修复;清单由 3 路并行审查重建)

**LOW 修复:**
- **[fork] 0-RTT opener/sealer 每包重建缺陷**:此前每次 Get 都新建,opener 的 `highestRcvdPN` 逐包归零——截断包号按零基线解码,重建的头与 AEAD AAD 失配,对端包号跨 2 字节 epoch 后 0-RTT 包静默解密失败(上游同样缓存)。现缓存实例并在全部弃钥位点/Close 释放;跨 epoch 包号重建有回归锁定
- **[fork] prevRcvKM 终身保留**:对齐上游 startKeyDropTimer——两个密钥更新提交点(对端发起/本端更新被证实)启动 3×PTO(近似)过期,到期在 Open 入口丢弃(RFC 9001 §6.1),收敛前向保密损失与迟到包回放面
- **[quicgm] anti-replay 缓存无界增长**:进程内缓存增加容量上限(默认 2^20,`NewAntiReplayCacheWithCap` 可调),满时 fail-safe 拒新 0-RTT(恢复仍走 1-RTT)——此前长窗口配置下高恢复量或攻击者重放大量合法票据可耗尽内存
- **[fork] 密钥材料擦除**:rollKeys 擦除被替换的滚动 traffic secret(tls13gm 新导出 `ZeroBytes` 包装,供独立模块的 fork 绕过 internal/ 可见性);Close 擦除已采集 resumption PSK/identity。注意 1-RTT AEAD 不在 Close 自动擦除——拆除路径要在其后用 1-RTT 密钥封 CONNECTION_CLOSE(实测回归后回退,`gmUpdatableAEAD.Zero` 保留给确知不再发包的所有者显式调用)
- **[fork] Initial/Handshake/0-RTT opener 无完整性上限**:`gmLongOpener` 计入 AEAD 认证失败,达 SM4-GCM 上限返回 AEADLimitReached(RFC 9001 §6.6)——此前仅 1-RTT 有界,攻击者可用垃圾包无界消耗解密 CPU
- **[sshca] 密钥类型白名单**:`AllowedKeyTypes`(默认 ed25519/ecdsa/rsa≥2048,可整体替换)同时约束 CA 密钥与被签公钥——此前任意 `ssh.PublicKey` 原样入证,CA 会为 ssh-dss 等弱类型背书
- **[sshca] 扩展白名单**:host 证书拒绝一切请求扩展(PROTOCOL.certkeys 明确禁止;此前原样拷贝),user 证书扩展名必须落在 permit-* 白名单——与 critical option 同样的签发/验证对称白名单
- **[tlcp] 客户端 ALPN 信任门**:客户端从不提议 ALPN,恶意服务器此前可让 `ConnectionState().NegotiatedProtocol` 报告任意未协商协议;现按提议列表校验(与 tls13gm 已修的 ALPN 信任族同类),恶意 ServerHello 注入有 pipe 级回归锁定
- **[tlcp] 空套件回退对齐 DefaultCipherSuites**:engine 级空 cipherSuites 此前回退到 static-ECC(无 PFS)+CBC 套件,与包级默认安全姿态矛盾——直接构造 tlcpEngineConfig 的调用方会静默降级
- **[https] 标准 TLS 密码套件白名单**:显式 CipherSuites 列表(服务端/客户端)必须是 AEAD+PFS;CBC/3DES/RSA 密钥交换报错。共享字段中的 GM 套件 ID(hybrid 模式)剔除而非报错;全 GM 列表回落 stdlib 默认组
- **[kdf] PBKDF2 拒绝空盐**:空盐使派生跨用户确定、彩虹表抵抗整体失效(pwHash 的 8 字节下限既有不变;RFC 2898 向量的 4 字节盐仍合法)
- **[tls13gm] 票据明文擦除**:解密循环内解析失败与非保留命中的整套明文(含另一把有效 PSK)即刻擦除——此前 decline/TEK 轮换场景裸 PSK 留在堆上

**INFO 修复:** tls13gm 密钥调度局部变量擦除(ECDHE 共享密钥/early secret/finished key/verify data/binder 派生链,13 处 defer);`ticket_age_add` 改由 tls13gm 内部随机生成(`NewSessionTicket(With Data)` 签名变更,fork 调用方同步);key_share/ALPN/cookie 解析与编解码严格化(trailing 字节拒绝、>65535 cookie 报错、ALPN 名字 1-255 字节校验);sshca 序列号生成 fail-closed(取消熵故障时的时间戳回退);sshca 有效期校验 60s 时钟偏差容忍(CertChecker.Clock 垫片);https NewTLS13Client 补齐与 NewClient 一致的 fail-closed 信任门;tlcp CKE 解密失败错误统一(消除格式预言机);quicgm 负值传输参数拒绝 + `ObfuscatedTicketAge` 帮助函数(直传 harvested ageAdd 会令服务端年龄门失效);fork NextEvent 弹出槽清零

**上游阻塞(注释归档,待 gmsm 暴露擦除接口):** tlcp MQV 临时标量、SM4 密钥编排均无法从外部擦除(gmsm ecdh/AEAD 封装)。**经上游对照撤销:** fork numRcvd 提交包计数(与上游 v0.64.0 行为一致,非缺陷)。**遗留未修(功能项):** https 会话票据键轮换钩子、smx509 传统 PEM 弱密码策略开关、tls13 CipherSuites 选项、tls13gm CCM 构造器标注、tlcp 静态 ECC 套件协商面

### Fixed — 第三轮安全审查收尾:M7 Retry 互操作 + M6 gmsm 上游同步缺口实证

- **[中] GM QUIC Retry 互操作**(fork `GMCryptoSetup.ChangeConnectionID`,M7):此前为 no-op——收到 Retry 的 GM 连接双方向仍用**原 DCID** 派生的 Initial 密钥封解密,post-Retry 包永远打不开(RFC 9001 §5.2 要求按新 DCID 重推 Initial secrets)。现按新 DCID 重推双向密钥(`reinitInitialKeys`);派生失败 panic(接口无错误返回,对齐上游 32 字节 DCID "不可能失败"不变量)。回归测试 `gm_retry_test.go` 三断言:新密钥可解、旧密钥不可解、独立推导的 ClientInitialKeys 交叉验证
- **M6 gmsm 上游同步缺口草稿**(`docs/security/gmsm-upstream-stdlib-sync.md`,未对外提交):两处缺口均已在 gmsm v0.45.0(当前最新)上实证复现——(1) **excluded IP 名称约束可被静默绕过**:smx509 遗漏 stdlib CL 787220(golang/go#79833,Go 1.27 已修)的 host-bit 归一化,host-bits 非零约束 + 一条邻居槽位约束即令二分查找跳过真正匹配项,stdlib 拒绝的链 smx509 放行;(2) `parseRFC2821Mailbox` 缺 stdlib 后续硬化(域内 `@` 等被 gmsm 接受、stdlib 拒绝)。pollux-go 侧不做 fork 补丁,依赖上游修复;依赖 IP 名称约束做隔离的部署在修复前不应将 GM 校验路径作为唯一防线

### Fixed/Added — M11/M12:票据携带传输参数,0-RTT 全链路补全(DialEarly 真正可用)

- **tls13gm 会话票据 v0x03**:票据明文新增不透明应用数据区(`psk ‖ be32(ageAdd) ‖ appData ‖ be32(len)`),`EncryptSessionTicketWithData`/`DecryptSessionTicketWithData` 新导出变体(旧签名保留为包装);解密循环改为与注释一致的 keep-FIRST(修复 L5:teks 新者在前,首个命中即最新密钥);同轮修复旧"bad version"测试硬编码 0x03 的自指问题
- **M11 客户端参数恢复**:fork `StartHandshake` 按上游契约——0-RTT 密钥与已存服务端参数**同时**具备才发 `EventRestoredTransportParameters`(连接层恢复流控限额并释放 DialEarly 早返回通道;该事件此前从不发出,DialEarly 实际等到握手完成);缺参数时按 crypto/tls 语义弃置 0-RTT 密钥(降级 1-RTT)
- **M12 服务端 ValidFor0RTT 准入门**:票据内保存的传输参数不满足当前参数的 `ValidFor0RTT`(如服务端缩限后)或票据无参数 → 拒 0-RTT(丢弃早密钥,EE 不回显 early_data),PSK 恢复继续——修复服务端缩限后 0-RTT 触发 FLOW_CONTROL_ERROR 断连
- **票据采集链路扩容**:fork `GMOnClientSessionTicket` 回调与服务端 `GetSessionTicket` 均携带服务端传输参数;quicgm `Conn.SessionTicket()` 返回 4 元组(新增 serverParams,破坏性签名变更),`ClientConfig.ResumptionAppData` 必填校验(EarlyData 缺它直接报错,对齐 crypto/tls"无已存参数不做 0-RTT")
- 回归测试:票据数据往返/TEK 轮换窗口/恢复事件/缺参数降级/参数变更拒 0-RTT(含同票据同参数对照组)

### Fixed/Added — 第三轮安全审查 P1(协议一致性 + GM QUIC 与上游契约对齐)

- **GM ALPN(RFC 9001 §8.1)**:tls13gm 新增 `NextProtos`(ClientConfig/ServerConfig)+ ALPN 扩展编解码与协商——客户端按 crypto/tls 偏好策略(客户端顺序)选择、服务端 EE 回显；三重 fail-closed:双方配置但无交集→服务端中止(no_application_protocol 语义)、客户端提供但服务端未回显→客户端中止、服务端选择未提供协议→客户端中止。quicgm 的 `ServerConfig/ClientConfig.NextProtos` 变为**必填**(Listen/Dial 空列表报错,对齐 `quic/` Route A);fork ConnectionState 暴露 `NegotiatedProtocol`
- **M3 HRR×PSK 三缺陷**(tls13gm):HRR 后清除 CH1 派生的 0-RTT 密钥并撤回 early_data 提议(RFC 8446 §4.2.10,CH2 不再携带 early_data);CH2 binder 现按 §4.2.11.2 覆盖 `message_hash(CH1)‖HRR‖Truncate(CH2)` 前缀(此前必与 Tongsuo/OpenSSL 失配)——回归测试按 RFC 独立重算锁定
- **M10 0-RTT 拒绝照会**:客户端 0-RTT 被拒(EE 无 early_data)或收到 HRR 时,GMCryptoSetup 发出 `EventDiscard0RTTKeys` 并丢弃 0-RTT 密钥——连接层重置 0-RTT 流、应用收到 `Err0RTTRejected`(此前静默 1-RTT 补送,DialEarly 的拒绝语义从未生效;zero_rtt 测试已按真实契约更新)
- **M9 Allow0RTT 接线**:`NewGMCryptoSetupServer` 接收 quic 级 `Allow0RTT` 并 AND 进 tls13gm 的 AllowEarlyData;quicgm Listen 按自身 0-RTT 策略(AntiReplay 必需)设置该开关——GM 连接不再绕过传输级 0-RTT 准入
- **M13 服务端 1-RTT opener 时序**:`Get1RTTOpener` 在服务端消费并验证客户端 Finished 之前返回 ErrKeysNotYetAvailable(早到 1-RTT 包缓冲重放),恢复上游"handshakeComplete ⇒ 对端已认证"不变量
- **L1 顺带修复**:客户端 EE 的 early_data 接受增加 `pskMode` 门(恶意服务器对非 PSK 握手谎报 0-RTT 接受的 visibility lie 面闭合)
- 剩余待办:M11/M12(票据携带传输参数 + EventRestoredTransportParameters/ValidFor0RTT,DialEarly 早返回)、M7(Retry/ChangeConnectionID)、M6(向 gmsm 上游报 IP 名称约束同步)

### Fixed — 第三轮全量安全审查(3 高危 + 2 中危 + fork 密钥更新缺陷)

- **[高] tls13gm 0-RTT 全零 PSK 注入**：PSK 票据解密失败被拒（降级全握手）后，0-RTT 接受块此前仍以 nil PSK 调用 acceptor 并派生 early keys——`DeriveEarlySecret(nil)` 走全零 IKM 公开路径，任何攻击者可用伪造票据 + early_data 扩展自行推导 0-RTT 密钥，注入被服务端解密并投递的"0-RTT 数据"。现要求 binder 验证通过的 PSK（非 nil）才会触发 acceptor 与派生；quicgm 的 acceptor 增加纵深 nil-psk 拒绝（回归测试锁定双路径）
- **[高] 主机名校验静默跳过缺陷族**：`tlcp` 引擎新增 crypto/tls 同款握手守卫——空 ServerName 且未显式 InsecureSkipVerify 时拒绝握手（此前空 DNSName 使 smx509 跳过主机名匹配，"配了根 CA 漏填 ServerName"退化为只验链不验域名，同根 CA 下任意域名证书均被接受）；`tls13gm` 客户端构造器要求 Roots 模式下 ServerName 非空；`https` 的 TLCP 传输从 URL host 回填 ServerName（对齐 net/http 标准路径行为）
- **[高] quic-go fork GM 密钥更新结构性缺陷**：`gmUpdatableAEAD.Open()` 相位失配分支按上游 v0.64.0 结构重写——本端发起更新后对端旧相位迟到包改用 prevRcvKM 解密且不再推进相位（旧逻辑每个迟到包都再 roll 一次，相位永久失步直至断连）；疑似更新包先用 next 密钥试解，RFC 9001 §6.1 "too quickly" 检查移到 AEAD 认证之后（单个损坏包不再确定性拆连接，改为计入完整性上限）。连带修复 `rollKeys` 的 `keyPhase ^= 1` 枚举翻转缺陷：iota 布局 `KeyPhaseUndefined=0/Zero=1/One=2` 下首次更新后相位变 Undefined、wire 相位位恒为 0——**GM 密钥更新自 v0.62 事件枚举适配以来实际从未可用**；新增 `gm_updatable_test.go` 四场景锁定（该文件此前零测试覆盖）
- **[中] https 标准 TLS 服务端 mTLS 门**：`TLSClientAuth` ≥ VerifyClientCertIfGiven 但未配 `ClientCAs` 时报错，不再静默回退系统根（否则任何公共 CA 签发的客户端证书都能通过 mTLS）；对齐 tlcp/tls13 路径已有的 fail-closed 门
- **[中] sshca 有效期上限守卫**：`NewCertificateSigner`/`NewAuthority` 拒绝 `maxDuration <= 0`（零值使 SignCertificate 的上限守卫整体短路，配合 ValidBefore=MaxInt64 可签出约 2262 年证书）
- CI：新增 quic-go fork 模块测试 job（fork 为独立模块，此前被根 `./...` 与全部 lint/安全门禁排除，GM 测试套件仅在本地运行）
- README：安全状态一节明示 Route C（quicgm）当前仅源码形态可用——根 `go.mod` 的 `replace` 不随发布生效，下游 `go get` 会解析到无 GM 补丁的上游 quic-go（fail-closed 编译失败，非静默降级）；fork 独立模块发布待决策
- `tls13.ClientConfig` 补充信任模型文档：RootCAs 为空且未跳过验证时走系统根，系刻意保留的 crypto/tls 语义（quic 包装依赖之）；不引入 https 式严格门

### Changed — 依赖第二轮刷新 + quic-go v0.64.0

- vendored quic-go fork：subtree 升级到上游 **v0.64.0**（跨 v0.63/v0.64 两个 minor，174 文件）。合并基线自上次修复后表现正确——仅 `config.go` 一处真实冲突（上游删除 `initialPacketSize` 归一化块、回退逻辑移至连接层；保留 fork 的 `cfg := / copyGMConfigFields` 包装）。GM 适配一处：`gmUpdatableAEAD.shouldInitiateKeyUpdate` 改读 `keyUpdateInterval.Load()`（上游删除了 `protocol.KeyUpdateInterval` 常量），同时修复既有偏差——`SetKeyUpdateInterval` 此前对 GM 连接不生效。随版新增：`ErrStreamClosed`、`InitialPacketSize=0` 运行时 1280→1200 回退语义
- 依赖：`emmansun/gmsm` v0.44.1→**v0.45.0**（RISC-V/LoongArch 向量加速、smx509 对齐 1.26 stdlib 基线、pkcs7 越界读修复；SM2/ecdh 无 API 变化，GM 核心包 race 全绿复核，枚举守卫继续成立）、`x/crypto` v0.58.0、`x/net` v0.61.0、`x/sys`/`x/sync` 等随升；fork 依赖同步（gmsm v0.45、go 指令对齐 1.26.6）

### Changed — 依赖升级与 Go 1.26 加解密适配（破坏性 API，无向后兼容）

- vendored quic-go fork：subtree 升级到上游 **v0.62.0**（根模块 require 同步 v0.62.0）。适配上游事件枚举拆分：`GMCryptoSetup` 按 0-RTT/Handshake/1-RTT 三级分别发出读密钥事件；服务端 `EventReceived1RTTReadKeys` 推迟到客户端 Finished 验证后（对齐 crypto/tls 语义，避免提前 `Finish` Handshake CRYPTO 流）。上游同版本带来的改进随之生效：`errors.AsType`、流优先级调度（RFC 9218）、`dropEncryptionLevel` 简化、pre-Go1.26 构建标签清理。注意：v0.60→v0.61 曾手工同步导致本次 subtree 合并基线偏旧，17 个 fork 零增量文件的冲突已逐一验证取上游侧，此后合并基线恢复正常（见 quic-go/PATCHES.md）

- 依赖：`emmansun/gmsm` v0.44.0→v0.44.1、`golang.org/x/crypto` v0.54.0→v0.57.0、`stretchr/testify` v1.11.1→v1.12.1（间接 `x/net`/`x/sys` 随升；vendored quic-go fork 不变）
- `tls13gm`：`GenerateCurveSM2KeyPair` **去掉 `io.Reader` 参数**——对齐 Go 1.26 随机数硬化语义（`crypto/ecdh.Curve.GenerateKey` 等已忽略调用方 reader），临时密钥恒取 `crypto/rand`
- `tls13gm`：`CurveSM2ECDHE` 内部从废弃的 `elliptic.Curve.ScalarMult` 手工裸乘迁移到 gmsm `ecdh`（`crypto/ecdh` 的 SM2 等价实现，常数时间点运算）：私钥标量校验 [1, N-1]、对端点在曲线校验、无穷远点拒绝、输出定长 32 字节；行为等价（KAT/互通测试不变）
- `tls13gm`：`DeriveEarlySecret` 返回 `([]byte, error)`（随 `sm3.HKDFExtract` 签名变化级联）
- `sm3`：HKDF 构造从 `golang.org/x/crypto/hkdf` 迁移到标准库 `crypto/hkdf`（Go 1.25+）；`HKDFExtract` 返回 `([]byte, error)`。`GODEBUG=fips140=only` 下按标准库语义 fail-closed（拒绝在 FIPS-only 进程内做 SM3 派生）
- `kdf`：PBKDF2 从 `golang.org/x/crypto/pbkdf2` 迁移到标准库 `crypto/pbkdf2`（Go 1.24+），导出签名不变
- `smx509`：PBES2 解密同迁标准库 `crypto/pbkdf2`；新增攻击者可控 PBKDF2 迭代次数上界（10,000,000，对齐 `kdf` 包 `maxIteration` 的 CPU 耗尽防护，此前仅有下界）
- 已核验（Go 1.27.1 实测）：smx509 枚举守卫共享前缀仍然准确（SignatureAlgorithm≤16 / PublicKeyAlgorithm≤4 / ExtKeyUsage≤13），stdlib ML-DSA 值冲突防护不变

### Changed — Go 1.26 适配收尾（SA1019 门禁实装 + PQ 密钥交换）

- `https`：标准 TLS 路径的 `CurvePreferences` 白名单加入 `X25519MLKEM768`/`SecP256r1MLKEM768`——显式列表会整体替换 stdlib 默认组，旧列表 `[X25519, P256]` 等于悄悄退出 Go 1.24/1.26 起默认开启的抗量子混合密钥交换；经典组保留为协商回落
- `https`：SM2 私钥/证书匹配校验改用 `sm2.Equal`（曲线身份优先 + 参数回落，防跨曲线坐标碰撞），去除废弃的 `ecdsa.PublicKey.X/Y` 直接访问
- 门禁：`.golangci.yml` 中 staticcheck 的 `SA1019`（废弃 API）从全局禁用改为**启用** + 路径级豁免（仅 `sm2/` 原始点运算与测试文件）——Go 1.26 新废弃面（如 ecdsa big.Int 字段）今后在提交时即被拦截，非豁免包引入废弃用法将 fail CI（已用金丝雀验证门禁生效）；CI golangci-lint v2.13.1→v2.13.2

### Changed — 依赖与 CI 全面刷新

- 依赖：`x/net` v0.59.0（根+fork）；fork 开发依赖 `go.uber.org/mock` v0.5.2→v0.6.0、`gcassert`/`x/tools` 随升，fork 对 pollux-go 的 require 对齐已发布版本（本地仍由 replace 覆盖）
- CI：`actions/checkout` v5→v6、`actions/setup-go` v6→v7（已核验 v6 的破坏性变更同时存在于 v5.1 回移版，v7 仅 ESM 内部迁移，输入面不变）
- CI：新增 **govulncheck** 步骤（Go 漏洞库可达性扫描）——本地预跑根+fork 均 0 可达漏洞（唯一模块级通告 GO-2026-5932 为 x/crypto/openpgp 弃用提示，无人导入、无修复版本、不影响门禁）

## [v0.5.0] - 2026-08-22

> 本版本为**破坏性安全加固版本**：对全库进行对抗性 Go 最佳实践审查后，根治全部 High/Medium 缺陷及配套 Low/Info 项。多处公共 API 有破坏性变更（见文末清单）。

### Fixed — 第三轮对抗性审查（5 项 High）

- `https`：HybridListener.Accept 对客户端可触发错误（连上即断/明文字节/握手失败）直接返回，而 `http.Server.Serve` 对非临时 Accept 错误会退出整个服务循环——**单个 TCP 包即可永久杀死 Hybrid 服务器**。根治：重写为惰性连接（对齐 `crypto/tls.Listener` 语义），Accept 零 I/O、永不因客户端行为失败，嗅探+握手推迟到首次 Read/Write，慢速客户端不再占用 accept 循环
- `tlcp`：握手消息 3 字节长度无上限——恶意对端每连接可驻留 ~16MB。对齐 crypto/tls：非证书消息 16KB、Certificate 128KB 硬上限
- `tlcp`：Listener.Accept 同步握手且无 deadline——单个不发数据的连接永久阻塞全部后续连接。改为惰性握手；`DialWithDialer` 的 Timeout 现在也约束握手；新增 `DialContext`
- `tlcp`：客户端 Finished 校验失败泄露期望 verify_data（master_secret 派生材料）——与服务端既有反 oracle 策略对齐
- `sshca`：maxDuration 检查被 uint64 溢出精确绕过（delta=2^55 时乘积≡0），可签出 ~10^12 年有效期 SSH 证书。全 uint64 域比较 + int64 范围守卫

### Fixed — 第三轮对抗性审查（Medium）

- `tlcp`：加密 alert 记录此前按密文解析（CCS 后的 close_notify 被误报为错误而非 `io.EOF`）→ 先解密后解析，close_notify 映射 io.EOF；Read 路径补读锁满足 `net.Conn` 并发契约；Close 的 close_notify 写入有界化（5s deadline，任何传输不再挂起）；CBC 填充校验整体移植 crypto/tls 常量时间算法（定长扫描、统一错误、MAC 时间均衡）；会话恢复从不可达死代码接线为可用功能（`Config.SessionCache` + 导出 API + 24h 过期）；握手失败发送 fatal alert；每条记录校验版本字节；`Close` 清零 halfConn 密钥
- `tls13gm`：客户端在服务端拒绝 PSK 时按 RFC 8446 §7.1 用全零重算 early secret（此前任何票据被拒都导致硬失败）；服务端票据解密失败优雅降级继续完全握手（§4.2.11）；`Zero()` 补 ECDHE 临时私钥清零（PFS 兜底）；pinning 模式（nil Roots + 回调）真正可用；线上中间证书参与链构建；服务端补 phase guard + 双端 Failed 终态（transcript 中途失败拒绝重试）；ECDHE 标量副本/票据明文 PSK/binder 失败路径密钥全部用后清零；扩展列表解析 fail-closed
- `quicgm`：`Listen` 的 ctx 真正传播取消；packet protector 构造时快照密钥（解除与 `Handshaker.Zero()` 的共享别名竞争）；`Conn.Close` 清零复用材料；防重放缓存按到期分桶（`Check` 摊还 O(1)，消除持锁全量扫描延迟尖峰）
- `smx509`：`copyCertFields` 三条静默跳过路径全部可观测（skipped 列表 + `CopyFieldDriftHook`），CRL 签发前断言撤销条目数一致（fail-closed 阻止"空名单 CRL"）；`mapEnumField` 重做 fail-closed 并补 ExtKeyUsage 守卫；OCSP ResponderID 补 ASN.1 Class 校验；`ToSMX509Certificate` 补 stdlib 回退；新增 `IsSM3CertID`（SM3 响应的 IssuerHash 谎报问题的显式判别）
- `crl`：标准 CA 路径 nil key panic（落在无 recover 的后台 goroutine 即崩进程）、`opts==nil` panic、`GetCRLNumber` 截断全部修复；fanout 全部子生成器停止后自动退出（停机泄漏）
- `https`：Transport 补 TLSHandshakeTimeout/IdleConnTimeout/ResponseHeaderTimeout；TLCP 拨号真传播 ctx 取消；客户端 nil Timeout 从无限改为默认 120s；删除服务端无效且误导的 `ServerOptions.InsecureSkipVerify`
- `jwt`：HMAC signer 深拷贝 secret（`Zeroize` 不再清调用方数组）；`NewSM2SM3` 曲线 fail-fast；`IssueWithExpiry` 拒绝 ttl<=0
- `kmc`：CSR 补默认 keyUsage 扩展；`https.DetectMode` 增加证书公钥回落判别（只配证书的客户端不再走错协议）

### Changed（破坏性 API，无向后兼容）

- `tlcp`：`NewLRUSessionCache`（原 `NewTLCPLRUSessionCache`）返回导出 `SessionCache`/`SessionState`；删除 `GetCipherSuites`/`IsAvailable`/`GetStandardSummary`/`Version12`；`GetCipherSuiteName`→`CipherSuiteName`；`ConnectionState` 删 `VerifiedChains`（永不填充的契约谎言）、增 `DidResume`/`NegotiatedProtocol`；`Config` 增 `SessionCache`
- `https`：`HybridListener` 导出（主路径调用者可用调优方法）；`ServerOptions` 删 `InsecureSkipVerify`；客户端 nil Timeout 语义变更
- `smx509`：`SMX509ToStdCertificate(s)`→`ToStdCertificate(s)`；`NewOCSPResponseTemplate` 签名变更；新增 `CopyFieldDriftHook`/`IsSM3CertID`
- `crl`：`CRLCache`→`Cache`、`CRLRecord`→`Record`、`NewMemoryCRLCache`→`NewMemoryCache`；`GetCRLNumber` 返回 `*big.Int`
- `tls`：`GetCipherSuites`→`CipherSuites`
- `tlcp` 行为变更：Listener.Accept 不再内联握手（crypto/tls 语义）

### Added

- CI 新增 golangci-lint 门禁（errcheck/revive/gocritic/errorlint/nilerr 等，v2.13.1）+ 仓库级 `.golangci.yml`（每条豁免附理由）；当前全仓 0 告警
- 新增约 20 个回归测试锁定本全部修复行为

### Removed

- `tlcp`：死代码清理（未用方法/类型/保 import 变量/冗余 Get* 包装）；`randReader` 包级可变全局；冗余 `nolint:staticcheck`（SA1019 已配置层统一豁免）

### Fixed — 第二轮审查剩余项(Low/Info 补完)

- `smx509`:OCSP `RevocationReason` 取值域校验(RFC 5280 §5.3.1:0-6/8-10,7 未分配);无 `NextUpdate` 响应对 `ThisUpdate` 施加 7 天本地 max-age(封住无界重放窗口);内嵌 responder 证书自身有效期校验;`ExtractOCSPRequestNonce` 拒绝尾部垃圾与重复 nonce 扩展;`CurrentTime` SM2 路径限制文档标注
- `sshca`:新增 `NewAuthorityWithRevocation`(吊销谓词接入 `CertChecker.IsRevoked`,验证端点不再仅依赖消费端 sshd 兜底);`SignCertificate` 校验 `req.Type` 与签名器类型一致(此前 user 签名器静默签出 HostCert 语义的 user 证书)
- `crl`:撤销原因码取值域校验(同 RFC 5280 §5.3.1);`Get()` 共享数组文档标注
- `tlcp`:session 缓存键 SNI 规范化(RFC 6066 大小写不敏感,消除缓存碎片)
- `sm2`:导出 `ErrDecryptFailed`(调用方可 `errors.Is` 匹配信封解密失败);空消息/可变全局/`from==to` 别名行为文档标注
- `sm4`:CMAC O(n) 缓冲内存特征文档标注(大输入调用方决策依据)
- `tls13gm`:session ticket 注释与 newest-first 约定对齐

### Fixed — 第二轮安全审查修复（18 项 Medium + 关键 Low，逐模块审查）

**crl**（fail-closed 与健壮性）：
- 空撤销列表（非 nil 空切片）回源存储——此前误传 `[]` 会签发"空名单"权威 CRL，所有已撤销证书在依赖方恢复有效
- 非法/非正数序列号拒绝整轮签发（此前 fail-open 静默跳过 = 漏撤销）
- 显式 CRL number 强制单调且拒绝负数（RFC 5280 §5.2.3）
- `StartAutoUpdate` 非正 interval 返回错误（此前 ticker panic 于子 goroutine 不可 recover，崩溃进程）；接口签名变更为返回 error
- `validity`/`numberSource` 读写纳入锁（数据竞争）；fanout stop 通道构造期创建（stop-before-start 泄漏）+ 刷新循环超时

**sm2**：
- `NewPrivateKeyFromInt` 标量域校验 [1, n-1]——越界 panic（不可信输入 DoS）与负数静默取绝对值均转为错误
- `AdjustCipherOrder` 对 ASN.1 输入显式拒绝（此前静默输出 Plain 编码，契约违背）
- `PlainToASN1` 拒绝压缩点输入（此前静默产出损坏 ASN.1）
- `NewEncrypterOpts(EncodingASN1, OrderC1C2C3)` 显式报错（此前静默忽略 order）

**sshca**：
- `ValidateCertificate` 放行 force-command（`CertChecker.SupportedCriticalOptions` 此前为空，所有带 force-command 的合法证书被误拒，手写白名单成死代码）
- 签发边界应用 critical option 白名单（force-command 非空/source-address 校验/未知拒绝——签发与验证对称）
- `ValidateSourceAddresses` 拒绝空串与非规范 CIDR（此前签出 OpenSSH 拒收的"死证书"）
- `BuildKRL` 预校验 CA wire 格式（非法 KRL 被 OpenSSH 整体拒收，sshd 对 KRL 解析错误拒绝所有密钥）
- host 证书不再写 permit-* 扩展（PROTOCOL.certkeys 规定 host 证书无扩展）；`NewCertificateSigner` 校验 certType

**smx509**：
- OCSP 签名分流：SM2 曲线的 `*ecdsa.PrivateKey` 显式拒绝（此前静默降级为普通 ECDSA-SHA256，违反包内自身约定）
- 新增 `VerifyOCSPResponseNonce`：客户端发出 nonce 后响应缺失/不匹配必须拒绝（RFC 6960 §4.4.1 完整绑定，防剥离重放）
- nonce 最小长度 16 字节（RFC 8954 §2.3，构造与解析双侧）；空 nonce 扩展报错而非空切片

**keycrypt / kmc**：
- PBKDF2 迭代 100k → 600k（对齐仓库 smx509 自定的 MUST 标准；此前库内自相矛盾）
- 密码副本与私钥中间态清零（memsecure 惯例对齐）；RSA <2048 位与 nil curve 构造期拒绝

**tls13gm**：
- 0-RTT age 改为 RFC 8446 §4.2.10 的 mod 2^32 语义（此前显式回绕守卫误拒约 14% ticket 生命末段的诚实客户端 0-RTT；新鲜度策略交还 acceptor）

### Added

- **`smx509`: OCSP 响应级扩展支持**（自 mekbuda 的 vendored fork 上移，消除双端维护）：
  - `CreateOCSPResponseExt`：RFC 6960 §4.4.1 nonce 回显（responseExtensions 标准位置）+
    统一签名分流（SM2 SM2+SM3 / RSA / ECDSA / Ed25519；`x/crypto/ocsp.CreateResponse`
    不支持响应级扩展，其验签表亦无 Ed25519/SM2 条目）
  - `ExtractOCSPRequestNonce` / `ResponseNonce`：请求与响应侧 nonce 提取
  - `OCSPErrorResponse`：responseStatus-only 错误响应
  - 互操作实测：带 nonce 响应可被 `x/crypto` `ParseResponse`、本包 SM2 解析器与
    `openssl ocsp` 解析（Go `encoding/asn1` 宽松忽略尾部元素，无需双位置模式）
- **`kmc` 包**：国密双证模型 KMC 抽象（`Manager` 接口 + `LocalKMC` 占位实现，
  GM/T 0018 SDF 实现方可直接接入；CSR subject 参数化）
- **`crl` 包**：CRL 生成 / 缓存 / fan-out / 解析（接口注入式 `Authority` /
  `CRLCache` / `NumberSource`；SM2 密钥自动 SM2+SM3 签名；RFC 5280 §5.2.3
  CRL number 单调性语义）
- **`keycrypt` 包**：私钥加密落盘（PKCS#8 PBES2 AES-256-GCM + PBKDF2-SHA256，
  与 `smx509.DecryptPEMPrivateKey` 格式闭环、明文一律拒绝）+ RSA/ECDSA/Ed25519/SM2
  密钥生成器族（默认算法选择属应用策略，库不预设）
- **`sshca` 包**：SSH 证书 CA——用户/主机证书签发（maxDuration 强制）、
  `CertChecker` 完整验签、**KRL 生成**（`x/crypto/ssh` 只有解析无生成，Go 生态
  稀缺能力）
- `smx509,sm2`：补全 PKIX 公钥解析与标量私钥构造 API（#21）
- `sm2`：C1C2C3 拼接顺序与 Plain 密文编码支持（#19）

### Fixed

- `smx509`：OCSP `revokedInfo` reason=unspecified(0) 时省略 reason 字段
  （RFC 5280 §5.3.1 SHOULD be absent；新旧构造 API 一致生效，行为变更）
- `sm4`：CMAC 迁移至 `gmsm/cbcmac`，keywrap 状态文档化

### Changed

- `sm3`/`kdf`/`sha`：HKDF / PBKDF2 迁移至 `golang.org/x/crypto` 参考实现
- 四个新包补齐 `doc.go`（英文 godoc 规范，与既有包对齐）；README 能力矩阵与
  根 `doc.go` Sub-packages 清单同步
- `sshca` KRL 默认 comment 中性化（应用名 → `pollux-go SSH KRL`）
- `sm4` 一键封装测试覆盖 47% → 91%

### Removed

- **`http/` deprecation shim（破坏性变更）**：`http`→`https` 重命名的兼容层，
  自 v0.1.1 起在全部已发布版本中提供，迁移窗口远超弃用政策。下游将
  `github.com/iuboy/pollux-go/http` 的 import 迁移到 `github.com/iuboy/pollux-go/https`
  （API 面除包名外完全一致）
- `sha` 包中无消费者的死代码入口

## [v0.4.2] - 2026-07-31

tlcp resume 缓存键修复（SNI 优先绑定），修复 `TestNative_Resume_NativeServer`
在端口不复用场景下的 flaky。详见 tag 注释。

## [v0.4.1] - 2026-07-31

安全审计加固：H1-H3 / M1-M8 / P3 共 15 项（GCM nonce panic DoS、0-RTT
fail-closed、resume 缓存键绑定 SNI、OCSP 时效校验、信封错误脱敏、密钥缓冲区
清零、JWT audience 等）。详见 tag 注释。
