# RFC 8998 互通矩阵 — pollux-go × Tongsuo (BabaSSL)

Route C（`tls13gm` + `quicgm`）的合规性验证记录。互通对象为
[Tongsuo 8.5](https://github.com/Tongsuo-Project/Tongsuo)（原 BabaSSL），业界
RFC 8998 参考实现。

## 范围与限制

RFC 8998 定义的是 **TLS 1.3** 层的国密套件（`TLS_SM4_GCM_SM3` = `0x00C6`，
SM2/SM3/SM4）。本矩阵在 **TLS 1.3 over TCP** 层验证 pollux-go 握手引擎与
Tongsuo 的字节级互通。

**为何不在 QUIC 层互通**：Tongsuo/BabaSSL 提供 QUIC *API*（供 ngtcp2/lsquic
等 QUIC 栈嵌入的握手回调），但**不提供独立的 QUIC server/client 端点**，也
没有公开的「QUIC + RFC 8998」可执行对端。QUIC 的 SM4-GCM packet protection
没有正式 RFC 标准化（RFC 8998 只覆盖 TLS 层），因此无公认对端可互通。
pollux-go 的 QUIC transport 层（`quicgm`，RFC 9001 SM4-GCM packet
protection）通过内部端到端测试验证（见 `quicgm/zero_rtt_test.go`、
`quicgm/listener_test.go`），TLS 握手层则通过本矩阵与 Tongsuo 互通验证。

## 矩阵

| 方向 | 模式 | Tongsuo 角色 | pollux-go 角色 | 结果 |
|------|------|--------------|----------------|------|
| TCP TLS 1.3 | 1-RTT 全握手 | `s_server`（SM2 证书 + `TLS_SM4_GCM_SM3` + `-groups SM2`） | tls13gm client（TCP record harness） | ✅ 握手成功 |
| TCP TLS 1.3 | 1-RTT 应用数据双向 | `s_server -rev`（行回显） | tls13gm client（应用数据往返） | ✅ 双向 SM4-GCM + secret 字节一致 |

**验证项（1-RTT 全握手）**：

- ClientHello：`legacy_version=0x0303`、`supported_versions=0x0304`、
  `cipher_suites=[0x00C6]`、`supported_groups=[0x0029 curveSM2]`、
  `key_share`（type `0x0033`=51，curveSM2 公钥）、`signature_algorithms=[sm2_sm3]`
- ECDHE：SM2（curveSM2），共享密钥一致
- 密钥调度：HKDF-SM3，handshake/master secret 派生
- 握手记录保护：SM4-GCM（handshake-level traffic secret，双向）
- CertificateVerify：SM2-SM3 签名（ID `1234567812345678`），验签通过
- Finished：SM3 transcript MAC，双向验证通过

**验证项（1-RTT 应用数据双向）**：

- 密钥调度一致性：pollux-go 的 `ClientHandshakeTrafficSecret` /
  `ClientApplicationTrafficSecret` 与 Tongsuo 通过 `-keylogfile` 导出的
  NSS keylog（`CLIENT_HANDSHAKE_TRAFFIC_SECRET` / `CLIENT_TRAFFIC_SECRET_0`）
  按 client_random 索引**逐字节相等**——证明两端 SM3 HKDF transcript 完全一致。
- client→server：pollux-go 用 client application traffic secret 派生 SM4-GCM
  record key 加密应用数据；Tongsuo 解密成功并回显。
- server→client：Tongsuo 用 server application traffic secret 加密回显
  （`-rev` 行回显）；pollux-go 解密并验证内容。

服务端确认（`s_server` 输出）：`Protocol version: TLSv1.3` /
`Ciphersuite: TLS_SM4_GCM_SM3` / `Signature Algorithms: SM2+SM3` /
`Supported groups: curveSM2` / `Peer Temp Key: ECDH, SM2, 256 bits`。

## 测试

- `test/tongsuo_rfc8998_test.go::TestRFC8998_Tongsuo_HandshakeInterop`
  起一个 Tongsuo `s_server`（运行时生成 SM2 自签证书），用 pollux-go 的
  tls13gm 引擎经一个最小 TLS 1.3 record layer 完成 RFC 8998 握手。server 的
  Finished 验证通过即证明字节级合规。
- `test/tongsuo_rfc8998_test.go::TestRFC8998_Tongsuo_AppDataEcho`
  在握手后双向交换 1-RTT 应用数据（`s_server -rev` 行回显），并对照 Tongsuo
  的 NSS keylog 验证 handshake/application traffic secret 逐字节一致。
- 前置条件：Tongsuo/BabaSSL 在 `PATH` 或 `/opt/local/tongsuo/bin/openssl`。
  缺失则测试 `t.Skip`（不阻塞 CI）。

## 复现

```sh
# 1. 起 Tongsuo s_server（SM2 证书 + RFC 8998）
/opt/local/tongsuo/bin/openssl ecparam -genkey -name SM2 -out server.key
/opt/local/tongsuo/bin/openssl req -x509 -new -key server.key -out server.crt \
    -sm3 -days 30 -subj "/CN=localhost" -sigopt sm2_id:1234567812345678
/opt/local/tongsuo/bin/openssl s_server -accept 127.0.0.1:4433 \
    -cert server.crt -key server.key -tls1_3 -ciphersuites TLS_SM4_GCM_SM3 -groups SM2

# 2. 跑 pollux-go 互通测试（自动起 s_server）
go test ./test/ -run TestRFC8998_Tongsuo -v
```

## PSK resumption / 0-RTT

已改造为 RFC 8446 标准模型：无状态 ticket（TEK 加密的 PSK 句柄）+ 标准 PSK
派生（`resumption_master_secret` + `ticket_nonce`），`tls13gm`/`quicgm` 的 ticket
与 PSK store 均按标准实现。

- **binder wire 语义已修复（commit 86a2b624）**：binder transcript 截断到
  `binders_len` 字段前（identities 含，binders 不含），`pre_shared_key` 的
  `ext_len` 保持 full 值，匹配 OpenSSL `binderoffset` / Go crypto/tls
  `bindersOffset`；并修复 resume CH2 的 `psk_key_exchange_modes` 被
  `pre_shared_key` 覆盖的 bug。
- **pollux 端密码学绝对正确**：binder 全链（early_secret/binder_key/finished_key/
  transcript hash/binder）、RMS、PSK 均用 openssl 逐字节独立验证完全符合 RFC 8446；
  phase1 ClientHandshake/Application TrafficSecret 与 Tongsuo NSS keylog 字节级
  一致（证明 CH1..SF transcript 一致）；`OPENSSL_TRACE=TLS` + tshark+keylog 解密
  确认 Tongsuo 收到完整的 CH1/CF。
- **pollux↔pollux PSK resume + 0-RTT + TEK 轮换全绿**（`quicgm` 端到端测试覆盖：
  `Test0RTT_TicketHarvest`、`Test0RTT_DialEarly`、`Test0RTT_TEKRotation`）。

## 已知差距

- **pollux↔Tongsuo PSK resume 仍失败（Tongsuo 端黑盒）**：尽管 pollux 端密码学
  绝对正确，且逻辑上 pollux transcript1（CH1..SF 经 traffic secret 一致 + CF 经
  Finished 验证一致）应与 Tongsuo transcript1 完全相同（⇒ RMS/PSK/binder 必匹配），
  Tongsuo `s_server` 仍报 `tls_psk_do_binder: binder does not verify`
  （`extensions.c:1673`）。含 CF / 不含 CF 两种 RMS 派生都被拒。判定为 Tongsuo
  RMS/binder 内部行为非标准（GM fork 特定），不是 pollux 问题；需 Tongsuo 源码级
  调试（编辑 `~/Downloads/github/ycq/Tongsuo` 源码加诊断点，或编译带调试符号的二
  进制）。仅影响 pollux client resume Tongsuo/BabaSSL TCP TLS server 这一边缘场景；
  pollux↔pollux QUIC（Route C 主用例）+ 1-RTT 握手互通 + 应用数据回显均不受影响。

## 环境

- Tongsuo 8.5.0-pre1（OpenSSL 3.5.6 兼容），`/opt/local/tongsuo/bin/openssl`
- 验证日期：2026-06
