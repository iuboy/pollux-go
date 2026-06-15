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

## 已知差距

- **PSK resumption / 0-RTT 互通**：Tongsuo `s_server` 的会话票据跨进程持久化
  较难编排，未纳入 TCP 矩阵；pollux-go 内部端到端测试（`Test0RTT_DialEarly`、
  `Test0RTT_TicketHarvest`）已验证 PSK 恢复 + 0-RTT + 防重放。

## 环境

- Tongsuo 8.5.0-pre1（OpenSSL 3.5.6 兼容），`/opt/local/tongsuo/bin/openssl`
- 验证日期：2026-06
