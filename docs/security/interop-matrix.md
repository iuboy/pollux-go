# RFC 8998 互通矩阵 — pollux-go × Tongsuo (BabaSSL)

Route C（`tls13gm` + `quicgm`）的合规性验证记录。互通对象为
[Tongsuo 8.5](https://github.com/Tongsuo-Project/Tongsuo)（原 BabaSSL），业界 RFC 8998 参考实现。

## 范围

RFC 8998 定义 TLS 1.3 层国密套件（`TLS_SM4_GCM_SM3` = `0x00C6`，SM2/SM3/SM4）。本矩阵在 **TLS 1.3 over TCP** 层验证 pollux-go 握手引擎与 Tongsuo 的字节级互通。

QUIC 层不在互通范围：Tongsuo/BabaSSL 不提供独立的「QUIC + RFC 8998」可执行对端（QUIC SM4-GCM packet protection 也无正式 RFC 标准化）。pollux-go 的 QUIC transport 层（`quicgm`）通过内部端到端测试验证（`quicgm/zero_rtt_test.go`、`quicgm/listener_test.go`）。

## 矩阵

| 方向 | 模式 | Tongsuo 角色 | pollux-go 角色 | 结果 |
|------|------|--------------|----------------|------|
| TCP TLS 1.3 | 1-RTT 全握手 | `s_server`（SM2 证书 + `TLS_SM4_GCM_SM3` + `-groups SM2`） | tls13gm client（TCP record harness） | ✅ 握手成功 |
| TCP TLS 1.3 | 1-RTT 应用数据双向 | `s_server -rev`（行回显） | tls13gm client（应用数据往返） | ✅ 双向 SM4-GCM + secret 字节一致 |

验证覆盖：ClientHello（`cipher_suites=[0x00C6]`、`supported_groups=[curveSM2]`、`signature_algorithms=[sm2_sm3]`）、ECDHE（curveSM2 共享密钥一致）、HKDF-SM3 密钥调度、SM4-GCM 握手记录保护、CertificateVerify（SM2-SM3 验签）、Finished（SM3 transcript MAC 双向验证）。

**应用数据密钥一致性**：pollux-go 的 `ClientHandshakeTrafficSecret` / `ClientApplicationTrafficSecret` 与 Tongsuo 通过 `-keylogfile` 导出的 NSS keylog 按 client_random 索引**逐字节相等**，证明两端 SM3 HKDF transcript 完全一致。

服务端确认（`s_server` 输出）：`Protocol version: TLSv1.3` / `Ciphersuite: TLS_SM4_GCM_SM3` / `Signature Algorithms: SM2+SM3` / `Supported groups: curveSM2` / `Peer Temp Key: ECDH, SM2, 256 bits`。

## 测试

- `test/tongsuo_rfc8998_test.go::TestRFC8998_Tongsuo_HandshakeInterop` — 起 Tongsuo `s_server`，用 tls13gm 引擎完成 RFC 8998 握手，Finished 验证通过即证明字节级合规。
- `TestRFC8998_Tongsuo_AppDataEcho` — 握手后双向交换 1-RTT 应用数据，对照 NSS keylog 验证 traffic secret 一致。
- 前置条件：Tongsuo/BabaSSL 在 `PATH` 或 `/opt/local/tongsuo/bin/openssl`，缺失则 `t.Skip`。

## 复现

```sh
# 1. 起 Tongsuo s_server（SM2 证书 + RFC 8998）
/opt/local/tongsuo/bin/openssl ecparam -genkey -name SM2 -out server.key
/opt/local/tongsuo/bin/openssl req -x509 -new -key server.key -out server.crt \
    -sm3 -days 30 -subj "/CN=localhost" -sigopt sm2_id:1234567812345678
/opt/local/tongsuo/bin/openssl s_server -accept 127.0.0.1:4433 \
    -cert server.crt -key server.key -tls1_3 -ciphersuites TLS_SM4_GCM_SM3 -groups SM2

# 2. 跑互通测试（自动起 s_server）
go test ./test/ -run TestRFC8998_Tongsuo -v
```

## PSK resumption / 0-RTT（已与 Tongsuo 互通）

采用标准 stateless-ticket 模型（无状态 ticket + PSK 派生 `resumption_master_secret` + `ticket_nonce`）。

两个互通适配点：

- **binder wire 语义**：binder transcript 截断到 `binders_len` 字段前（identities 含、binders 不含），`pre_shared_key` 的 `ext_len` 保持 full 值，匹配 OpenSSL `binderoffset` / Go crypto/tls `bindersOffset`。
- **resumption PSK label**：BabaSSL/Tongsuo 用非标准 `"resumption"` label（非 RFC 8446 §7.1 的 `"res psk"`）派生 resumption PSK。pollux 适配 `"resumption"` 以互通；pollux↔pollux 两端同 label 仍一致。

验证：`TestRFC8998_Tongsuo_PSKResume`、`TestRFC8998_Tongsuo_0RTT`（含 early_data + `client_early_traffic_secret` 加密）均 PASS；pollux↔pollux PSK resume + 0-RTT + TEK 轮换全绿（`Test0RTT_TicketHarvest`、`Test0RTT_DialEarly`、`Test0RTT_TEKRotation`）。

## 环境

- Tongsuo 8.5.0-pre1（OpenSSL 3.5.6 兼容）
- 验证日期：2026-06
