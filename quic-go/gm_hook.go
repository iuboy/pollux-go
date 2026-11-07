// gm_hook.go 隔离 fork 在 Config.GMSM4GCM 上分叉的全部位置。
//
// 本文件存在的原因：quic-go 上游没有公开的 CryptoSetup 注入点
// （internal/handshake.CryptoSetup 为 internal，且 crypto/tls 的套件枚举对
// RFC 8998 ID 直接 panic），fork 必须在传输层内部分叉。把分叉集中于此使
// fork 触碰的每个上游文件（connection.go/config.go/interface.go）尽量贴近
// 上游原形——connection.go 的两个调用点各自收敛为单次 hook 调用， subtree
// pull 新版本 tag 时被补丁文件极少冲突。See quic-go/PATCHES.md。
//
// 每个 hook 返回 (cryptoSetup, ok, err)：ok 为 false 表示 GMSM4GCM 未启用，
// 调用方回落到上游 crypto/tls 构造器；ok 为 true 表示走 GM 路径，err 非 nil
// 表示 GM 构造失败（GM 配置缺失、非 QUIC v1、ECDHE keygen 失败等），调用方
// 必须让本次连接创建失败。
//
// 设计裁决（第四轮审计 #1）：构造错误不再 panic。此前 panic 发生在
// newConnection 内部——服务端路径位于 server run loop goroutine，攻击者一个
// Initial（或版本协商出非 v1）即可通过远程输入触发进程级崩溃；客户端路径则
// 炸掉整个 Dial。现改为错误沿 newConnection/newClientConnection 的新 error
// 返回值上传：服务端按 GetConfigForClient 失败的既有路径拒连（单连接
// CONNECTION_REFUSED，进程存活），客户端 Dial 直接报错。正常路径下
// validateGMConfig 已在 Listen/Dial 构造期拦截同类配置错误，hook 内的 nil
// 检查是纵深防御——覆盖 GetConfigForClient 每连接回调绕过 validateGMConfig
// 的入口。See quic-go/PATCHES.md。
//

package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// newGMCryptoSetupServerHook builds a GMCryptoSetup for the server side when
// Config.GMSM4GCM is set. Returns (nil, false, nil) when the GM path is
// disabled, leaving the caller to use the upstream crypto/tls-backed
// constructor; a non-nil error means the GM path was selected but construction
// failed, and the caller must fail the connection.
func newGMCryptoSetupServerHook(
	conf *Config,
	clientDestConnID protocol.ConnectionID,
	params *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
) (handshake.CryptoSetup, bool, error) {
	if !conf.GMSM4GCM {
		return nil, false, nil
	}
	// GM Initial keys 由 tls13gm/quic_keys.go 的 quicV1InitialSalt（RFC 9001
	// §5.2 的 QUIC v1 salt）派生——tls13gm 不实现 QUIC v2 的 salt，客户端以
	// 版本协商送来非 v1 的 Initial 时，此处若继续会静默派生出错误密钥。锁死
	// v1：非 v1 返回错误，由调用方拒连（服务端单连接失败，进程存活）。
	if version != protocol.Version1 {
		return nil, true, fmt.Errorf("GM handshake requires QUIC v1 (GM Initial keys are derived from the v1 salt), got %s", version)
	}
	// 纵深防御：validateGMConfig 在 Listen 时校验 s.config，但
	// GetConfigForClient 每连接回调可以换入未经校验的 conf——这里 nil 时返回
	// 错误拒连，绝不 panic、也绝不静默回落到非 GM 的 crypto/tls 路径。
	if conf.GMHandshakeConfig == nil || conf.GMHandshakeConfig.Server == nil {
		return nil, true, fmt.Errorf("GMSM4GCM enabled but GMHandshakeConfig.Server is nil")
	}
	// Route C: RFC 8998 GM handshake driven by pollux-go tls13gm. tlsConf is
	// ignored; the GM server config carries the certificate/key. conf.Allow0RTT
	// is the transport-level early-data admission switch — ANDed into the
	// tls13gm-level AllowEarlyData so 0-RTT cannot be accepted (or echoed in
	// EncryptedExtensions) when the quic.Config forbids it.
	cs, err := handshake.NewGMCryptoSetupServer(clientDestConnID, conf.GMHandshakeConfig.Server, params, logger, version, conf.Allow0RTT)
	if err != nil {
		return nil, true, fmt.Errorf("GM server CryptoSetup init failed: %w", err)
	}
	return cs, true, nil
}

// newGMCryptoSetupClientHook builds a GMCryptoSetup for the client side when
// Config.GMSM4GCM is set. Returns (nil, false, nil) when the GM path is
// disabled, leaving the caller to use the upstream crypto/tls-backed
// constructor; a non-nil error means the GM path was selected but construction
// failed, and the caller must fail the connection.
func newGMCryptoSetupClientHook(
	conf *Config,
	destConnID protocol.ConnectionID,
	params *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
) (handshake.CryptoSetup, bool, error) {
	if !conf.GMSM4GCM {
		return nil, false, nil
	}
	// GM Initial keys 固定用 QUIC v1 salt（见服务端 hook 注释），非 v1 直接报错。
	if version != protocol.Version1 {
		return nil, true, fmt.Errorf("GM handshake requires QUIC v1 (GM Initial keys are derived from the v1 salt), got %s", version)
	}
	if conf.GMHandshakeConfig == nil || conf.GMHandshakeConfig.Client == nil {
		return nil, true, fmt.Errorf("GMSM4GCM enabled but GMHandshakeConfig.Client is nil")
	}
	// Route C: RFC 8998 GM handshake driven by pollux-go tls13gm.
	cs, err := handshake.NewGMCryptoSetupClient(destConnID, conf.GMHandshakeConfig.Client, params, logger, version, conf.GMOnClientSessionTicket)
	if err != nil {
		return nil, true, fmt.Errorf("GM client CryptoSetup init failed: %w", err)
	}
	return cs, true, nil
}
