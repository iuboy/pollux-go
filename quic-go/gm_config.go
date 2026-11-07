// gm_config.go holds the fork's GM (RFC 8998) configuration types and the
// field-copy helper used by populateConfig.
//
// The Config struct's three GM fields (GMSM4GCM, GMHandshakeConfig,
// GMOnClientSessionTicket) must live in interface.go next to Config itself —
// Go does not allow splitting a struct's fields across files. But the
// GMHandshakeConfig *type* and the copy logic are self-contained, so they live
// here to keep config.go's populateConfig free of GM-specific lines (one fewer
// upstream file to conflict on upgrade). See quic-go/PATCHES.md.

package quic

import (
	"fmt"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
)

// GMHandshakeConfig carries pollux-go tls13gm handshake configuration for a
// Config with GMSM4GCM enabled. Exactly one of Client or Server should be set,
// matching whether the Config is used for Dial (Client) or Listen (Server).
type GMHandshakeConfig struct {
	Client *tls13gm.ClientConfig
	Server *tls13gm.ServerConfig
}

// copyGMConfigFields copies the fork's GM-specific Config fields from src into
// dst. Called by populateConfig so that the field list inside populateConfig's
// returned &Config{...} literal need not mention the GM fields — keeping
// populateConfig byte-for-byte close to its upstream form.
func copyGMConfigFields(dst, src *Config) {
	dst.GMSM4GCM = src.GMSM4GCM
	dst.GMHandshakeConfig = src.GMHandshakeConfig
	dst.GMOnClientSessionTicket = src.GMOnClientSessionTicket
}

// validateGMConfig 在构造期校验 GM 配置的完整性：GMSM4GCM 为 true 时，
// GMHandshakeConfig 必须非 nil，且对应视角的字段必须非 nil（Listen/服务端
// 场景校验 Server，Dial/客户端场景校验 Client）。不满足即返回错误——配置
// 错误在 Listen/Dial 处 fail-fast，而不是等到首个入站 Initial 在连接构造
// 时才暴露（那曾是第四轮审计的远程 panic 杀进程缺陷）。
//
// GetConfigForClient 每连接回调返回的配置不经过本函数（服务端入站路径只有
// hook 一道防线），gm_hook.go 的 nil 检查兜住该路径。
func validateGMConfig(conf *Config, p protocol.Perspective) error {
	if conf == nil || !conf.GMSM4GCM {
		return nil
	}
	if conf.GMHandshakeConfig == nil {
		return fmt.Errorf("GMSM4GCM enabled but GMHandshakeConfig is nil")
	}
	if p == protocol.PerspectiveServer {
		if conf.GMHandshakeConfig.Server == nil {
			return fmt.Errorf("GMSM4GCM enabled but GMHandshakeConfig.Server is nil (server-side Listen)")
		}
	} else if conf.GMHandshakeConfig.Client == nil {
		return fmt.Errorf("GMSM4GCM enabled but GMHandshakeConfig.Client is nil (client-side Dial)")
	}
	return nil
}
