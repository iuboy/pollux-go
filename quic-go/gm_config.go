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
	"github.com/iuboy/pollux-go/tls13gm"
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
