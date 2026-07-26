// gm_hook.go isolates every site where the fork branches on Config.GMSM4GCM.
//
// Why this file exists: quic-go upstream has no public CryptoSetup injection
// point (internal/handshake.CryptoSetup is internal, and crypto/tls's cipher
// suite enum panics on RFC 8998 IDs), so the fork must branch inside the
// transport. Centralizing the branches here means every upstream file that the
// fork touches (connection.go, config.go, interface.go) stays as close to its
// upstream form as possible — connection.go's two call sites collapse to a
// single hook call each, so a `git subtree pull` of a new quic-go tag rarely
// conflicts on the patched files. See quic-go/PATCHES.md.
//
// Each hook returns (cryptoSetup, ok): ok is false when GMSM4GCM is disabled,
// in which case the caller falls through to the upstream crypto/tls-backed
// constructor unchanged. When ok is true, the returned CryptoSetup is already
// built and the caller must use it. Construction errors (missing GM config,
// ECDHE keygen failure) are caller bugs and panic here, mirroring how a
// malformed *tls.Config surfaces upstream.

package quic

import (
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// newGMCryptoSetupServerHook builds a GMCryptoSetup for the server side when
// Config.GMSM4GCM is set. Returns (nil, false) when the GM path is disabled,
// leaving the caller to use the upstream crypto/tls-backed constructor.
func newGMCryptoSetupServerHook(
	conf *Config,
	clientDestConnID protocol.ConnectionID,
	params *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
) (handshake.CryptoSetup, bool) {
	if !conf.GMSM4GCM {
		return nil, false
	}
	// Route C: RFC 8998 GM handshake driven by pollux-go tls13gm. tlsConf is
	// ignored; the GM server config carries the certificate/key.
	cs, err := handshake.NewGMCryptoSetupServer(clientDestConnID, conf.GMHandshakeConfig.Server, params, logger, version)
	if err != nil {
		// Configuration errors (missing GM server config / ECDHE keygen) are
		// caller bugs; surface them loudly like a bad *tls.Config would.
		panic("quic-go: GM server CryptoSetup init failed: " + err.Error())
	}
	return cs, true
}

// newGMCryptoSetupClientHook builds a GMCryptoSetup for the client side when
// Config.GMSM4GCM is set. Returns (nil, false) when the GM path is disabled,
// leaving the caller to use the upstream crypto/tls-backed constructor.
func newGMCryptoSetupClientHook(
	conf *Config,
	destConnID protocol.ConnectionID,
	params *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
) (handshake.CryptoSetup, bool) {
	if !conf.GMSM4GCM {
		return nil, false
	}
	// Route C: RFC 8998 GM handshake driven by pollux-go tls13gm.
	cs, err := handshake.NewGMCryptoSetupClient(destConnID, conf.GMHandshakeConfig.Client, params, logger, version, conf.GMOnClientSessionTicket)
	if err != nil {
		panic("quic-go: GM client CryptoSetup init failed: " + err.Error())
	}
	return cs, true
}
