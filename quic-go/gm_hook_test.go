// gm_hook_test.go verifies the behavioral contract of the GM CryptoSetup
// hooks: when GMSM4GCM is disabled the hooks return (nil, false) without
// touching any GM code path (so the upstream crypto/tls constructor runs), and
// when GMSM4GCM is enabled but the required GM config is missing the hooks
// panic — matching how a malformed *tls.Config surfaces upstream.
//
// These tests guard the refactor that moved the GM branches out of
// connection.go into gm_hook.go: the externally observable behavior (fall-
// through vs. panic) must not change.

package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestGMCryptoSetupServerHook_Disabled(t *testing.T) {
	// GMSM4GCM false: hook must return (nil, false) and not panic, even though
	// GMHandshakeConfig is nil. The caller falls through to the upstream
	// crypto/tls-backed constructor.
	cs, ok := newGMCryptoSetupServerHook(
		&Config{GMSM4GCM: false},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.False(t, ok)
	require.Nil(t, cs)
}

func TestGMCryptoSetupClientHook_Disabled(t *testing.T) {
	cs, ok := newGMCryptoSetupClientHook(
		&Config{GMSM4GCM: false},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.False(t, ok)
	require.Nil(t, cs)
}

func TestGMCryptoSetupServerHook_MissingConfigPanics(t *testing.T) {
	// GMSM4GCM true but GMHandshakeConfig.Server nil: a caller bug. The hook
	// must panic loudly (mirroring a bad *tls.Config), not return a silent error.
	require.Panics(t, func() {
		_, _ = newGMCryptoSetupServerHook(
			&Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}},
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			&wire.TransportParameters{},
			utils.DefaultLogger,
			protocol.Version1,
		)
	})
}

func TestGMCryptoSetupClientHook_MissingConfigPanics(t *testing.T) {
	require.Panics(t, func() {
		_, _ = newGMCryptoSetupClientHook(
			&Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}},
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			&wire.TransportParameters{},
			utils.DefaultLogger,
			protocol.Version1,
		)
	})
}
