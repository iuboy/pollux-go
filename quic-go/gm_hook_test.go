// gm_hook_test.go verifies the behavioral contract of the GM CryptoSetup
// hooks: when GMSM4GCM is disabled the hooks return (nil, false, nil) without
// touching any GM code path (so the upstream crypto/tls constructor runs), and
// when GMSM4GCM is enabled but construction fails (GM config missing, non-v1
// QUIC version) the hooks return an ERROR — never a panic, never a silent
// fallback to the non-GM path (第四轮审计 #1/#6: 此前构造错误在服务端 run
// loop 上 panic,一个远程 Initial 即可杀进程).
//
// These tests guard the refactor that moved the GM branches out of
// connection.go into gm_hook.go: the externally observable behavior (fall-
// through vs. error) must not change.

package quic

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestGMCryptoSetupServerHook_Disabled(t *testing.T) {
	// GMSM4GCM false: hook must return (nil, false, nil) without touching GM
	// state, even though GMHandshakeConfig is nil. The caller falls through to
	// the upstream crypto/tls-backed constructor.
	cs, ok, err := newGMCryptoSetupServerHook(
		&Config{GMSM4GCM: false},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.False(t, ok)
	require.Nil(t, cs)
	require.NoError(t, err)
}

func TestGMCryptoSetupClientHook_Disabled(t *testing.T) {
	cs, ok, err := newGMCryptoSetupClientHook(
		&Config{GMSM4GCM: false},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.False(t, ok)
	require.Nil(t, cs)
	require.NoError(t, err)
}

func TestGMCryptoSetupServerHook_MissingConfigError(t *testing.T) {
	// GMSM4GCM true but GMHandshakeConfig.Server nil: the hook returns an
	// error (ok=true) so the caller fails the single connection — no panic,
	// no silent downgrade to the crypto/tls path.
	cs, ok, err := newGMCryptoSetupServerHook(
		&Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.True(t, ok)
	require.Nil(t, cs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "GMHandshakeConfig.Server")
}

func TestGMCryptoSetupServerHook_NilGMHandshakeConfigError(t *testing.T) {
	// GMHandshakeConfig 整体为 nil(此前在此处 nil-deref panic):必须返回错误。
	cs, ok, err := newGMCryptoSetupServerHook(
		&Config{GMSM4GCM: true},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.True(t, ok)
	require.Nil(t, cs)
	require.Error(t, err)
}

func TestGMCryptoSetupClientHook_MissingConfigError(t *testing.T) {
	cs, ok, err := newGMCryptoSetupClientHook(
		&Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.True(t, ok)
	require.Nil(t, cs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "GMHandshakeConfig.Client")
}

func TestGMCryptoSetupClientHook_NilGMHandshakeConfigError(t *testing.T) {
	cs, ok, err := newGMCryptoSetupClientHook(
		&Config{GMSM4GCM: true},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&wire.TransportParameters{},
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.True(t, ok)
	require.Nil(t, cs)
	require.Error(t, err)
}

// TestGMCryptoSetupHooks_NonV1VersionRejected locks 第四轮审计 #6: GM Initial
// keys are derived from the QUIC v1 salt (tls13gm/quic_keys.go 的
// quicV1InitialSalt),非 v1 版本(如版本协商出的 v2)必须报错,而非静默派生
// 错误密钥。
func TestGMCryptoSetupHooks_NonV1VersionRejected(t *testing.T) {
	cfg := &Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}}
	for _, v := range []protocol.Version{protocol.Version2, protocol.Version(0xaabbccdd)} {
		cs, ok, err := newGMCryptoSetupServerHook(
			cfg,
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			&wire.TransportParameters{},
			utils.DefaultLogger,
			v,
		)
		require.True(t, ok)
		require.Nil(t, cs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "QUIC v1")

		cs, ok, err = newGMCryptoSetupClientHook(
			cfg,
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			&wire.TransportParameters{},
			utils.DefaultLogger,
			v,
		)
		require.True(t, ok)
		require.Nil(t, cs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "QUIC v1")
	}
}

func TestValidateGMConfig(t *testing.T) {
	// 非 GM 配置一律通过(nil Config 亦然——populateConfig 之前可能为 nil)。
	require.NoError(t, validateGMConfig(nil, protocol.PerspectiveServer))
	require.NoError(t, validateGMConfig(&Config{}, protocol.PerspectiveClient))

	// GMSM4GCM 开启但 GMHandshakeConfig 整体缺失:两个视角都报错。
	require.Error(t, validateGMConfig(&Config{GMSM4GCM: true}, protocol.PerspectiveServer))
	require.Error(t, validateGMConfig(&Config{GMSM4GCM: true}, protocol.PerspectiveClient))

	// 视角字段按场景校验:Listen 要求 Server,Dial 要求 Client;对侧字段缺失
	// 不阻塞构造(同一 Config 结构体天然只填一侧)。
	serverSide := &Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}}
	require.Error(t, validateGMConfig(serverSide, protocol.PerspectiveServer),
		"GMHandshakeConfig.Server 缺失时 Listen 场景必须报错")

	clientSide := &Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}}
	require.Error(t, validateGMConfig(clientSide, protocol.PerspectiveClient),
		"GMHandshakeConfig.Client 缺失时 Dial 场景必须报错")
}

// TestValidateGMConfig_FailFastAtListenAndDial locks 第四轮审计 #1 的构造期
// fail-fast:GMSM4GCM 开启但对应视角 GM 配置缺失时,Listen/Dial 立即报错,
// 而不是等首个连接构造时才暴露(那曾是远程 panic 杀进程的入口)。
func TestValidateGMConfig_FailFastAtListenAndDial(t *testing.T) {
	tr := &Transport{}
	_, err := tr.Listen(&tls.Config{}, &Config{GMSM4GCM: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GMHandshakeConfig")

	tr2 := &Transport{}
	_, err = tr2.Listen(&tls.Config{}, &Config{GMSM4GCM: true, GMHandshakeConfig: &GMHandshakeConfig{}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GMHandshakeConfig.Server")

	udpConn := newUDPConnLocalhost(t)
	defer udpConn.Close()
	tr3 := &Transport{Conn: udpConn}
	_, err = tr3.Dial(context.Background(), udpConn.LocalAddr(), &tls.Config{}, &Config{GMSM4GCM: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GMHandshakeConfig")
}

// TestServerGMHookConfigErrorRefusesConnection locks 第四轮审计 #1 的服务器
// 场景:GetConfigForClient 每连接回调换入 GMSM4GCM=true 而 GMHandshakeConfig
// 缺失的配置(绕过 Listen 期 validateGMConfig)时,一条 Initial 只导致该单个
// 连接被拒(CONNECTION_REFUSED)——不再 panic 杀死服务进程,服务器 run loop
// 继续处理后续 Initial。
func TestServerGMHookConfigErrorRefusesConnection(t *testing.T) {
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{
		eventRecorder: &eventRecorder,
		// newTestServer 默认把 newConn 置 nil;本测试要走真实连接构造路径。
		newConn: newConnection,
		config: &Config{
			GetConfigForClient: func(*ClientInfo) (*Config, error) {
				// 绕过 Listen 期 validateGMConfig 的入口:GM 被开启但配置不完整。
				return &Config{GMSM4GCM: true}, nil
			},
		},
	})
	// newTestServer 的零值 statelessResetter 没有 HMAC key,真实连接构造会
	// 在 GetStatelessResetToken 上 nil-deref;换成带 key 的真实 resetter。
	server.statelessResetter = newStatelessResetter(nil)

	conn := newUDPConnLocalhost(t)
	srcConnID := randConnID(6)
	destConnID := randConnID(8)
	// 第一条 Initial:GM hook 返回错误,连接被拒——绝不 panic。
	server.handlePacket(getValidInitialPacket(t, conn.LocalAddr(), srcConnID, destConnID))
	checkConnectionClose(t, conn, &eventRecorder, destConnID, srcConnID, qerr.ConnectionRefused)

	// 第二条 Initial:服务器 run loop 仍然存活并继续拒绝(而非进程消亡)。
	srcConnID2 := randConnID(6)
	destConnID2 := randConnID(8)
	server.handlePacket(getValidInitialPacket(t, conn.LocalAddr(), srcConnID2, destConnID2))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(b)
	require.NoError(t, err)
	parsedHdr, _, _, err := wire.ParsePacket(b[:n])
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, parsedHdr.Type)
	// 服务器回应的 CONNECTION_CLOSE:DestConnectionID = 客户端的 srcConnID
	// (与 checkConnectionClose 的既有约定一致)。
	require.Equal(t, srcConnID2, parsedHdr.DestConnectionID)
	require.Len(t, eventRecorder.Events(qlog.PacketSent{}), 2)
	for _, ev := range eventRecorder.Events(qlog.PacketSent{}) {
		sent, ok := ev.(qlog.PacketSent)
		require.True(t, ok)
		require.Len(t, sent.Frames, 1)
		_, isCC := sent.Frames[0].Frame.(*qlog.ConnectionCloseFrame)
		require.True(t, isCC, "every rejected Initial must be answered with a CONNECTION_CLOSE")
	}
}
