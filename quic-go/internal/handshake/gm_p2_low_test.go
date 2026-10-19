package handshake

// 第三轮审查 P2 低危批(fork 侧)回归测试:
//   - B1  0-RTT opener/sealer 缓存(此前每包重建,highestRcvdPN 归零)
//   - B2  prevRcvKM 到期丢弃(RFC 9001 §6.1 3×PTO)
//   - B4/B5 关闭时擦除滚动 traffic secret 与已采集 PSK
//   - B6  Initial/Handshake/0-RTT opener 的 AEAD 完整性上限

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
)

// gmAccepted0RTTServerPair 构造一对完成 ClientHello 交换的 client/server,
// 服务端接受了 0-RTT(双方 EarlyKeys 均可用)。
func gmAccepted0RTTServerPair(t *testing.T) (client, server *GMCryptoSetup) {
	t.Helper()
	cert, serverKey := gmTestServerCert(t)
	tek := bytes16(0xE1)
	psk := bytes32(0xE2)
	params := gmRestoreServerParams(t)
	savedRaw := params.Marshal(protocol.PerspectiveServer)
	identity, err := tls13gm.EncryptSessionTicketWithData(tek, psk, 0, savedRaw)
	if err != nil {
		t.Fatalf("EncryptSessionTicketWithData: %v", err)
	}

	clientCfg := &tls13gm.ClientConfig{
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
		ResumptionAppData:             savedRaw,
	}
	client = gmRestoreClient(t, params, clientCfg)
	if err := client.StartHandshake(context.Background()); err != nil {
		t.Fatalf("client StartHandshake: %v", err)
	}
	var ch []byte
	for _, ev := range drainGMEvents(client) {
		if ev.Kind == EventWriteInitialData {
			ch = ev.Data
		}
	}

	connID := protocol.ParseConnectionID([]byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78})
	server, err = NewGMCryptoSetupServer(connID, &tls13gm.ServerConfig{
		Certificate:       cert,
		PrivateKey:        serverKey,
		NextProtos:        []string{"echo"},
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
		AllowEarlyData:    true,
		EarlyDataAcceptor: func([]byte, time.Duration) bool { return true },
	}, params, utils.DefaultLogger, protocol.Version1, true)
	if err != nil {
		t.Fatalf("NewGMCryptoSetupServer: %v", err)
	}
	if err := server.HandleMessage(ch, protocol.EncryptionInitial); err != nil {
		t.Fatalf("server HandleMessage(ClientHello): %v", err)
	}
	drainGMEvents(server)
	return client, server
}

// TestGMCryptoSetup_0RTTCodecsCached 锁定 B1:Get0RTTOpener/Sealer 返回缓存
// 实例;opener 的 highestRcvdPN 随包推进,跨 2 字节截断窗口的包号经
// DecodePacketNumber 正确重建(此前每包重建 opener,基线恒为 0)。
func TestGMCryptoSetup_0RTTCodecsCached(t *testing.T) {
	client, server := gmAccepted0RTTServerPair(t)

	opener1, err := server.Get0RTTOpener()
	if err != nil {
		t.Fatalf("Get0RTTOpener: %v", err)
	}
	opener2, err := server.Get0RTTOpener()
	if err != nil {
		t.Fatalf("Get0RTTOpener(2nd): %v", err)
	}
	if opener1 != opener2 {
		t.Fatal("Get0RTTOpener 必须返回缓存实例(每包重建会丢失 highestRcvdPN)")
	}

	sealer1, err := client.Get0RTTSealer()
	if err != nil {
		t.Fatalf("client Get0RTTSealer: %v", err)
	}
	sealer2, err := client.Get0RTTSealer()
	if err != nil {
		t.Fatalf("client Get0RTTSealer(2nd): %v", err)
	}
	if sealer1 != sealer2 {
		t.Fatal("Get0RTTSealer 必须返回缓存实例")
	}

	// 功能验证:QUIC 包号解码只容忍 ±2^15 重排序,缺陷在跨 epoch 边界
	// 显形——先开 pn=1 再开 pn=65535(推进 highestRcvdPN 跨过 2 字节
	// epoch),随后 wire 2 字节 pn=10 应重建为 65546;每包重建的 opener
	// 基线恒为 0,会错误地解出 10。
	ad := []byte("gm-0rtt-ad")
	ct1 := sealer1.Seal(nil, []byte("pn-1"), 1, ad)
	if _, err := opener1.Open(nil, ct1, 1, ad); err != nil {
		t.Fatalf("open pn=1: %v", err)
	}
	ct2 := sealer1.Seal(nil, []byte("pn-65535"), 65535, ad)
	if _, err := opener1.Open(nil, ct2, 65535, ad); err != nil {
		t.Fatalf("open pn=65535: %v", err)
	}
	if got := opener1.DecodePacketNumber(10, protocol.PacketNumberLen2); got != 65546 {
		t.Fatalf("跨 epoch 包号重建 = %d, want 65546(缓存 opener 的 highestRcvdPN 基线失效)", got)
	}
}

// TestGMUpdatable_PrevKeysDroppedAfterExpiry 锁定 B2:本端更新后旧相位密钥
// 仍可解迟到包(回声窗口),到期后(prevRcvKMExpiry 已过)返回
// ErrKeysDropped;对端发起更新成功提交后自动启动丢弃定时器。
func TestGMUpdatable_PrevKeysDroppedAfterExpiry(t *testing.T) {
	receiver, sender := newGMUpdatablePair(t)
	ad := []byte("gm-ku-ad")

	// 本端更新:receiver 先发一包(firstSent 置位允许更新),再 roll。
	receiver.Seal(nil, []byte("phase-0"), 1, ad)
	if err := receiver.rollKeys(); err != nil {
		t.Fatalf("receiver rollKeys: %v", err)
	}
	// sender 仍在相位 0:其包对 receiver 是"旧相位迟到包"。
	ct := sender.Seal(nil, []byte("late"), 10, ad)
	if _, err := openPacket(receiver, ct, 10, protocol.KeyPhaseZero, ad); err != nil {
		t.Fatalf("更新后旧相位迟到包应可解(回声窗口): %v", err)
	}

	// 到期后:prevRcvKM 在 Open 入口即被丢弃。
	receiver.prevRcvKMExpiry = monotime.Now().Add(-time.Millisecond)
	ct2 := sender.Seal(nil, []byte("late-2"), 11, ad)
	_, err := openPacket(receiver, ct2, 11, protocol.KeyPhaseZero, ad)
	if !errors.Is(err, ErrKeysDropped) {
		t.Fatalf("到期后的旧相位包应返回 ErrKeysDropped, got %v", err)
	}

	// 对端发起更新(全新一对,避免上方手动过期丢弃的残留):trial-open
	// 成功提交后,旧相位密钥保留在 prevRcvKM 且丢弃定时器已布。
	rx2, tx2 := newGMUpdatablePair(t)
	if err := tx2.rollKeys(); err != nil {
		t.Fatalf("tx2 rollKeys: %v", err)
	}
	ct3 := tx2.Seal(nil, []byte("phase-1"), 500, ad)
	if _, err := openPacket(rx2, ct3, 500, protocol.KeyPhaseOne, ad); err != nil {
		t.Fatalf("对端发起的更新应被接受: %v", err)
	}
	if rx2.keyPhase != protocol.KeyPhaseOne {
		t.Fatalf("rx2 相位 = %v, want KeyPhaseOne", rx2.keyPhase)
	}
	if rx2.prevRcvKMExpiry == 0 {
		t.Fatal("对端更新提交后应启动旧密钥丢弃定时器")
	}
	if rx2.prevRcvKM == nil {
		t.Fatal("丢弃定时器窗口内 prevRcvKM 仍应保留")
	}
}

// TestGMUpdatable_ZeroWipesSecrets 锁定 B5:Zero 擦除滚动 traffic secret 并
// 释放全部密钥材料指针;GMCryptoSetup.Close 清空已采集 PSK(B4)但不触碰
// 1-RTT AEAD——连接拆除路径要在 Close 之后用它封 CONNECTION_CLOSE。
func TestGMUpdatable_ZeroWipesSecrets(t *testing.T) {
	receiver, _ := newGMUpdatablePair(t)
	receiver.Zero()
	if receiver.nextSendSecret != nil || receiver.nextRcvSecret != nil {
		t.Fatal("Zero 后滚动 traffic secret 必须清空")
	}
	if receiver.sendKM != nil || receiver.rcvKM != nil || receiver.prevRcvKM != nil {
		t.Fatal("Zero 后密钥材料指针必须释放")
	}

	client, _ := gmAccepted0RTTServerPair(t)
	client.oneRTTAEAD = nil // Close 不应触碰 1-RTT AEAD;置 nil 使断言不依赖它
	client.clientSessionPSK = []byte("live-psk-material")
	client.clientSessionIdentity = []byte("identity")
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if client.clientSessionPSK != nil || client.clientSessionIdentity != nil {
		t.Fatal("Close 后已采集的 resumption PSK/identity 必须清空")
	}
	if client.zeroRTTOpener != nil || client.zeroRTTSealer != nil {
		t.Fatal("Close 后 0-RTT 编解码缓存必须释放")
	}
}

// TestGMLongOpener_IntegrityLimit 锁定 B6:长包头 opener(Initial/Handshake/
// 0-RTT)计入 AEAD 认证失败,达到上限返回 AEADLimitReached(此前无界)。
func TestGMLongOpener_IntegrityLimit(t *testing.T) {
	keys, err := tls13gm.DeriveQUICPacketKeys(bytes32(0xE3))
	if err != nil {
		t.Fatalf("DeriveQUICPacketKeys: %v", err)
	}
	opener, err := newGMLongOpener(keys)
	if err != nil {
		t.Fatalf("newGMLongOpener: %v", err)
	}
	garbage := []byte("definitely-not-valid-ciphertext")
	if _, err := opener.Open(nil, garbage, 1, []byte("ad")); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("垃圾密文应返回 ErrDecryptionFailed, got %v", err)
	}
	opener.invalidPacketCount = gmAEADInvalidPacketLimit - 1
	_, err = opener.Open(nil, garbage, 2, []byte("ad"))
	var terr *qerr.TransportError
	if !errors.As(err, &terr) || terr.ErrorCode != qerr.AEADLimitReached {
		t.Fatalf("达到完整性上限应返回 AEADLimitReached, got %v", err)
	}
}
