// gm_updatable.go is the 1-RTT AEAD with QUIC key update support (RFC 9001 §6).
// It replaces the P0 gmShortSealer/gmShortOpener (fixed key phase) for 1-RTT
// packets and implements both ShortHeaderSealer and ShortHeaderOpener. Key
// rotation is driven by tls13gm.QUICKeyUpdate; the send/rcv AEADs and header
// protectors are rebuilt each phase from the derived QUIC packet keys.

package handshake

import (
	"fmt"
	"time"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
)

// gmFirstKeyUpdateInterval mirrors quic-go's FirstKeyUpdateInterval: the packet
// count after which the first key update is initiated (exercises the mechanism).
const gmFirstKeyUpdateInterval uint64 = 100

// gmApproximatePTO substitutes the PTO estimate used by upstream's
// startKeyDropTimer (3 × rttStats.PTO). The GM AEAD has no rttStats injection;
// 1s is a conservative upper bound on real-path PTOs, so the previous-phase
// keys are retained at least as long as RFC 9001 §6.1 requires while still
// bounding their lifetime (previously: retained forever).
const gmApproximatePTO = time.Second

// gmAEADInvalidPacketLimit is the AEAD integrity limit for SM4-GCM
// (128-bit authentication tag): the maximum number of packets that may fail
// authentication before the connection is closed, denying a limitless
// decryption oracle (RFC 9001 §6.6).
const gmAEADInvalidPacketLimit uint64 = 1 << 36

// gmUpdatableAEAD is the 1-RTT AEAD with key update. It implements
// ShortHeaderSealer and ShortHeaderOpener. One instance serves as both the
// sealer and opener for a connection's 1-RTT level.
type gmUpdatableAEAD struct {
	sendKM, rcvKM *gmKeyMaterial // current phase send / receive
	prevRcvKM     *gmKeyMaterial // previous phase receive (for packet-number echo)
	// nextRcvKM 是下一 key phase 的接收密钥材料，随构造与每次 rollKeys 预
	// 构建（对齐上游预构建模型，第四轮审计 #5）：key phase 不符的包直接用
	// 它试开，失败零额外派生——旧实现 nextRcvKeyMaterial 每个试开包都重新
	// 走 DeriveQUICPacketKeys + newGMKeyMaterial，攻击者注入的垃圾包即可
	// 无限放大 HKDF + SM4 调度初始化的 CPU。常驻（而非试开后即擦）：真实
	// key update 到来时同一份材料原地转正，仅换代时擦旧。
	nextRcvKM *gmKeyMaterial
	// prevRcvKMExpiry is the monotime deadline after which prevRcvKM is
	// dropped (RFC 9001 §6.1: retain previous-phase keys ~3×PTO, no longer).
	// Zero while no drop is pending.
	prevRcvKMExpiry monotime.Time

	nextSendSecret []byte // seeds the next send keys via QUICKeyUpdate
	nextRcvSecret  []byte

	keyPhase protocol.KeyPhaseBit

	largestAcked       protocol.PacketNumber
	firstSent          protocol.PacketNumber
	firstRcvd          protocol.PacketNumber
	highestRcvdPN      protocol.PacketNumber
	numSent            uint64
	numRcvd            uint64
	invalidPacketCount uint64
	invalidPacketLimit uint64

	handshakeConfirmed bool
}

var (
	_ ShortHeaderSealer = &gmUpdatableAEAD{}
	_ ShortHeaderOpener = &gmUpdatableAEAD{}
)

// newGMUpdatableAEAD builds the 1-RTT AEAD from the initial send/rcv QUIC
// packet keys and their traffic secrets (the secrets roll forward via
// QUICKeyUpdate to produce later phases). 下一 phase 的接收密钥材料在此预构建
// （见 nextRcvKM 字段注释），构造失败即报错（fail-fast）。
func newGMUpdatableAEAD(sendKeys, rcvKeys *tls13gm.QUICPacketKeys, sendSecret, rcvSecret []byte) (*gmUpdatableAEAD, error) {
	sendKM, err := newGMKeyMaterial(sendKeys)
	if err != nil {
		return nil, err
	}
	rcvKM, err := newGMKeyMaterial(rcvKeys)
	if err != nil {
		return nil, err
	}
	nextSend, err := tls13gm.QUICKeyUpdate(sendSecret)
	if err != nil {
		return nil, err
	}
	nextRcv, err := tls13gm.QUICKeyUpdate(rcvSecret)
	if err != nil {
		tls13gm.ZeroBytes(nextSend)
		return nil, err
	}
	nextRcvKM, err := newGMKeyMaterialFromSecret(nextRcv)
	if err != nil {
		tls13gm.ZeroBytes(nextSend)
		tls13gm.ZeroBytes(nextRcv)
		return nil, err
	}
	return &gmUpdatableAEAD{
		sendKM:             sendKM,
		rcvKM:              rcvKM,
		nextRcvKM:          nextRcvKM,
		nextSendSecret:     nextSend,
		nextRcvSecret:      nextRcv,
		keyPhase:           protocol.KeyPhaseZero,
		firstSent:          protocol.InvalidPacketNumber,
		firstRcvd:          protocol.InvalidPacketNumber,
		largestAcked:       protocol.InvalidPacketNumber,
		highestRcvdPN:      protocol.InvalidPacketNumber,
		invalidPacketLimit: gmAEADInvalidPacketLimit,
	}, nil
}

// newGMKeyMaterialFromSecret 从一个 traffic secret 派生 QUIC packet keys 并
// 构建密钥材料；派生结构体在构建完成后立即 Zero（密钥字节已由 AEAD/cipher
// 构造器拷贝），不留明文副本在堆上。
func newGMKeyMaterialFromSecret(secret []byte) (*gmKeyMaterial, error) {
	keys, err := tls13gm.DeriveQUICPacketKeys(secret)
	if err != nil {
		return nil, err
	}
	km, err := newGMKeyMaterial(keys)
	if err != nil {
		keys.Zero()
		return nil, err
	}
	keys.Zero()
	return km, nil
}

// rollKeys advances to the next key phase: the current receive keys become the
// previous (for packet-number echo), the prebuilt next receive keys become
// current, and the next generation is prebuilt again.
//
// 提交原子化：所有新阶段材料先派生进局部变量，全部成功后才一次性替换字段
// （旧实现逐字段就地提交，中途失败会留下半滚动状态——sendKM 已换代而
// keyPhase 未翻转等）。send 侧密钥材料仍在换代点派生（每 phase 一次，无
// 每包放大）；rcv 侧直接转正预构建的 nextRcvKM。
func (u *gmUpdatableAEAD) rollKeys() error {
	nextSendKeys, err := tls13gm.DeriveQUICPacketKeys(u.nextSendSecret)
	if err != nil {
		return err
	}
	sendKM, err := newGMKeyMaterial(nextSendKeys)
	if err != nil {
		nextSendKeys.Zero()
		return err
	}
	nextSendKeys.Zero()
	newSendSecret, err := tls13gm.QUICKeyUpdate(u.nextSendSecret)
	if err != nil {
		return err
	}
	newRcvSecret, err := tls13gm.QUICKeyUpdate(u.nextRcvSecret)
	if err != nil {
		tls13gm.ZeroBytes(newSendSecret)
		return err
	}
	newNextRcvKM, err := newGMKeyMaterialFromSecret(newRcvSecret)
	if err != nil {
		tls13gm.ZeroBytes(newSendSecret)
		tls13gm.ZeroBytes(newRcvSecret)
		return err
	}
	// —— 全部材料就绪，一次性提交 ——
	u.prevRcvKM = u.rcvKM
	u.sendKM = sendKM
	u.rcvKM = u.nextRcvKM // 预构建材料原地转正，无新派生
	u.nextRcvKM = newNextRcvKM
	// 擦除旧 traffic secret 再替换(它们是传输层持有的唯一长期明文密钥
	// 副本——tls13gm 的 Zero() 刻意把 transport 拥有的秘密留给传输层)。
	tls13gm.ZeroBytes(u.nextSendSecret)
	tls13gm.ZeroBytes(u.nextRcvSecret)
	u.nextSendSecret = newSendSecret
	u.nextRcvSecret = newRcvSecret

	// Toggle the phase bit. The wire mapping is KeyPhaseZero(1)↔bit 0 and
	// KeyPhaseOne(2)↔bit 1 (see wire.ParseShortHeader / AppendShortHeader), so
	// the toggle MUST map the two enum values onto each other — the previous
	// `keyPhase ^= 1` turned KeyPhaseZero(1) into KeyPhaseUndefined(0), and
	// AppendShortHeader then emitted bit 0 (="no update") for every post-update
	// packet, permanently breaking GM key updates.
	if u.keyPhase == protocol.KeyPhaseZero {
		u.keyPhase = protocol.KeyPhaseOne
	} else {
		u.keyPhase = protocol.KeyPhaseZero
	}
	u.firstSent = protocol.InvalidPacketNumber
	u.firstRcvd = protocol.InvalidPacketNumber
	u.numSent = 0
	u.numRcvd = 0
	return nil
}

func (u *gmUpdatableAEAD) updateAllowed() bool {
	if !u.handshakeConfirmed {
		return false
	}
	return u.keyPhase == protocol.KeyPhaseZero ||
		(u.firstSent != protocol.InvalidPacketNumber &&
			u.largestAcked != protocol.InvalidPacketNumber &&
			u.largestAcked >= u.firstSent)
}

func (u *gmUpdatableAEAD) shouldInitiateKeyUpdate() bool {
	if !u.updateAllowed() {
		return false
	}
	if u.keyPhase == protocol.KeyPhaseZero {
		if u.numRcvd >= gmFirstKeyUpdateInterval || u.numSent >= gmFirstKeyUpdateInterval {
			return true
		}
	}
	// Read the configurable interval (SetKeyUpdateInterval), matching the
	// upstream updatableAEAD — GM connections honor the same knob instead of
	// the removed protocol.KeyUpdateInterval constant.
	return u.numRcvd >= keyUpdateInterval.Load() || u.numSent >= keyUpdateInterval.Load()
}

// --- ShortHeaderSealer ---

func (u *gmUpdatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	ct, err := u.sendKM.aead.Seal(uint64(pn), src, ad)
	if err != nil {
		panic(fmt.Sprintf("handshake: GM 1-RTT Seal failed for packet %d: %v", pn, err))
	}
	u.numSent++
	if u.firstSent == protocol.InvalidPacketNumber {
		u.firstSent = pn
	}
	return append(dst, ct...)
}

func (u *gmUpdatableAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(u.sendKM.hp, false, sample, firstByte, pnBytes)
}

func (u *gmUpdatableAEAD) Overhead() int { return u.sendKM.aead.Overhead() }

// KeyPhase returns the current send key phase, initiating a key update if the
// packet counts cross the threshold (RFC 9001 §6).
func (u *gmUpdatableAEAD) KeyPhase() protocol.KeyPhaseBit {
	if u.shouldInitiateKeyUpdate() {
		if err := u.rollKeys(); err != nil {
			// rollKeys fails only on an invariant violation (OOM / HKDF bug).
			// The ShortHeaderSealer.KeyPhase interface has no error return
			// (mirroring upstream updatable_aead.go), so we fail closed here
			// rather than continue with stale keys past the AEAD nonce budget.
			panic(fmt.Sprintf("handshake: GM key update failed: %v", err))
		}
	}
	return u.keyPhase
}

// --- ShortHeaderOpener ---

func (u *gmUpdatableAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	applyGMHeaderMask(u.rcvKM.hp, false, sample, firstByte, pnBytes)
}

func (u *gmUpdatableAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, u.highestRcvdPN, wirePN)
}

func (u *gmUpdatableAEAD) Open(dst, src []byte, rcvTime monotime.Time, pn protocol.PacketNumber, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	// Key-drop deadline (RFC 9001 §6.1): previous-phase keys are retained for
	// a bounded window only. Upstream mirrors this with prevRcvAEADExpiry.
	if u.prevRcvKM != nil && u.prevRcvKMExpiry != 0 && rcvTime.After(u.prevRcvKMExpiry) {
		u.prevRcvKM = nil
		u.prevRcvKMExpiry = 0
	}
	if kp != u.keyPhase {
		// The packet claims a key phase we are not on. Two legitimate causes:
		// the peer initiated a key update, or the packet is a late one from
		// the previous phase (we initiated the update and the peer has not
		// switched yet). Distinguish by packet number against the first packet
		// received in the current phase (upstream updatable_aead.go): a packet
		// numbered below it cannot belong to the new phase.
		if u.keyPhase != protocol.KeyPhaseZero && (u.firstRcvd == protocol.InvalidPacketNumber || pn < u.firstRcvd) {
			// We updated the keys, but the peer hasn't updated yet: a late
			// packet from the previous phase (RFC 9001 §6.1 packet-number echo).
			if u.prevRcvKM == nil {
				return nil, ErrKeysDropped
			}
			pt, err := u.prevRcvKM.aead.Open(uint64(pn), src, ad)
			if err != nil {
				return nil, u.decryptionFailed()
			}
			return append(dst, pt...), nil
		}
		// Trial-open with the NEXT key phase before committing to the update:
		// a corrupted or injected packet whose header happens to decode to the
		// other phase bit must fail AEAD here (and count toward the integrity
		// limit) instead of advancing the key phase or tearing down the
		// connection. 使用预构建的 nextRcvKM（第四轮审计 #5）：失败路径零额外
		// 派生、零临时材料——材料常驻，真实换代到来时原地转正（换代时擦旧，
		// 见 rollKeys）。nextRcvKM 在构造后不可能为 nil；nil 只可能是内部
		// 不变量被破坏，按密钥不可用失败关闭。
		if u.nextRcvKM == nil {
			return nil, ErrKeysDropped
		}
		pt, err := u.nextRcvKM.aead.Open(uint64(pn), src, ad)
		if err != nil {
			return nil, u.decryptionFailed()
		}
		// Opening succeeded — the peer really did update. Enforce RFC 9001
		// §6.1 only now that the packet is authentic: the peer must hold proof
		// that we can use the current phase (an ACK of a packet we sent under
		// it) before updating again.
		if u.keyPhase != protocol.KeyPhaseZero && u.firstSent == protocol.InvalidPacketNumber {
			return nil, &qerr.TransportError{ErrorCode: qerr.KeyUpdateError, ErrorMessage: "keys updated too quickly"}
		}
		if err := u.rollKeys(); err != nil {
			return nil, err
		}
		// rollKeys reset the per-phase bookkeeping; this packet is the first
		// one received under the new phase (upstream sets
		// firstRcvdWithCurrentKey here).
		u.firstRcvd = pn
		if pn > u.highestRcvdPN {
			u.highestRcvdPN = pn
		}
		// The peer initiated this update: it is safe to schedule dropping the
		// previous generation's keys now (upstream startKeyDropTimer).
		u.startKeyDropTimer(rcvTime)
		return append(dst, pt...), nil
	}
	pt, err := u.rcvKM.aead.Open(uint64(pn), src, ad)
	if err != nil && u.prevRcvKM != nil {
		// Packet-number echo: the phase bit decoded as the current phase (e.g.
		// the header protection sample garbled the bit across the phase
		// switch) but the packet was protected with the previous phase keys.
		if pt2, err2 := u.prevRcvKM.aead.Open(uint64(pn), src, ad); err2 == nil {
			pt, err = pt2, nil
		}
	}
	if err != nil {
		return nil, u.decryptionFailed()
	}
	u.numRcvd++
	if u.firstRcvd == protocol.InvalidPacketNumber {
		// We initiated the key update and this is the first packet protected
		// with the new phase: the peer has rolled its keys too — schedule
		// dropping the previous generation's keys.
		if u.keyPhase != protocol.KeyPhaseZero {
			u.startKeyDropTimer(rcvTime)
		}
		u.firstRcvd = pn
	}
	if pn > u.highestRcvdPN {
		u.highestRcvdPN = pn
	}
	return append(dst, pt...), nil
}

// startKeyDropTimer schedules dropping the previous-phase receive keys
// (RFC 9001 §6.1: 3×PTO after the update is proven). See gmApproximatePTO for
// the PTO substitution.
func (u *gmUpdatableAEAD) startKeyDropTimer(now monotime.Time) {
	u.prevRcvKMExpiry = now.Add(3 * gmApproximatePTO)
}

// decryptionFailed records an AEAD authentication failure. RFC 9001 §6.6:
// once too many packets fail authentication the connection is closed, denying
// an attacker a limitless decryption oracle.
func (u *gmUpdatableAEAD) decryptionFailed() error {
	u.invalidPacketCount++
	if u.invalidPacketCount >= u.invalidPacketLimit {
		return &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
	}
	return ErrDecryptionFailed
}

// --- key-update control ---

// SetLargestAcked records the largest acknowledged 1-RTT packet number (governs
// when a locally-initiated key update is allowed) and detects a peer that ACKed
// our new key phase without having updated its own keys.
func (u *gmUpdatableAEAD) SetLargestAcked(pn protocol.PacketNumber) error {
	if u.firstSent != protocol.InvalidPacketNumber && pn >= u.firstSent && u.numRcvd == 0 {
		return fmt.Errorf("quic-go: received ACK for key phase %d but peer didn't update keys", u.keyPhase)
	}
	u.largestAcked = pn
	return nil
}

// SetHandshakeConfirmed enables key updates (the first update is allowed once
// the handshake is confirmed).
func (u *gmUpdatableAEAD) SetHandshakeConfirmed() {
	u.handshakeConfirmed = true
}

// Zero wipes the rolling traffic secrets and releases all key-material
// pointers. Called from GMCryptoSetup.Close. Note the SM4 key schedules held
// inside each tls13gm.AEAD are NOT reachable from here (upstream-parity
// limitation: gmsm cipher state is unexported); the raw secrets — the only
// material that rolls forward into future phases — are what gets wiped.
func (u *gmUpdatableAEAD) Zero() {
	tls13gm.ZeroBytes(u.nextSendSecret)
	tls13gm.ZeroBytes(u.nextRcvSecret)
	u.nextSendSecret, u.nextRcvSecret = nil, nil
	u.sendKM, u.rcvKM, u.prevRcvKM, u.nextRcvKM = nil, nil, nil, nil
	u.prevRcvKMExpiry = 0
}
