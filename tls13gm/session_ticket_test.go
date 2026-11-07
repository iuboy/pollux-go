package tls13gm

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/sm3"
)

// testTicketLifetime 是测试票据的有效期(1 小时)。EncryptSessionTicket 自
// 第四轮审计 P3 起要求显式有效期:0 会生成立即过期的票据,解密一律 decline。
const testTicketLifetime uint32 = 3600

func TestSessionTicket_RoundTrip(t *testing.T) {
	tek := bytes.Repeat([]byte{0xAB}, SessionTicketKeyLen)
	psk := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	ticket, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}
	if ticket[0] != sessionTicketVersion {
		t.Fatalf("ticket version = %d, want %d", ticket[0], sessionTicketVersion)
	}
	if len(ticket) <= 1+12 {
		t.Fatalf("ticket too short: %d", len(ticket))
	}
	// Two encryptions of the same PSK must differ (fresh nonce).
	ticket2, _ := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if bytes.Equal(ticket, ticket2) {
		t.Fatal("two ticket encryptions are identical (nonce reuse?)")
	}

	got, _, err := DecryptSessionTicket([][]byte{tek}, ticket)
	if err != nil {
		t.Fatalf("DecryptSessionTicket: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Fatalf("decrypted PSK mismatch: got %x want %x", got, psk)
	}
}

func TestSessionTicket_RotationPreviousKey(t *testing.T) {
	// A ticket encrypted under the "previous" key must still decrypt when the
	// caller supplies [current, previous] (rotation window).
	old := bytes.Repeat([]byte{0x11}, SessionTicketKeyLen)
	cur := bytes.Repeat([]byte{0x22}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xCD}, 32)

	ticket, err := EncryptSessionTicket(old, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// After rotation, the caller passes [current, previous]; the old key is
	// still tried and must recover the PSK.
	got, _, err := DecryptSessionTicket([][]byte{cur, old}, ticket)
	if err != nil {
		t.Fatalf("decrypt under [cur, prev]: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Fatalf("PSK mismatch after rotation: %x", got)
	}
}

func TestSessionTicket_RejectsUnknownKey(t *testing.T) {
	tek := bytes.Repeat([]byte{0x33}, SessionTicketKeyLen)
	wrong := bytes.Repeat([]byte{0x44}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0xEE}, 32)

	ticket, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, _, err := DecryptSessionTicket([][]byte{wrong}, ticket); err == nil {
		t.Fatal("decrypted with wrong key (expected failure)")
	}
}

func TestSessionTicket_RejectsBadVersion(t *testing.T) {
	tek := bytes.Repeat([]byte{0x55}, SessionTicketKeyLen)
	ticket, _ := EncryptSessionTicket(tek, bytes.Repeat([]byte{0x01}, 32), 0, testTicketLifetime)
	// 0x7F has never been a valid version (0x02/0x03 are the retired/current
	// ones — corrupting to the CURRENT version would be a no-op).
	ticket[0] = 0x7F
	if _, _, err := DecryptSessionTicket([][]byte{tek}, ticket); err == nil {
		t.Fatal("decrypted ticket with bad version")
	}
}

func TestSessionTicket_RejectsBadKeyLength(t *testing.T) {
	if _, err := EncryptSessionTicket([]byte{1, 2, 3}, bytes.Repeat([]byte{0x01}, 32), 0, testTicketLifetime); err == nil {
		t.Fatal("EncryptSessionTicket accepted short key")
	}
}

// TestSessionTicket_MatchAtAnyPosition is the regression guard for the
// constant-time-traversal change in DecryptSessionTicket: the function must
// never short-circuit on the first successful key. Before the change it
// returned early on the first matching key, leaking via timing which depth into
// the rotation list matched; after the change every key is always tried.
//
// We assert the behavioral consequence: a ticket whose TEK sits at the LAST
// position of the candidate list decrypts correctly (proving the loop reaches
// the end), and one whose TEK sits at the FIRST position also decrypts
// correctly. Both must recover the exact original PSK.
func TestSessionTicket_MatchAtAnyPosition(t *testing.T) {
	match := bytes.Repeat([]byte{0x77}, SessionTicketKeyLen)
	wrong1 := bytes.Repeat([]byte{0x12}, SessionTicketKeyLen)
	wrong2 := bytes.Repeat([]byte{0x34}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x9A}, 32)

	ticket, err := EncryptSessionTicket(match, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Match at the end of a 3-key list: the loop must traverse wrong1, wrong2,
	// then succeed on match. A short-circuit-after-first-success bug would
	// leave result unset and return errTicketUndecryptable.
	got, _, err := DecryptSessionTicket([][]byte{wrong1, wrong2, match}, ticket)
	if err != nil {
		t.Fatalf("match-at-end should decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("match-at-end PSK mismatch: %x", got)
	}

	// Match at the front: still correct (records last success = the only one).
	got, _, err = DecryptSessionTicket([][]byte{match, wrong1, wrong2}, ticket)
	if err != nil {
		t.Fatalf("match-at-front should decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("match-at-front PSK mismatch: %x", got)
	}
}

// TestSessionTicket_MultiMatchTakesLast confirms the documented selection
// semantics: when more than one candidate key decrypts (e.g. duplicate TEKs in
// the list), the LAST successful result is returned. This pins the behavior the
// constant-time traversal relies on — it records rather than returns.
func TestSessionTicket_MultiMatchDuplicateKeys(t *testing.T) {
	k := bytes.Repeat([]byte{0x55}, SessionTicketKeyLen)
	ticket, err := EncryptSessionTicket(k, bytes.Repeat([]byte{0x01}, 32), 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Same key three times — every Open succeeds identically, and the
	// keep-FIRST policy (teks newest-first; see DecryptSessionTicketWithData)
	// yields the same PSK. AEAD guarantees distinct keys never both decrypt,
	// so duplicates are the only multi-match case.
	got, _, err := DecryptSessionTicket([][]byte{k, k, k}, ticket)
	if err != nil {
		t.Fatalf("multi-match should decrypt: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty PSK from multi-match decrypt")
	}
}

// TestSessionTicket_MalformedKeysInListSkipped confirms that malformed (wrong
// length) entries in the TEK list are skipped without aborting the traversal,
// so a later valid key still recovers the PSK. This guards the len(tek) !=
// SessionTicketKeyLen continue branch in the constant-time loop.
func TestSessionTicket_MalformedKeysInListSkipped(t *testing.T) {
	good := bytes.Repeat([]byte{0x88}, SessionTicketKeyLen)
	short := []byte{0x01, 0x02} // wrong length, must be skipped
	psk := bytes.Repeat([]byte{0xEE}, 32)
	ticket, err := EncryptSessionTicket(good, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, _, err := DecryptSessionTicket([][]byte{short, good, short}, ticket)
	if err != nil {
		t.Fatalf("should skip malformed keys and decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("PSK mismatch with malformed keys in list: %x", got)
	}
}

// withTicketTimeNow 覆写 ticketTimeNow 测试缝并注册恢复;返回的闭包把当前
// 时刻平移 offset 秒,供过期/未过期票据的确定性构造。
func withTicketTimeNow(t *testing.T, offset time.Duration) {
	t.Helper()
	base := time.Now()
	ticketTimeNow = func() time.Time { return base.Add(offset) }
	t.Cleanup(func() { ticketTimeNow = time.Now })
}

// TestSessionTicket_ExpiredDeclined 是第四轮审计 P3 的回归守卫:票据明文
// 自带签发时刻与有效期,超出有效期(含 60 秒时钟偏差容忍窗)的票据在解密
// 侧被 decline。错误以 errTicketExpired 报告,且仍满足
// errors.Is(err, errTicketUndecryptable),保证既有按"不可解密"匹配的 decline
// 调用方(verifyPSKBinder)行为不变。
func TestSessionTicket_ExpiredDeclined(t *testing.T) {
	tek := bytes.Repeat([]byte{0x66}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x77}, 32)

	// 签发发生在"2 小时前",有效期 1 小时 → 已过期。
	withTicketTimeNow(t, -2*time.Hour)
	ticket, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// 校验发生在"现在"(seam 恢复后的真实时钟)。
	ticketTimeNow = time.Now
	got, _, err := DecryptSessionTicket([][]byte{tek}, ticket)
	if got != nil {
		t.Errorf("expired ticket returned a PSK: %x", got)
	}
	if !errors.Is(err, errTicketExpired) {
		t.Errorf("err = %v, want errTicketExpired", err)
	}
	if !errors.Is(err, errTicketUndecryptable) {
		t.Errorf("errTicketExpired must wrap errTicketUndecryptable, got %v", err)
	}
}

// TestSessionTicket_ZeroLifetimeDeclined 确认 lifetime=0(签发即过期)的
// 票据在任何时刻都不可用。
func TestSessionTicket_ZeroLifetimeDeclined(t *testing.T) {
	tek := bytes.Repeat([]byte{0x6B}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x7C}, 32)
	withTicketTimeNow(t, 0)
	ticket, err := EncryptSessionTicket(tek, psk, 0, 0)
	if err != nil {
		t.Fatalf("encrypt with lifetime 0: %v", err)
	}
	if _, _, err := DecryptSessionTicket([][]byte{tek}, ticket); !errors.Is(err, errTicketExpired) {
		t.Errorf("zero-lifetime ticket err = %v, want errTicketExpired", err)
	}
}

// TestSessionTicket_FutureIssuanceDeclined 确认签发时刻超前超出偏差容忍窗的
// 票据被拒(伪造或严重时钟漂移)。
func TestSessionTicket_FutureIssuanceDeclined(t *testing.T) {
	tek := bytes.Repeat([]byte{0x6D}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x7E}, 32)
	// 签发于"6 小时后",校验于现在 → 超前 6 小时,远超 60 秒容忍窗。
	withTicketTimeNow(t, 6*time.Hour)
	ticket, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ticketTimeNow = time.Now
	if _, _, err := DecryptSessionTicket([][]byte{tek}, ticket); !errors.Is(err, errTicketExpired) {
		t.Errorf("future-issued ticket err = %v, want errTicketExpired", err)
	}
}

// TestSessionTicket_SkewToleranceAccepted 确认容忍窗内的边缘时钟偏差不误拒:
// 签发于"30 秒后"(在 ±60 秒容忍窗内)的票据可以正常解密。
func TestSessionTicket_SkewToleranceAccepted(t *testing.T) {
	tek := bytes.Repeat([]byte{0x6F}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x70}, 32)
	withTicketTimeNow(t, 30*time.Second)
	ticket, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ticketTimeNow = time.Now
	got, _, err := DecryptSessionTicket([][]byte{tek}, ticket)
	if err != nil {
		t.Fatalf("ticket within skew tolerance should decrypt: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Errorf("PSK mismatch: %x", got)
	}
}

// TestSessionTicket_RejectsLegacyLayoutVersion 确认旧布局票据(v0x03 及更早)
// 在版本字节即被拒——新明文布局(含签发时刻/有效期)与旧布局不兼容,旧票据
// 确定性地解密失败并回落完整握手,而不是落入明文错位解析。
func TestSessionTicket_RejectsLegacyLayoutVersion(t *testing.T) {
	tek := bytes.Repeat([]byte{0x71}, SessionTicketKeyLen)
	ticket, err := EncryptSessionTicket(tek, bytes.Repeat([]byte{0x01}, 32), 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// 0x03 是上一代布局(PSK+age+appData,无有效期);篡改回旧版本字节必须
	// 被版本校验拒绝。
	ticket[0] = 0x03
	_, _, err = DecryptSessionTicket([][]byte{tek}, ticket)
	if err == nil {
		t.Fatal("legacy-layout ticket decrypted (version bump regression)")
	}
	if !errors.Is(err, errTicketVersion) {
		t.Errorf("err = %v, want errTicketVersion", err)
	}
}

// TestSessionTicket_RejectsOversizedLifetime 确认 EncryptSessionTicketWithData
// 拒绝超出 RFC 8446 §4.6.1 上限(604800 秒)的有效期。
func TestSessionTicket_RejectsOversizedLifetime(t *testing.T) {
	tek := bytes.Repeat([]byte{0x73}, SessionTicketKeyLen)
	psk := bytes.Repeat([]byte{0x74}, 32)
	if _, err := EncryptSessionTicket(tek, psk, 0, 604801); err == nil {
		t.Fatal("EncryptSessionTicket accepted lifetime 604801 (> RFC 8446 §4.6.1 maximum)")
	}
	if _, err := EncryptSessionTicket(tek, psk, 0, 604800); err != nil {
		t.Fatalf("EncryptSessionTicket rejected the legal 604800 ceiling: %v", err)
	}
}

// TestHandshake_ExpiredTicketDeclinesResumption 是第四轮审计 P3 的握手级
// 回归守卫:过期票据在 verifyPSKBinder 里必须按 RFC 8446 §4.2.11 decline
// (回落完整握手),而不是中止握手,更不是照常选中 PSK。decline 的可观察
// 后果:HandleClientHello 成功返回,resumptionSelectedPSK 为 nil,
// ServerFlight 携带 Certificate/CertificateVerify(PSK 模式下两者省略)。
func TestHandshake_ExpiredTicketDeclinesResumption(t *testing.T) {
	dcid := []byte{0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8}
	cert, serverKey := generateTestSM2Cert(t)
	psk := bytes.Repeat([]byte{0xEE}, sm3.Size)
	tek := bytes.Repeat([]byte{0x4A}, SessionTicketKeyLen)

	// 票据签发于"2 小时前",有效期 1 小时 → 服务端校验时已过期。
	withTicketTimeNow(t, -2*time.Hour)
	identity, err := EncryptSessionTicket(tek, psk, 0, testTicketLifetime)
	if err != nil {
		t.Fatalf("EncryptSessionTicket: %v", err)
	}
	ticketTimeNow = time.Now

	client, err := NewClientHandshakerWithConfig(ClientConfig{
		DCID:                          dcid,
		InsecureSkipVerify:            true,
		ResumptionPSK:                 psk,
		ResumptionIdentity:            identity,
		ResumptionObfuscatedTicketAge: 1,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ch, err := client.ClientHello()
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	server, err := NewServerHandshakerWithConfig(ServerConfig{
		DCID:              dcid,
		Certificate:       cert,
		PrivateKey:        serverKey,
		SessionTicketKeys: func() [][]byte { return [][]byte{tek} },
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	// decline:过期票据不得让握手失败。
	if err := server.HandleClientHello(ch); err != nil {
		t.Fatalf("HandleClientHello with expired ticket must decline (not abort): %v", err)
	}
	if server.resumptionSelectedPSK != nil {
		t.Fatal("expired ticket still selected a PSK (expiry validation missing)")
	}
	sh, ee, certMsg, cv, fin, err := server.ServerFlight()
	if err != nil {
		t.Fatalf("ServerFlight after declined expired ticket: %v", err)
	}
	if certMsg == nil || cv == nil || sh == nil || ee == nil || fin == nil {
		t.Fatal("declined PSK flight must be a full handshake (Certificate/CertificateVerify present)")
	}
}
