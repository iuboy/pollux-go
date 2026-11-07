package tlcp

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// 本文件是第四轮审计修复批 A 清单外发现的回归测试（批 A 后续报告）：
//   F1 changeCipherSpec 未显式检查 destroyed（错误文案误导）
//   F2 客户端死会话不清缓存（服务端拒绝 resume 后死会话被持续提议至 24h 过期）
//   F3 VerifyClientCertIfGiven 的 resume 不重验缓存证书（批 A #7 只覆盖强制模式）
//   F4 sessionCacheKey 的 addr 键无命名空间前缀
//   F5 tlcp.Conn nil 接收者无防护（typed-nil-in-interface 陷阱 panic 面）

// --- F1 changeCipherSpec destroyed 错误归因 ---

// TestChangeCipherSpecDestroyedAttribution 锁定：destroy 后到达的 CCS 必须报
// errHalfConnDestroyed 哨兵（错误可归因），而非落入误导性的
// "without prepareCipherSpec"——destroy 清零 staged 字段后两者在修复前无法区
// 分。未 staged 且未 destroy 的既有错误路径保持不变（对照组）。
func TestChangeCipherSpecDestroyedAttribution(t *testing.T) {
	// 对照组：staged 后正常激活。
	hc := &tlcpHalfConn{}
	hc.prepareCipherSpec(make([]byte, 16), nil, hmacSM3Size{}, make([]byte, 32))
	if err := hc.changeCipherSpec(); err != nil {
		t.Fatalf("staged 后 changeCipherSpec 应成功: %v", err)
	}
	// 未 staged 且未 destroy：既有错误路径不受影响（非 destroyed 场景）。
	fresh := &tlcpHalfConn{}
	err := fresh.changeCipherSpec()
	if err == nil || errors.Is(err, errHalfConnDestroyed) {
		t.Fatalf("未 staged 未 destroy 应保持 without prepareCipherSpec 错误，got %v", err)
	}
	// destroy 后：显式 destroyed 哨兵。
	hc.destroy()
	if err := hc.changeCipherSpec(); !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("destroy 后 changeCipherSpec 应报 errHalfConnDestroyed，got %v", err)
	}
}

// --- F2 服务端拒绝 resume 后客户端清缓存 ---

// TestClientDeclinedResumeEvictsCache 端到端锁定：客户端提议了缓存会话 X，
// 但服务端缓存无 X（如服务端重启丢失会话）→ ServerHello 回新 sessionId、
// 客户端按「已提议未 resume」回落全握手。修复后死会话 X 的缓存条目（
// sessionId 键 + sni 键）必须在回落时清除；全握手新会话覆盖 sni 键；第二次
// 连接以新会话正常 resume（清理不得误伤正常 resume 面）。
func TestClientDeclinedResumeEvictsCache(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	signPriv := signCert.PrivateKey.(*polluxSM2.PrivateKey)
	encPriv := encCert.PrivateKey.(*polluxSM2.PrivateKey)
	sharedCache := NewLRUSessionCache(8)

	serverConfig := &tlcpEngineConfig{
		rand:         crand.Reader,
		cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		serverCerts: &tlcpServerCerts{
			signCertDER:  signCert.Certificate[0],
			encCertDER:   encCert.Certificate[0],
			signSigner:   signPriv,
			encDecrypter: encPriv,
		},
		sessionCache: sharedCache,
	}

	// 毒化客户端侧缓存：死会话 X（服务端没有 X 的服务端条目，必然拒绝 resume）。
	x := make([]byte, 32)
	if _, err := crand.Read(x); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dead := &SessionState{
		sessionID:    x,
		version:      tlcpVersionTLCP,
		cipherSuite:  SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret: make([]byte, 32),
		createdAt:    time.Now(),
	}
	sniKey := sessionCacheKey("", "test.example.com")
	sharedCache.Put(sniKey, dead)
	sharedCache.Put(clientSessionKey(x), dead)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{}, 2)
	serve := func() {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
		conn := newTLCPConn(rawConn, serverConfig, false)
		if err := conn.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			t.Errorf("server write: %v", err)
		}
		serverDone <- struct{}{}
	}
	go serve()
	go serve()

	clientConfig := &tlcpEngineConfig{
		rand:               crand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		serverName:         "test.example.com",
		insecureSkipVerify: true,
		sessionCache:       sharedCache,
	}
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	conn1 := newTLCPConn(c1, clientConfig, true)
	if err := conn1.Handshake(); err != nil {
		t.Fatalf("first handshake（应为回落全握手成功）: %v", err)
	}
	if conn1.didResume {
		t.Fatal("服务端无 X 缓存，第一次连接不应 resume")
	}

	// 死会话条目已从缓存清除（修复前残留至 24h 过期）。
	if _, ok := sharedCache.Get(clientSessionKey(x)); ok {
		t.Fatal("服务端拒绝 resume 后，死会话的 sessionId 缓存条目未被清除")
	}
	// sni 键被全握手新会话覆盖（非死会话 X）。
	fresh, ok := sharedCache.Get(sniKey)
	if !ok {
		t.Fatal("全握手新会话未写入 sni 键")
	}
	if bytes.Equal(fresh.sessionID, x) {
		t.Fatal("sni 键仍指向死会话 X")
	}

	msg := []byte("declined resume falls back to full handshake")
	if _, err := conn1.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(conn1, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = conn1.Close()
	<-serverDone

	// 正例控制：第二次连接以新会话 resume——清理只针对死会话。
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	_ = c2.SetDeadline(time.Now().Add(10 * time.Second))
	conn2 := newTLCPConn(c2, clientConfig, true)
	if err := conn2.Handshake(); err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if !conn2.didResume {
		t.Fatal("第二次连接应以全握手新会话 resume")
	}
	// 回发数据让服务端 serve 循环走完（服务端握手后阻塞在 Read）。
	msg2 := []byte("resumed after eviction")
	if _, err := conn2.Write(msg2); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	echo2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(conn2, echo2); err != nil {
		t.Fatalf("read echo 2: %v", err)
	}
	if !bytes.Equal(echo2, msg2) {
		t.Fatal("resume echo mismatch")
	}
	_ = conn2.Close()
	<-serverDone
}

// --- F3 VerifyClientCertIfGiven 的 resume 重验缓存证书 ---

// TestResume_VerifyIfGiven_ResumesWithVerifiedIdentity 正例：可选验链模式下，
// 全握手后第二次连接正常 resume（缓存会话携带的客户端双证重跑链验证通过）。
func TestResume_VerifyIfGiven_ResumesWithVerifiedIdentity(t *testing.T) {
	sharedCache := NewLRUSessionCache(8)
	serverConfig, clientConfig := mtlsResumeConfigs(t, sharedCache, VerifyClientCertIfGiven)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go mtlsServeLoop(t, ln, serverConfig, done)
	defer func() { _ = ln.Close(); <-done }()

	conn1 := mtlsDial(t, ln, clientConfig)
	if err := conn1.Handshake(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if conn1.ConnectionState().DidResume {
		t.Fatal("第一次连接应为全握手")
	}
	mtlsEcho(t, conn1, []byte("verify-if-given full handshake"))
	_ = conn1.Close()

	conn2 := mtlsDial(t, ln, clientConfig)
	if err := conn2.Handshake(); err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if !conn2.ConnectionState().DidResume {
		t.Fatal("VerifyClientCertIfGiven 模式下第二次连接应 resume（缓存身份重验通过）")
	}
	mtlsEcho(t, conn2, []byte("verify-if-given resumed"))
	_ = conn2.Close()
}

// TestResume_VerifyIfGiven_RogueCachedSessionFallsBackToFullHandshake 负例：
// 可选验链模式下服务端缓存条目被替换为不受信 CA 签发的客户端双证。修复前
// resume 门只覆盖 RequireAndVerifyClientCert，VerifyClientCertIfGiven 直接以
// 伪造会话 resume（rogue 身份无从拦截）；修复后重验失败 → 放弃 resume 走全
// 握手（不报错中断），连接照常可用、didResume=false。
func TestResume_VerifyIfGiven_RogueCachedSessionFallsBackToFullHandshake(t *testing.T) {
	sharedCache := NewLRUSessionCache(8)
	serverConfig, clientConfig := mtlsResumeConfigs(t, sharedCache, VerifyClientCertIfGiven)

	rogueCA, rogueKey := generateSM2CA(t, "rogue-vig-ca")
	rogueSign, rogueEnc := generateClientCertPair(t, rogueCA, rogueKey)

	x := make([]byte, 32)
	if _, err := crand.Read(x); err != nil {
		t.Fatalf("rand: %v", err)
	}
	serverPoisoned := &SessionState{
		sessionID:        x,
		version:          tlcpVersionTLCP,
		cipherSuite:      SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret:     make([]byte, 32),
		peerCertificates: [][]byte{rogueSign.Certificate[0], rogueEnc.Certificate[0]},
		createdAt:        time.Now(),
	}
	sharedCache.Put(serverSessionKey(x), serverPoisoned)
	// 客户端条目（sni 键）：让客户端在下一次连接提议 X。
	clientOffer := &SessionState{
		sessionID:    x,
		version:      tlcpVersionTLCP,
		cipherSuite:  SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret: make([]byte, 32),
		createdAt:    time.Now(),
	}
	sharedCache.Put(sessionCacheKey("", "test"), clientOffer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go mtlsServeLoop(t, ln, serverConfig, done)
	defer func() { _ = ln.Close(); <-done }()

	conn := mtlsDial(t, ln, clientConfig)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake（应为放弃 resume 后的全握手成功）: %v", err)
	}
	if conn.ConnectionState().DidResume {
		t.Fatal("VerifyClientCertIfGiven 模式下 rogue 缓存条目被 resume（resume 门未覆盖可选验链模式）")
	}
	mtlsEcho(t, conn, []byte("verify-if-given fallback full handshake"))
	_ = conn.Close()
}

// TestLookupResumedSession_VerifyIfGiven_EmptyCertsCached 锁定缓存会话未绑定
// 客户端身份时的两种模式语义：RequireAndVerifyClientCert 不可 resume（身份
// MUST 存在）；VerifyClientCertIfGiven 按原样 resume（全握手时客户端本就未给
// 证书，与「给了就验」语义一致，无可验对象）。
func TestLookupResumedSession_VerifyIfGiven_EmptyCertsCached(t *testing.T) {
	trustedCA, _ := generateSM2CA(t, "empty-certs-ca")
	pool := polluxsmx509.NewCertPool()
	pool.AddCert(stdCertFromSM(t, trustedCA))

	x := make([]byte, 32)
	if _, err := crand.Read(x); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sess := &SessionState{
		sessionID:        x,
		version:          tlcpVersionTLCP,
		cipherSuite:      SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret:     make([]byte, 32),
		peerCertificates: nil, // 未绑定客户端身份
		createdAt:        time.Now(),
	}
	cache := NewLRUSessionCache(8)
	cache.Put(serverSessionKey(x), sess)

	suite := tlcpLookupCipherSuite(SuiteECC_SM2_SM4_GCM_SM3)
	ch := &tlcpClientHelloMsg{version: tlcpVersionTLCP, sessionID: x, cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3}}

	// 强制模式：无身份缓存不可 resume。
	serverConn := newTLCPConn(nil, &tlcpEngineConfig{
		sessionCache: cache,
		clientRoots:  pool,
		clientAuth:   RequireAndVerifyClientCert,
	}, false)
	serverConn.vers = tlcpVersionTLCP
	if got := serverConn.lookupResumedSession(ch, suite); got != nil {
		t.Fatal("RequireAndVerifyClientCert 下无身份缓存条目被 resume")
	}
	// 可选模式：按原样 resume。
	serverConn.config.clientAuth = VerifyClientCertIfGiven
	if got := serverConn.lookupResumedSession(ch, suite); got == nil {
		t.Fatal("VerifyClientCertIfGiven 下无证书缓存条目应按原样 resume（无可验对象）")
	}
}

// --- F4 sessionCacheKey 命名空间前缀 ---

// TestSessionCacheKeyPrefixNamespaces 锁定：addr 键带 "addr:" 前缀、sni 键带
// "sni:" 前缀且规范化小写；三类键（addr/sni/sessionId 角色键）命名空间两两
// 不碰撞——修复前裸地址作键可与 "c:"/"s:" 角色键共享字符串空间（本测试用
// addr 字面 "c:31" 与 clientSessionKey([]byte("1"))="c:31" 的构造性碰撞示范）。
func TestSessionCacheKeyPrefixNamespaces(t *testing.T) {
	if got := sessionCacheKey("127.0.0.1:443", ""); got != "addr:127.0.0.1:443" {
		t.Errorf("addr 键应有 addr: 前缀，got %q", got)
	}
	if got := sessionCacheKey("ignored", "Example.com"); got != "sni:example.com" {
		t.Errorf("sni 键应规范化小写并带 sni: 前缀，got %q", got)
	}
	keys := []string{
		sessionCacheKey("c:31", ""),   // addr 字面碰巧形如角色键
		sessionCacheKey("", "c:31"),   // sni 同理
		clientSessionKey([]byte("1")), // "c:31"
		serverSessionKey([]byte("1")), // "s:31"
	}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if seen[k] {
			t.Errorf("缓存键命名空间碰撞：%q", k)
		}
		seen[k] = true
	}
}

// --- F5 tlcp.Conn nil 接收者守卫 ---

// TestNilConnReceiverGuards 锁定：nil 接收者上的 Close/Read/Write/Handshake/
// HandshakeContext 返回 errNilConn、NegotiatedProtocol 返回空串，一律不
// panic——typed-nil-in-interface 陷阱下 (*Conn)(nil) 存入 net.Conn 接口后接
// 口值非 nil，下游据接口判定调用方法（如 https watchdog 的防御性 Close）会
// 命中 nil 接收者，修复前解引用 c.inner 直接 panic。
func TestNilConnReceiverGuards(t *testing.T) {
	var c *Conn
	if err := c.Close(); !errors.Is(err, errNilConn) {
		t.Errorf("nil 接收者 Close 应报 errNilConn，got %v", err)
	}
	if n, err := c.Read(make([]byte, 8)); n != 0 || !errors.Is(err, errNilConn) {
		t.Errorf("nil 接收者 Read 应返回 (0, errNilConn)，got (%d, %v)", n, err)
	}
	if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, errNilConn) {
		t.Errorf("nil 接收者 Write 应返回 (0, errNilConn)，got (%d, %v)", n, err)
	}
	if err := c.Handshake(); !errors.Is(err, errNilConn) {
		t.Errorf("nil 接收者 Handshake 应报 errNilConn，got %v", err)
	}
	if err := c.HandshakeContext(context.Background()); !errors.Is(err, errNilConn) {
		t.Errorf("nil 接收者 HandshakeContext 应报 errNilConn，got %v", err)
	}
	if got := c.NegotiatedProtocol(); got != "" {
		t.Errorf("nil 接收者 NegotiatedProtocol 应返回空串，got %q", got)
	}
	// typed-nil 接口面：经接口值调用同样不 panic 且错误可归因。
	var iconn net.Conn = c
	if err := iconn.Close(); !errors.Is(err, errNilConn) {
		t.Errorf("typed-nil 接口的 Close 应报 errNilConn，got %v", err)
	}
}

// --- F6 discardSession 跨连接误删（身份守卫）---

// TestRemoveIfSession_IdentityGuard 单元：条件删除只对同源（sessionID 相同）
// 条目生效——异源条目保留（并行连接的新会话不被误删），同源条目删除。
func TestRemoveIfSession_IdentityGuard(t *testing.T) {
	cache := NewLRUSessionCache(8).(*lruSessionCache)
	a := &SessionState{sessionID: []byte{0xAA}, masterSecret: []byte("secret-a"), createdAt: time.Now()}
	b := &SessionState{sessionID: []byte{0xBB}, masterSecret: []byte("secret-b"), createdAt: time.Now()}
	const key = "sni:test.example.com"
	cache.Put(key, a)

	// 异源（B 的会话已接管同键的形态）：保留。
	if cache.removeIfSession(key, b) {
		t.Fatal("removeIfSession removed a foreign session")
	}
	if got, ok := cache.Get(key); !ok || !bytes.Equal(got.sessionID, a.sessionID) {
		t.Fatal("foreign-session removal must leave the entry untouched")
	}
	// 同源：删除。
	if !cache.removeIfSession(key, a) {
		t.Fatal("removeIfSession did not remove the matching session")
	}
	if _, ok := cache.Get(key); ok {
		t.Fatal("matching session not removed")
	}
	// want 为 nil：恒不删除（防御）。
	cache.Put(key, a)
	if cache.removeIfSession(key, nil) {
		t.Fatal("removeIfSession with nil want must be a no-op")
	}
}

// TestDiscardSession_DoesNotEvictParallelSession 引擎级：连接 A 的拒绝-resume
// 清理（修复前的无条件删除）不得误删并行连接 B 刚写入同一 sni 键的新会话。
func TestDiscardSession_DoesNotEvictParallelSession(t *testing.T) {
	sharedCache := NewLRUSessionCache(8)

	// B 连接已完成全握手，新会话 S_B 在 sni 键与 sessionId 键下。
	sb := &SessionState{
		sessionID:    []byte{0x01, 0x02, 0x03},
		version:      tlcpVersionTLCP,
		cipherSuite:  SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret: []byte("secret-b"),
		createdAt:    time.Now(),
	}
	sniKey := sessionCacheKey("", "test.example.com")
	sharedCache.Put(sniKey, sb)
	sharedCache.Put(clientSessionKey(sb.sessionID), sb)

	// A 连接的在途会话是死会话 X（在 B 写入 sni 键之前由 A 读取——
	// 现在服务端拒绝 A 的 resume，A 执行 discardSession）。
	xa := &SessionState{
		sessionID:    []byte{0xDE, 0xAD},
		version:      tlcpVersionTLCP,
		cipherSuite:  SuiteECC_SM2_SM4_GCM_SM3,
		masterSecret: []byte("secret-dead"),
		createdAt:    time.Now(),
	}
	clientConfig := &tlcpEngineConfig{
		rand:               crand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		serverName:         "test.example.com",
		insecureSkipVerify: true,
		sessionCache:       sharedCache,
	}
	rawA, peerA := net.Pipe()
	defer func() { _ = rawA.Close(); _ = peerA.Close() }()
	connA := newTLCPConn(rawA, clientConfig, true)
	connA.session = xa

	connA.discardSession()

	// A 的 sessionId 键被清除（唯一归属）。
	if _, ok := sharedCache.Get(clientSessionKey(xa.sessionID)); ok {
		t.Fatal("dead session's sessionId key not evicted")
	}
	// B 的新会话在 sni 键下完好（修复前被 A 的无条件删除误删）。
	got, ok := sharedCache.Get(sniKey)
	if !ok || !bytes.Equal(got.sessionID, sb.sessionID) {
		t.Fatal("parallel connection's fresh session was evicted from the sni key")
	}
	// B 的会话仍可正常 resume（后续连接以它恢复）。
	if !sessionFresh(got) {
		t.Fatal("surviving session must remain fresh")
	}
	// A 本身的在途引用清空。
	if connA.session != nil {
		t.Fatal("discardSession must clear the in-flight session reference")
	}
}

// customSessionCache 是自定义 SessionCache 实现（非内置 LRU）——验证
// discardSession 的 Get 比对 + Put(nil) 回退路径同样具备身份守卫。
type customSessionCache struct {
	mu sync.Mutex
	m  map[string]*SessionState
}

func newCustomSessionCache() *customSessionCache {
	return &customSessionCache{m: make(map[string]*SessionState)}
}

func (c *customSessionCache) Get(k string) (*SessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs, ok := c.m[k]
	return cs.clone(), ok
}

func (c *customSessionCache) Put(k string, cs *SessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs == nil {
		delete(c.m, k)
		return
	}
	c.m[k] = cs
}

// TestDiscardSession_CustomCacheFallbackGuard 验证自定义缓存的回退路径：
// 异源 sni 条目保留、同源删除（比对与删除间的窗口已文档化，此处断言常见
// 串行交错下的守卫行为）。
func TestDiscardSession_CustomCacheFallbackGuard(t *testing.T) {
	cache := newCustomSessionCache()
	sb := &SessionState{sessionID: []byte{0x01}, masterSecret: []byte("b"), createdAt: time.Now()}
	xa := &SessionState{sessionID: []byte{0xDE, 0xAD}, masterSecret: []byte("dead"), createdAt: time.Now()}
	cache.Put(sessionCacheKey("", "test.example.com"), sb)

	clientConfig := &tlcpEngineConfig{
		rand:               crand.Reader,
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		serverName:         "test.example.com",
		insecureSkipVerify: true,
		sessionCache:       cache,
	}
	rawA, peerA := net.Pipe()
	defer func() { _ = rawA.Close(); _ = peerA.Close() }()
	connA := newTLCPConn(rawA, clientConfig, true)
	connA.session = xa
	connA.discardSession()

	got, ok := cache.Get(sessionCacheKey("", "test.example.com"))
	if !ok || !bytes.Equal(got.sessionID, sb.sessionID) {
		t.Fatal("custom-cache fallback evicted a foreign session from the sni key")
	}

	// 同源：回退路径删除。
	cache.Put(sessionCacheKey("", "test.example.com"), xa)
	connA.session = xa
	connA.discardSession()
	if _, ok := cache.Get(sessionCacheKey("", "test.example.com")); ok {
		t.Fatal("custom-cache fallback did not evict the matching session")
	}
}
