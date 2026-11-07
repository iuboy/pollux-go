package tlcp

import (
	"bytes"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// 本文件是第四轮安全审计修复批 A（tlcp 连接层与会话面）的回归测试：
//   #1 prepareCipherSpec 无锁写 staged 密钥（与 destroy 数据竞争）
//   #2 Conn.Write 非整调用原子（并发 Write 记录粒度交错 / close_notify 切开 Write）
//   #3 destroy 后明文回退（双重 Close、teardown 超时场景）
//   #4 Config.Clone 丢 tls.Certificate.SupportedSignatureAlgorithms
//   #5 服务端 NextProtos 无构造期校验
//   #6 SessionCache 客户端/服务端共用 key 命名空间
//   #7 服务端 resume 缓存无身份/策略绑定
//   #8 服务端 mTLS 不验客户端 enc 证书链

// --- #1 prepareCipherSpec vs destroy 数据竞争 ---

// TestPrepareCipherSpecConcurrentDestroy 以引擎级单测直接对撞 establishKeys
// （写 staged 密钥）与 destroy（清零同址字段）。修复前用 -race 运行必报数据
// 竞争；修复后（prepareCipherSpec 内部持 hc.mu）必须干净。CBC 路径写
// nextCBCKey/nextMACKeyBytes，AEAD 路径写 nextAEAD，两条分支各跑一段。
func TestPrepareCipherSpecConcurrentDestroy(t *testing.T) {
	c := newTLCPConn(nil, nil, true)
	ms := bytes.Repeat([]byte{7}, 32)
	cr := bytes.Repeat([]byte{1}, 32)
	sr := bytes.Repeat([]byte{2}, 32)

	for _, suiteID := range []uint16{SuiteECC_SM2_SM4_CBC_SM3, SuiteECC_SM2_SM4_GCM_SM3} {
		suite := tlcpLookupCipherSuite(suiteID)
		if suite == nil {
			t.Fatalf("suite %#04x 未注册", suiteID)
		}
		stop := make(chan struct{})
		// 运行约 200ms 的对撞窗口，让 -race 有足够交错样本。
		timer := time.AfterFunc(200*time.Millisecond, func() { close(stop) })
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.establishKeys(suite, ms, cr, sr)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.in.destroy()
					c.out.destroy()
				}
			}
		}()
		wg.Wait()
		timer.Stop()
	}
}

// --- #3 destroy 后明文回退 ---

// TestHalfConnDestroyedNoPlaintextFallback 锁定：destroy 置位后，encrypt/
// decrypt 在「已建立密钥」与「明文相位」两种状态下都必须报错，绝不回退明文
// 路径（回退 = 应用数据裸奔上 wire，或以全零 CBC 密钥继续加密）。
func TestHalfConnDestroyedNoPlaintextFallback(t *testing.T) {
	rec := make([]byte, tlcpRecordHeaderLen)
	payload := []byte("application data")

	// 已建立密钥（CBC）：destroy 后 encrypt/decrypt 报错。
	hc := &tlcpHalfConn{}
	hc.prepareCipherSpec(make([]byte, 16), nil, hmacSM3Size{}, make([]byte, 32))
	if err := hc.changeCipherSpec(); err != nil {
		t.Fatalf("changeCipherSpec: %v", err)
	}
	if _, err := hc.encrypt(rec, payload); err != nil {
		t.Fatalf("destroy 前 encrypt 应成功: %v", err)
	}
	hc.destroy()
	if _, err := hc.encrypt(rec, payload); !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("destroy 后 encrypt 应报 destroyed，got %v", err)
	}
	if _, _, err := hc.decrypt(append(append([]byte{}, rec...), make([]byte, 48)...)); !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("destroy 后 decrypt 应报 destroyed，got %v", err)
	}

	// 明文相位（从未建立密钥）：destroy 后同样拒绝——这正是双重 Close /
	// teardown 告警超时场景下的明文回退面。
	plain := &tlcpHalfConn{}
	plain.destroy()
	if _, err := plain.encrypt(rec, payload); !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("明文相位 destroy 后 encrypt 回退明文（未拒绝）: %v", err)
	}
	if _, _, err := plain.decrypt(rec); !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("明文相位 destroy 后 decrypt 回退明文（未拒绝）: %v", err)
	}
}

// TestDoubleCloseAndWriteAfterClose 端到端锁定 #3：双重 Close 不 panic、不产
// 生明文回退；Close 之后的 Write 必须报 destroyed 错误（修复前会以清零密钥
// 继续加密或回退明文）。
func TestDoubleCloseAndWriteAfterClose(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer server.Close()

	if err := client.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// 双重 Close：告警写会命中 destroyed 半连接，须静默失败而非 panic。
	if err := client.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	_, err := client.Write([]byte("after close"))
	if !errors.Is(err, errHalfConnDestroyed) {
		t.Errorf("Close 后 Write 应报 destroyed，got %v", err)
	}
}

// --- #2 Write 整调用原子 ---

// TestWriteAtomic_ConcurrentWritesNoInterleave 并发 Write 字节流不交错：两个
// goroutine 各写 N×64KB（每 chunk 拆 4 条记录）的单字节图案，单一读者断言
// 图案切换只发生在 64KB 边界。记录粒度交错（修复前 out.mu 只保证单条记录）
// 会产生 16KB 级的混合 run。-race 下运行。
func TestWriteAtomic_ConcurrentWritesNoInterleave(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	const chunk = 4 * tlcpMaxPlaintext // 64KB = 4 条记录
	const chunks = 4
	const totalWant = 2 * chunk * chunks

	readerErr := make(chan error, 1)
	go func() {
		cur := byte(0)
		run := 0
		total := 0
		buf := make([]byte, 8192)
		for total < totalWant {
			n, err := server.Read(buf)
			if err != nil {
				readerErr <- fmt.Errorf("read at %d: %w", total, err)
				return
			}
			for i := 0; i < n; i++ {
				if buf[i] != cur {
					if run%chunk != 0 {
						readerErr <- fmt.Errorf("并发 Write 交错：图案在 %d 字节处切换，run=%d 非 %d 的倍数", total, run, chunk)
						return
					}
					cur = buf[i]
					run = 0
				}
				run++
				total++
			}
		}
		if run%chunk != 0 {
			readerErr <- fmt.Errorf("尾部 run=%d 非 %d 的倍数", run, chunk)
			return
		}
		readerErr <- nil
	}()

	var wg sync.WaitGroup
	for _, p := range []byte{0xAA, 0xBB} {
		wg.Add(1)
		go func(p byte) {
			defer wg.Done()
			payload := bytes.Repeat([]byte{p}, chunk)
			for i := 0; i < chunks; i++ {
				if _, err := client.Write(payload); err != nil {
					t.Errorf("write pattern %#x: %v", p, err)
					return
				}
			}
		}(p)
	}
	wg.Wait()
	if err := <-readerErr; err != nil {
		t.Fatal(err)
	}
}

// recordTapConn 包装 net.Conn：记录每条记录的类型字节（wrapper 入口处），
// 并可用一次性闸门把下一次 Write 停在入口——用于断言 close_notify 不切开
// 进行中的 Write（#2）。
type recordTapConn struct {
	net.Conn
	mu    sync.Mutex
	types []byte        // 每次底层 Write 的首字节（记录类型）
	gate  chan struct{} // 非 nil：下一次 Write 在入口阻塞
	once  sync.Once
	// closed 在传输层 Close 首次到达时关闭（tlcpConn.Close 会调用
	// conn.Close；此处替换为标记而非真关闭，保证告警记录仍可落 wire）。
	closed chan struct{}
}

func (w *recordTapConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return w.Conn.Write(p)
	}
	w.mu.Lock()
	w.types = append(w.types, p[0])
	g := w.gate
	w.gate = nil
	w.mu.Unlock()
	if g != nil {
		<-g
	}
	return w.Conn.Write(p)
}

func (w *recordTapConn) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

func (w *recordTapConn) len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.types)
}

func (w *recordTapConn) indices(since int, typ byte) []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []int
	for i, b := range w.types[since:] {
		if b == typ {
			out = append(out, i)
		}
	}
	return out
}

// waitTapRecord eventually 轮询等待自 since 起出现指定类型的记录。
func waitTapRecord(t *testing.T, w *recordTapConn, since int, typ byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for w.len() <= since || len(w.indices(since, typ)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("等待记录类型 %d 超时", typ)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCloseNotifyCannotSplitInFlightWrite 锁定：Close 的 close_notify 持
// writeMu 排队，不得切开进行中的 Write。时序：第一条应用数据记录停在
// wrapper 入口（Write 全程持 writeMu）→ 发起 Close → eventually 轮询确认
// 该窗口内无告警记录上 wire → 放行 → 断言全部应用数据记录先于 close_notify。
func TestCloseNotifyCannotSplitInFlightWrite(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	pipeC, pipeS := net.Pipe()
	_ = pipeC.SetDeadline(time.Now().Add(15 * time.Second))
	_ = pipeS.SetDeadline(time.Now().Add(15 * time.Second))
	defer pipeC.Close()
	defer pipeS.Close()

	tap := &recordTapConn{Conn: pipeC, closed: make(chan struct{})}
	client := Client(tap, clientConfig)
	server := Server(pipeS, serverConfig)

	srvErr := make(chan error, 1)
	go func() { srvErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	post := tap.len()

	// 服务端持续读，排空管道。
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	// 闸门停在第一条应用数据记录入口。
	gate := make(chan struct{})
	tap.mu.Lock()
	tap.gate = gate
	tap.mu.Unlock()

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(bytes.Repeat([]byte{0xCD}, 4*tlcpMaxPlaintext))
		writeErr <- err
	}()
	waitTapRecord(t, tap, post, byte(tlcpRecordApplicationData), 5*time.Second)

	// Close 的告警 goroutine 应阻塞在 writeMu（由 Write 持有）。
	closeDone := make(chan struct{})
	go func() {
		_ = client.Close()
		close(closeDone)
	}()
	select {
	case <-tap.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close 未到达传输层")
	}

	// eventually 轮询窗口：若序列化缺失，告警有机会在此窗口上 wire（正常实现
	// 会在整个窗口内保持无告警——窗口本身不是同步，是缺席断言的观察期）。
	pollDeadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(pollDeadline) {
		if n := len(tap.indices(post, byte(tlcpRecordAlert))); n > 0 {
			t.Fatal("close_notify 切开进行中的 Write（writeMu 序列化缺失）")
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(gate) // 放行，Write 完成剩余记录
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Close 未返回")
	}

	waitTapRecord(t, tap, post, byte(tlcpRecordAlert), 5*time.Second)
	appIdx := tap.indices(post, byte(tlcpRecordApplicationData))
	alertIdx := tap.indices(post, byte(tlcpRecordAlert))
	if len(appIdx) < 4 {
		t.Fatalf("应用数据记录数 %d，应 >= 4（64KB 拆 4 条）", len(appIdx))
	}
	if appIdx[len(appIdx)-1] > alertIdx[0] {
		t.Fatalf("close_notify 先于最后一条应用数据记录：app=%v alert=%v", appIdx, alertIdx)
	}
	<-readDone
}

// --- #4 Config.Clone 深拷贝 SupportedSignatureAlgorithms ---

func TestConfigClone_SupportedSignatureAlgorithms(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)
	signCert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.PSSWithSHA256}

	c := &Config{SignCertificate: signCert, EncCertificate: encCert}
	clone := c.Clone()

	got := clone.SignCertificate.SupportedSignatureAlgorithms
	if len(got) != 2 || got[0] != tls.PKCS1WithSHA256 || got[1] != tls.PSSWithSHA256 {
		t.Fatalf("Clone 丢失 SupportedSignatureAlgorithms: %v", got)
	}
	// 深拷贝：改 clone 不影响原件。
	got[0] = 0
	if signCert.SupportedSignatureAlgorithms[0] == 0 {
		t.Error("Clone 与原件共享 SupportedSignatureAlgorithms 底层数组")
	}
	// 未设置该字段的证书保持 nil。
	if clone.EncCertificate.SupportedSignatureAlgorithms != nil {
		t.Error("未设置字段的 Clone 结果应为 nil")
	}
}

// --- #5 NextProtos 双端构造期校验 ---

func TestConfigToNative_InvalidNextProtosBothRoles(t *testing.T) {
	oversizedTotal := make([]string, 256)
	for i := range oversizedTotal {
		oversizedTotal[i] = strings.Repeat("a", 255)
	}
	cases := []struct {
		name    string
		protos  []string
		wantErr string
	}{
		{"空名", []string{"h2", ""}, "tlcp: invalid NextProtos value"},
		{"超 255 字节", []string{strings.Repeat("a", 256)}, "tlcp: invalid NextProtos value"},
		{"总长超 0xffff", oversizedTotal, "tlcp: NextProtos values too large"},
	}
	for _, isClient := range []bool{true, false} {
		for _, tc := range cases {
			nc, err := configToNative(&Config{NextProtos: tc.protos}, isClient)
			if err == nil || nc != nil {
				t.Errorf("role=client=%v %s：应构造期报错，got nc=%v err=%v", isClient, tc.name, nc, err)
				continue
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("role=client=%v %s：want %q，got %v", isClient, tc.name, tc.wantErr, err)
			}
		}
	}
	// 构造期 fail-fast 端到端：Server() 把校验错误落到 initErr，Handshake 即刻
	// 失败（此前服务端非法 NextProtos 会静默通过构造期）。
	pipeC, pipeS := net.Pipe()
	defer pipeC.Close()
	defer pipeS.Close()
	s := Server(pipeS, &Config{NextProtos: []string{""}})
	if err := s.Handshake(); err == nil || !strings.Contains(err.Error(), "invalid NextProtos value") {
		t.Errorf("服务端构造期校验缺失：Handshake err = %v", err)
	}
}

// --- #6 SessionCache 角色前缀 ---

func TestSessionKeyRolePrefix(t *testing.T) {
	id := []byte{1, 2, 3, 4}
	if clientSessionKey(id) == serverSessionKey(id) {
		t.Fatal("客户端/服务端 sessionId 缓存键未隔离")
	}
	cache := NewLRUSessionCache(8)
	mkSess := func() *SessionState {
		return &SessionState{
			sessionID:    id,
			version:      tlcpVersionTLCP,
			cipherSuite:  SuiteECC_SM2_SM4_GCM_SM3,
			masterSecret: make([]byte, 32),
			createdAt:    time.Now(),
		}
	}
	cache.Put(clientSessionKey(id), mkSess())

	// 共享缓存跨角色不命中：服务端读不到客户端条目。
	if _, ok := cache.Get(serverSessionKey(id)); ok {
		t.Fatal("服务端命中了客户端写入的缓存条目（跨角色命名空间未隔离）")
	}
	if _, ok := cache.Get(clientSessionKey(id)); !ok {
		t.Fatal("客户端自己的缓存条目不可读")
	}

	// 服务端视角端到端：lookupResumedSession 不命中客户端条目，命中服务端条目。
	serverConn := newTLCPConn(nil, &tlcpEngineConfig{sessionCache: cache}, false)
	serverConn.vers = tlcpVersionTLCP
	suite := tlcpLookupCipherSuite(SuiteECC_SM2_SM4_GCM_SM3)
	ch := &tlcpClientHelloMsg{version: tlcpVersionTLCP, sessionID: id, cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3}}
	if sess := serverConn.lookupResumedSession(ch, suite); sess != nil {
		t.Fatal("服务端 resume 命中了客户端角色的缓存条目")
	}
	cache.Put(serverSessionKey(id), mkSess())
	if sess := serverConn.lookupResumedSession(ch, suite); sess == nil {
		t.Fatal("服务端应命中自己角色的缓存条目")
	}
}

// --- #7 / #8 mTLS resume 与双证验链 ---

// mtlsResumeConfigs 构造 mTLS（clientAuth 指定校验级别）+ 共享会话缓存的
// 双端配置：客户端证书由 trustedCA 签发（含 ClientAuth EKU），服务端证书为
// 自签名测试对。
func mtlsResumeConfigs(t *testing.T, sharedCache SessionCache, clientAuth ClientAuthType) (serverConfig, clientConfig *Config) {
	t.Helper()
	trustedCA, trustedKey := generateSM2CA(t, "mtls-resume-ca")
	clientSign, clientEnc := generateClientCertPair(t, trustedCA, trustedKey)
	serverSign, serverEnc := generateTestCertPair(t)

	serverConfig = &Config{
		Version:              Version11,
		SignCertificate:      serverSign,
		EncCertificate:       serverEnc,
		CipherSuites:         []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		ClientAuth:           clientAuth,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, trustedCA)},
		InsecureSkipVerify:   true,
		SessionCache:         sharedCache,
	}
	clientConfig = &Config{
		Version:            Version11,
		SignCertificate:    clientSign,
		EncCertificate:     clientEnc,
		CipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		ServerName:         "test",
		InsecureSkipVerify: true,
		SessionCache:       sharedCache,
	}
	return serverConfig, clientConfig
}

// mtlsServeLoop 在 ln 上循环接受连接：握手成功后回显一条消息。
func mtlsServeLoop(t *testing.T, ln net.Listener, config *Config, done chan struct{}) {
	t.Helper()
	for {
		rawConn, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		go func() {
			_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
			conn := Server(rawConn, config)
			if err := conn.Handshake(); err != nil {
				t.Errorf("server handshake: %v", err)
				_ = rawConn.Close()
				return
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("server read: %v", err)
				_ = rawConn.Close()
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				t.Errorf("server write: %v", err)
			}
		}()
	}
}

func mtlsDial(t *testing.T, ln net.Listener, config *Config) *Conn {
	t.Helper()
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	return Client(rawConn, config)
}

func mtlsEcho(t *testing.T, conn *Conn, msg []byte) {
	t.Helper()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Fatalf("echo mismatch: %q != %q", echo, msg)
	}
}

// TestResume_mTLS_RequireVerify_ResumesWithVerifiedIdentity 正例：mTLS 强制
// 验链模式下，全握手后第二次连接正常 resume（缓存会话携带的客户端双证重跑
// 链验证通过）。
func TestResume_mTLS_RequireVerify_ResumesWithVerifiedIdentity(t *testing.T) {
	sharedCache := NewLRUSessionCache(8)
	serverConfig, clientConfig := mtlsResumeConfigs(t, sharedCache, RequireAndVerifyClientCert)

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
	mtlsEcho(t, conn1, []byte("mtls full handshake"))
	_ = conn1.Close()

	conn2 := mtlsDial(t, ln, clientConfig)
	if err := conn2.Handshake(); err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if !conn2.ConnectionState().DidResume {
		t.Fatal("mTLS 模式下第二次连接应 resume（缓存身份重验通过）")
	}
	mtlsEcho(t, conn2, []byte("mtls resumed"))
	_ = conn2.Close()
}

// TestResume_mTLS_RogueCachedSessionFallsBackToFullHandshake 负例：服务端缓
// 存条目被替换为不受信 CA 签发的客户端双证（其余字段与配置一致）。客户端提
// 议该 sessionId 时，resume 门必须验链失败 → 放弃 resume 走全握手（不报错中
// 断），连接照常可用、didResume=false。修复前服务端仅验 version+suite，会直
// 接以伪造会话 resume（abbreviated handshake 不重发客户端证书，rogue 身份无
// 从拦截）。
func TestResume_mTLS_RogueCachedSessionFallsBackToFullHandshake(t *testing.T) {
	sharedCache := NewLRUSessionCache(8)
	serverConfig, clientConfig := mtlsResumeConfigs(t, sharedCache, RequireAndVerifyClientCert)

	rogueCA, rogueKey := generateSM2CA(t, "rogue-resume-ca")
	rogueSign, rogueEnc := generateClientCertPair(t, rogueCA, rogueKey)

	// 伪造 sessionId X（32 字节）与两端缓存条目：服务端条目绑 rogue 双证。
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
		t.Fatal("rogue 缓存条目被 resume（resume 门未验链）")
	}
	mtlsEcho(t, conn, []byte("fallback full handshake"))
	_ = conn.Close()
}

// TestClientAuth_RogueEncCertRejected 负例（#8）：客户端 sign 证书链受信、
// enc 证书由另一 CA 签发。修复前服务端只验 sign 链，该组合被放行（PMS 用
// enc 公钥加密，enc 证书不受信即 PMS 泄露面）；修复后 VerifyDualCertSignatures
// 的同 CA/同 subject 配对约束直接拒绝。
func TestClientAuth_RogueEncCertRejected(t *testing.T) {
	trustedCA, trustedKey := generateSM2CA(t, "sign-trusted-ca")
	rogueCA, rogueKey := generateSM2CA(t, "enc-rogue-ca")
	trustedSign, _ := generateClientCertPair(t, trustedCA, trustedKey)
	_, rogueEnc := generateClientCertPair(t, rogueCA, rogueKey)

	serverSign, serverEnc := generateTestCertPair(t)
	serverConfig := &Config{
		Version:              Version11,
		SignCertificate:      serverSign,
		EncCertificate:       serverEnc,
		CipherSuites:         []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		ClientAuth:           RequireAndVerifyClientCert,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, trustedCA)},
		InsecureSkipVerify:   true,
	}
	clientConfig := &Config{
		Version:            Version11,
		SignCertificate:    trustedSign,
		EncCertificate:     rogueEnc,
		CipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	// 用 TCP 而非 net.Pipe：拒绝发生在服务端读完客户端 Certificate 之后，双方
	// 同时处于写方向（服务端写告警、客户端写 CKE）——net.Pipe 无缓冲会把两端
	// 卡到 5s 告警截止时间；TCP 内核缓冲让双方即时完成各自写入。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			serverErrCh <- aerr
			return
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		serverErrCh <- Server(raw, serverConfig).Handshake()
	}()
	clientErrCh := make(chan error, 1)
	go func() {
		raw, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			clientErrCh <- derr
			return
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		clientErrCh <- Client(raw, clientConfig).Handshake()
	}()

	serverErr := <-serverErrCh
	clientErr := <-clientErrCh
	if serverErr == nil || !strings.Contains(serverErr.Error(), "client certificate verification failed") {
		t.Fatalf("混合受信/rogue enc 证书应被拒绝，serverErr = %v", serverErr)
	}
	if clientErr == nil {
		t.Fatal("客户端应在服务端拒绝后收到握手失败")
	}
}

// TestVerifyClientCertChain_SingleSignCert 锁定单证回退路径：客户端只发
// sign 证书（无 enc）时退化为单链 Verify——受信接受、rogue 拒绝。
func TestVerifyClientCertChain_SingleSignCert(t *testing.T) {
	trustedCA, trustedKey := generateSM2CA(t, "single-cert-ca")
	trustedSign, _ := generateClientCertPair(t, trustedCA, trustedKey)
	pool := polluxsmx509.NewCertPool()
	pool.AddCert(stdCertFromSM(t, trustedCA))

	trustedCert, err := polluxsmx509.ParseCertificate(trustedSign.Certificate[0])
	if err != nil {
		t.Fatalf("parse trusted cert: %v", err)
	}
	if err := verifyClientCertChain(trustedCert, nil, pool); err != nil {
		t.Errorf("单证回退路径误拒受信证书: %v", err)
	}

	rogueCA, rogueKey := generateSM2CA(t, "single-rogue-ca")
	rogueSign, _ := generateClientCertPair(t, rogueCA, rogueKey)
	rogueCert, err := polluxsmx509.ParseCertificate(rogueSign.Certificate[0])
	if err != nil {
		t.Fatalf("parse rogue cert: %v", err)
	}
	if err := verifyClientCertChain(rogueCert, nil, pool); err == nil {
		t.Error("rogue 单证被接受")
	}
}
