package tlcp

// ALPN（RFC 7301）协商测试：提议+选中、无提议、无 overlap、信任门（配置
// 提议列表后的注入拒绝）、wire 行为不变、resume 回传。覆盖面与
// tls13gm/alpn_test.go 对应；信任门的"未提议任何列表"负例在
// alpn_gate_test.go（第三轮审查 A1）。

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestALPN_Negotiation 锁定正向路径：客户端提议 + 服务端按客户端优先序
// 选中。客户端首项 "h2"（服务端也支持）胜出，而非服务端自己的首项
// "gm/1.0"——与 tls13gm 的同名测试同一断言。
func TestALPN_Negotiation(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	serverConfig.NextProtos = []string{"gm/1.0", "h3", "h2"}
	clientConfig.NextProtos = []string{"h2", "gm/1.0"}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	for _, tc := range []struct {
		name string
		got  string
	}{
		{"client.NegotiatedProtocol", client.NegotiatedProtocol()},
		{"client.ConnectionState", client.ConnectionState().NegotiatedProtocol},
		{"server.NegotiatedProtocol", server.NegotiatedProtocol()},
		{"server.ConnectionState", server.ConnectionState().NegotiatedProtocol},
	} {
		if tc.got != "h2" {
			t.Fatalf("%s = %q, want h2（客户端优先序）", tc.name, tc.got)
		}
	}
	transferData(t, client, server, []byte("alpn negotiated round trip"))
}

// TestALPN_ClientNoOffer 锁定：客户端不提议 ALPN、服务端配置了 NextProtos
// 时，服务端不选择、不报错（stdlib negotiateALPN 对空 clientProtos 返回
// ("", nil)），握手照常完成、NegotiatedProtocol 为空。
func TestALPN_ClientNoOffer(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	serverConfig.NextProtos = []string{"gm/1.0"}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	if got := client.NegotiatedProtocol(); got != "" {
		t.Fatalf("client NegotiatedProtocol = %q, want 空（客户端未提议）", got)
	}
	if got := server.NegotiatedProtocol(); got != "" {
		t.Fatalf("server NegotiatedProtocol = %q, want 空（客户端未提议）", got)
	}
	transferData(t, client, server, []byte("no offer still works"))
}

// TestALPN_ServerNoProtosDoesNotAdoptClientFirst 锁定语义裁决：客户端提议
// ALPN、服务端未配置 NextProtos 时，服务端不选择（stdlib 对空 serverProtos
// 返回 ("", nil)），而不是采纳客户端首个提议——否则客户端可让服务端
// "协商"任意未配置协议。
func TestALPN_ServerNoProtosDoesNotAdoptClientFirst(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	clientConfig.NextProtos = []string{"h2", "gm/1.0"}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	if got := client.NegotiatedProtocol(); got != "" {
		t.Fatalf("client NegotiatedProtocol = %q, want 空（服务端未配置不应选择）", got)
	}
	if got := server.NegotiatedProtocol(); got != "" {
		t.Fatalf("server NegotiatedProtocol = %q, want 空（服务端未配置不应选择）", got)
	}
	transferData(t, client, server, []byte("server silence is not adoption"))
}

// TestALPN_NoOverlapAbortsServer 锁定：两侧都配置但无交集时服务端中止
// 握手（错误文本含 no_application_protocol），客户端随之失败。
func TestALPN_NoOverlapAbortsServer(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	serverConfig.NextProtos = []string{"h3"}
	clientConfig.NextProtos = []string{"h2"}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	serverErrCh := make(chan error, 1)
	go func() {
		err := Server(serverConn, serverConfig).Handshake()
		serverErrCh <- err // 缓冲为 1：先交结果再陪跑
		// 陪跑到客户端关闭：否则客户端失败路径的 best-effort fatal alert
		// 写会阻塞在无读者的 net.Pipe 上，直到 deadline 才返回（与
		// alpn_gate_test.go 注入测试的 io.Discard 模式一致）。
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	clientErr := Client(clientConn, clientConfig).Handshake()
	serverErr := <-serverErrCh
	if serverErr == nil || !strings.Contains(serverErr.Error(), "no overlapping ALPN protocol") {
		t.Fatalf("服务端应因无 overlap 中止（no_application_protocol），got: %v", serverErr)
	}
	if clientErr == nil {
		t.Fatal("客户端应在服务端中止后收到握手失败")
	}
}

// TestALPN_TrustGateRejectsUnofferedSelection 锁定信任门在客户端实际提议
// 后的语义：恶意服务器在 ServerHello 里选择的协议即便贴合"有提议列表"
// 的新状态，只要不在提议列表内就必须中止握手。
func TestALPN_TrustGateRejectsUnofferedSelection(t *testing.T) {
	_, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	clientConfig.NextProtos = []string{"gm/1.0"}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	sh := &tlcpServerHelloMsg{
		version:           tlcpVersionTLCP,
		random:            make([]byte, 32),
		sessionID:         nil,
		cipherSuite:       SuiteECDHE_SM2_SM4_GCM_SM3, // 客户端已提议，避开套件门
		compressionMethod: 0,
		alpnProtocol:      "evil-unoffered-protocol",
	}
	shBody, err := sh.marshal()
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 0, 5+len(shBody))
	record = append(record, byte(tlcpRecordHandshake), 0x01, 0x01)
	record = binary.BigEndian.AppendUint16(record, uint16(len(shBody)))
	record = append(record, shBody...)

	serverErr := make(chan error, 1)
	go func() {
		// 读掉客户端的 ClientHello（现携带 ALPN 扩展），回注入的
		// ServerHello，然后等客户端报警断开。
		header := make([]byte, 5)
		if _, err := io.ReadFull(serverConn, header); err != nil {
			serverErr <- err
			return
		}
		body := make([]byte, int(header[3])<<8|int(header[4]))
		if _, err := io.ReadFull(serverConn, body); err != nil {
			serverErr <- err
			return
		}
		if _, err := serverConn.Write(record); err != nil {
			serverErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, serverConn) // 直到客户端断开
		serverErr <- nil
	}()

	client := Client(clientConn, clientConfig)
	err = client.Handshake()
	if err == nil {
		t.Fatal("恶意服务器选择了未提议的 ALPN 协议，握手必须失败")
	}
	if !strings.Contains(err.Error(), "ALPN protocol that was not offered") {
		t.Fatalf("错误应为 ALPN 未提议拒绝， got: %v", err)
	}
}

// TestClientHello_ALPNWireBehavior 锁定 wire 行为不变面：未配置 NextProtos
// 时不提议 ALPN 扩展（marshal→unmarshal 往返后 alpnProtocols 为空）；
// 配置后往返保序保留全部提议。
func TestClientHello_ALPNWireBehavior(t *testing.T) {
	// 未配置：不提议。
	hello, err := tlcpMakeClientHello(&tlcpEngineConfig{rand: crand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if len(hello.alpnProtocols) != 0 {
		t.Fatalf("未配置 NextProtos 时不应提议 ALPN，got %v", hello.alpnProtocols)
	}
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed := &tlcpClientHelloMsg{}
	if !parsed.unmarshal(data) {
		t.Fatal("未提议的 ClientHello 应可解析")
	}
	if len(parsed.alpnProtocols) != 0 {
		t.Fatalf("wire 上不应出现 ALPN 扩展，parsed %v", parsed.alpnProtocols)
	}

	// 配置后：往返保序。
	offered := []string{"h2", "gm/1.0"}
	hello, err = tlcpMakeClientHello(&tlcpEngineConfig{rand: crand.Reader, nextProtos: offered})
	if err != nil {
		t.Fatal(err)
	}
	data, err = hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed = &tlcpClientHelloMsg{}
	if !parsed.unmarshal(data) {
		t.Fatal("携带 ALPN 的 ClientHello 应可解析")
	}
	if len(parsed.alpnProtocols) != len(offered) {
		t.Fatalf("ALPN 往返 = %v, want %v", parsed.alpnProtocols, offered)
	}
	for i, p := range offered {
		if parsed.alpnProtocols[i] != p {
			t.Fatalf("ALPN 往返 = %v, want %v（保序）", parsed.alpnProtocols, offered)
		}
	}
}

// TestMakeClientHello_InvalidNextProtos 锁定 stdlib 对齐的构造期校验：
// 空名/超 255 字节 → invalid NextProtos value；总和超 0xffff → values
// too large。
func TestMakeClientHello_InvalidNextProtos(t *testing.T) {
	// 256 个 255 字节名：256×(1+255) = 65536 > 0xffff，单个名字合法但总长超限。
	oversizedTotal := make([]string, 256)
	for i := range oversizedTotal {
		oversizedTotal[i] = strings.Repeat("a", 255)
	}
	for _, tc := range []struct {
		name    string
		protos  []string
		wantErr string
	}{
		{"空名", []string{"h2", ""}, "tlcp: invalid NextProtos value"},
		{"超 255 字节", []string{strings.Repeat("a", 256)}, "tlcp: invalid NextProtos value"},
		{"总长超 0xffff", oversizedTotal, "tlcp: NextProtos values too large"},
	} {
		_, err := tlcpMakeClientHello(&tlcpEngineConfig{rand: crand.Reader, nextProtos: tc.protos})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s：want %q，got %v", tc.name, tc.wantErr, err)
		}
	}
}

// TestALPN_ResumeEchoesSelection 锁定 resume 路径：全握手协商的 ALPN 协议
// 在第二次连接（abbreviated handshake）的 ServerHello 中照常回传，客户端
// 信任门同样覆盖 resume。
func TestALPN_ResumeEchoesSelection(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECC_SM2_SM4_GCM_SM3})
	serverConfig.NextProtos = []string{"gm/1.0"}
	clientConfig.NextProtos = []string{"gm/1.0"}
	sharedCache := NewLRUSessionCache(8)
	serverConfig.SessionCache = sharedCache
	clientConfig.SessionCache = sharedCache

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 4)
	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			go func() {
				_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
				serverErr <- Server(rawConn, serverConfig).Handshake()
			}()
		}
	}()

	dial := func() *Conn {
		rawConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
		return Client(rawConn, clientConfig)
	}

	// 第一次连接：全握手，协商 gm/1.0 并写入会话缓存。
	c1 := dial()
	if err := c1.Handshake(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if c1.ConnectionState().DidResume {
		t.Fatal("第一次连接应为全握手")
	}
	if got := c1.NegotiatedProtocol(); got != "gm/1.0" {
		t.Fatalf("第一次连接协商 %q, want gm/1.0", got)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	// 第二次连接：resume，ServerHello 仍回传 ALPN 选择。
	c2 := dial()
	if err := c2.Handshake(); err != nil {
		t.Fatalf("resume handshake: %v", err)
	}
	if !c2.ConnectionState().DidResume {
		t.Fatal("第二次连接应走 resume")
	}
	if got := c2.NegotiatedProtocol(); got != "gm/1.0" {
		t.Fatalf("resume 连接协商 %q, want gm/1.0", got)
	}
	if err := c2.Close(); err != nil {
		t.Fatalf("close resume: %v", err)
	}
}
