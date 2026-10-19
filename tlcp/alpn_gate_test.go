package tlcp

// 第三轮审查 P2:A1 客户端 ALPN 信任门、A3 空套件回退与 DefaultCipherSuites 对齐。

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// TestClientHello_EmptySuiteFallbackIsDefault 锁定 A3:engine 级空套件列表
// 回退到 DefaultCipherSuites()(ECDHE+GCM,前向保密),不再静默降级到
// static-ECC(无 PFS)+ CBC 套件。
func TestClientHello_EmptySuiteFallbackIsDefault(t *testing.T) {
	hello, err := tlcpMakeClientHello(&tlcpEngineConfig{rand: crand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultCipherSuites()
	if len(hello.cipherSuites) != len(want) {
		t.Fatalf("空套件回退 = %v, want %v", hello.cipherSuites, want)
	}
	for i, s := range want {
		if hello.cipherSuites[i] != s {
			t.Fatalf("空套件回退 = %v, want %v", hello.cipherSuites, want)
		}
	}
	for _, s := range hello.cipherSuites {
		if s == SuiteECC_SM2_SM4_CBC_SM3 || s == SuiteECC_SM2_SM4_GCM_SM3 {
			t.Fatalf("回退列表包含 static-ECC 套件 %#04x(无前向保密)", s)
		}
	}
}

// TestClientHandshake_RejectsUnofferedALPN 锁定 A1:客户端从不提议 ALPN,
// 恶意服务器在 ServerHello 里选择的任意 ALPN 协议必须中止握手(此前被
// 原样采信,ConnectionState().NegotiatedProtocol 可报告未协商协议)。
func TestClientHandshake_RejectsUnofferedALPN(t *testing.T) {
	_, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	sh := &tlcpServerHelloMsg{
		version:           tlcpVersionTLCP,
		random:            make([]byte, 32),
		sessionID:         nil,
		cipherSuite:       SuiteECDHE_SM2_SM4_GCM_SM3, // 客户端已提议,避开套件门
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
		// 读掉客户端的 ClientHello(明文记录),回注入的 ServerHello,
		// 然后等客户端报警断开。
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
		t.Fatal("恶意服务器选择了未提议的 ALPN 协议,握手必须失败")
	}
	if !strings.Contains(err.Error(), "ALPN protocol that was not offered") {
		t.Fatalf("错误应为 ALPN 未提议拒绝, got: %v", err)
	}
}
