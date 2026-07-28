//go:build integration

package tlcp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	gotlcp "gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
)

// generateInteropCerts 生成 gotlcp 兼容的证书。
// gotlcp 的 Certificates 按顺序配置：[0]=签名证书, [1]=加密证书
func generateInteropCerts(t *testing.T) (signCert, encCert gotlcp.Certificate) {
	t.Helper()

	curve := sm2.P256()

	// 签名密钥对
	signPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	sm2SignPriv := new(sm2.PrivateKey)
	if _, err := sm2SignPriv.FromECPrivateKey(signPriv); err != nil {
		t.Fatalf("convert sign key: %v", err)
	}

	// 加密密钥对
	encPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate enc key: %v", err)
	}
	sm2EncPriv := new(sm2.PrivateKey)
	if _, err := sm2EncPriv.FromECPrivateKey(encPriv); err != nil {
		t.Fatalf("convert enc key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &smx509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "interop-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
	}

	// 签名证书
	signTemplate := *template
	signTemplate.KeyUsage = smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign
	signDER, err := smx509.CreateCertificate(rand.Reader, &signTemplate, &signTemplate, &signPriv.PublicKey, sm2SignPriv)
	if err != nil {
		t.Fatalf("create sign cert: %v", err)
	}

	// 加密证书
	encTemplate := *template
	encTemplate.KeyUsage = smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment
	encDER, err := smx509.CreateCertificate(rand.Reader, &encTemplate, &encTemplate, &encPriv.PublicKey, sm2EncPriv)
	if err != nil {
		t.Fatalf("create enc cert: %v", err)
	}

	signCert = gotlcp.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  sm2SignPriv,
	}
	encCert = gotlcp.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  sm2EncPriv,
	}
	return
}

// TestInterop_GotlcpServer_PolluxClient 测试 gotlcp 服务端 + pollux-go 客户端
func TestInterop_GotlcpServer_PolluxClient(t *testing.T) {
	signCert, encCert := generateInteropCerts(t)

	// 启动 gotlcp 服务端
	gotlcpConfig := &gotlcp.Config{
		Certificates: []gotlcp.Certificate{signCert, encCert},
		CipherSuites: []uint16{gotlcp.ECC_SM4_GCM_SM3},
	}

	listener, err := gotlcp.Listen("tcp", "127.0.0.1:0", gotlcpConfig)
	if err != nil {
		t.Fatalf("gotlcp listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		// 读取客户端数据
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		// 回显
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverErr <- err
			return
		}
		conn.Close()
		close(serverErr)
	}()

	// pollux-go 客户端连接 gotlcp 服务端
	polluxSignCert := &tls.Certificate{
		Certificate: signCert.Certificate,
		PrivateKey:  signCert.PrivateKey,
	}
	polluxEncCert := &tls.Certificate{
		Certificate: encCert.Certificate,
		PrivateKey:  encCert.PrivateKey,
	}

	clientConfig := &Config{
		Version:            Version11,
		SignCertificate:    polluxSignCert,
		EncCertificate:     polluxEncCert,
		CipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := Client(rawConn, clientConfig)
	if err := client.Handshake(); err != nil {
		t.Fatalf("pollux client handshake: %v", err)
	}
	defer client.Close()

	// 发送数据
	testData := []byte("Hello interop!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// 读取回显（gotlcp 的 Read 可能随数据一起返回 io.EOF，当对端紧接着 close_notify）
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if n == 0 && err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}

	// 检查服务端错误
	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// TestInterop_PolluxServer_GotlcpClient 测试 pollux-go 服务端 + gotlcp 客户端
func TestInterop_PolluxServer_GotlcpClient(t *testing.T) {
	signCert, encCert := generateInteropCerts(t)

	// pollux-go 服务端
	polluxSignCert := &tls.Certificate{
		Certificate: signCert.Certificate,
		PrivateKey:  signCert.PrivateKey,
	}
	polluxEncCert := &tls.Certificate{
		Certificate: encCert.Certificate,
		PrivateKey:  encCert.PrivateKey,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverConfig := &Config{
		Version:         Version11,
		SignCertificate: polluxSignCert,
		EncCertificate:  polluxEncCert,
		CipherSuites:    []uint16{SuiteECC_SM2_SM4_GCM_SM3},
	}

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		server := Server(conn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		// 读取并回显
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			serverDone <- err
			return
		}
		if _, err := server.Write(buf[:n]); err != nil {
			serverDone <- err
			return
		}
		server.Close()
	}()

	// gotlcp 客户端连接 pollux-go 服务端
	gotlcpConfig := &gotlcp.Config{
		Certificates:       []gotlcp.Certificate{signCert, encCert},
		CipherSuites:       []uint16{gotlcp.ECC_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	conn, err := gotlcp.Dial("tcp", ln.Addr().String(), gotlcpConfig)
	if err != nil {
		t.Fatalf("gotlcp dial: %v", err)
	}
	defer conn.Close()

	// 发送数据
	testData := []byte("Hello from gotlcp!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("gotlcp write: %v", err)
	}

	// 读取回显（gotlcp 的 Read 可能随数据一起返回 io.EOF，当对端紧接着 close_notify）
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		t.Fatalf("gotlcp read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}

	// 检查服务端（带超时）
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server timeout")
	}
}
