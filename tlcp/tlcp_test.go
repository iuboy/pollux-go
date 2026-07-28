package tlcp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	smx509 "github.com/emmansun/gmsm/smx509"
	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// generateTestCertPair 生成一对自签名 SM2 证书（签名 + 加密）。
func generateTestCertPair(t *testing.T) (signCert, encCert *tls.Certificate) {
	t.Helper()

	curve := sm2.P256()

	// 生成签名密钥对
	signPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	sm2SignPriv := new(sm2.PrivateKey)
	if _, err := sm2SignPriv.FromECPrivateKey(signPriv); err != nil {
		t.Fatalf("convert sign key: %v", err)
	}

	// 生成加密密钥对
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
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment,
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

	signCert = &tls.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  sm2SignPriv,
	}
	encCert = &tls.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  sm2EncPriv,
	}
	return
}

// stdCertFromSM converts a gmsm *smx509.Certificate to a stdlib *x509.Certificate
// via pollux's ParseCertificate path (field copy; gmsm v0.44 removed ToX509()).
func stdCertFromSM(t *testing.T, smCert *smx509.Certificate) *x509.Certificate {
	t.Helper()
	std, err := polluxsmx509.ParseCertificate(smCert.Raw)
	if err != nil {
		t.Fatalf("convert smx509 cert to stdlib: %v", err)
	}
	return std
}

// testConfig 创建测试用 TLCP 配置。
func testConfig(t *testing.T, cipherSuites []uint16) (*Config, *Config) {
	t.Helper()
	signCert, encCert := generateTestCertPair(t)

	serverConfig := &Config{
		Version:         Version11,
		SignCertificate: signCert,
		EncCertificate:  encCert,
		CipherSuites:    cipherSuites,
	}

	clientConfig := &Config{
		Version:            Version11,
		SignCertificate:    signCert,
		EncCertificate:     encCert,
		CipherSuites:       cipherSuites,
		InsecureSkipVerify: true,
	}

	return serverConfig, clientConfig
}

// transferData 通过同步管道发送数据：在独立 goroutine 中写入，主 goroutine 读取。
func transferData(t *testing.T, writer, reader *Conn, data []byte) {
	t.Helper()

	writeErr := make(chan error, 1)
	go func() {
		_, err := writer.Write(data)
		writeErr <- err
	}()

	buf := make([]byte, len(data)+256)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Fatalf("data mismatch: got %q, want %q", string(buf[:n]), string(data))
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
}

// handshakeOverPipe 通过 net.Pipe 执行握手。
func handshakeOverPipe(t *testing.T, serverConfig, clientConfig *Config) (*Conn, *Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()

	var clientErr, serverErr error
	var clientTLCP, serverTLCP *Conn

	done := make(chan struct{})

	go func() {
		defer close(done)
		defer func() {
			if serverErr != nil {
				serverConn.Close()
			}
		}()
		serverTLCP = Server(serverConn, serverConfig)
		serverErr = serverTLCP.Handshake()
		if serverErr != nil {
			t.Logf("server handshake error: %v", serverErr)
		}
	}()

	clientTLCP = Client(clientConn, clientConfig)
	clientErr = clientTLCP.Handshake()

	<-done

	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}

	return clientTLCP, serverTLCP
}

func TestHandshakeECDHE_GCM(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("Hello TLCP ECDHE-GCM!"))
}

func TestHandshakeECDHE_CBC(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_CBC_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("Hello TLCP ECDHE-CBC!"))
}

func TestHandshakeECC_GCM(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECC_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("Hello TLCP ECC-GCM!"))
}

func TestHandshakeECC_CBC(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECC_SM2_SM4_CBC_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("Hello TLCP ECC-CBC!"))
}

func TestBidirectionalData(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	// client → server
	transferData(t, client, server, []byte("client to server"))

	// server → client
	transferData(t, server, client, []byte("server to client"))
}

func TestLargeDataTransfer(t *testing.T) {
	serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	// 发送较大数据（超过单个记录）
	largeData := make([]byte, 8192)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(largeData)
		writeErr <- err
	}()

	received := make([]byte, 0, len(largeData))
	buf := make([]byte, 16384)
	for len(received) < len(largeData) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		received = append(received, buf[:n]...)
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("client write large data: %v", err)
	}

	for i := range largeData {
		if received[i] != largeData[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, received[i], largeData[i])
		}
	}
}

// TestCertificateVerify_SelfSigned 测试自签名证书验证。
// 使用自签名证书作为自己的根 CA，验证完整的证书链检查。
func TestCertificateVerify_SelfSigned(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	// 构建根 CA 池：将自签名证书加入
	signPool := x509.NewCertPool()
	smSignCert, err := smx509.ParseCertificate(signCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse sign cert: %v", err)
	}
	signPool.AddCert(stdCertFromSM(t, smSignCert))

	encPool := x509.NewCertPool()
	smEncCert, err := smx509.ParseCertificate(encCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse enc cert: %v", err)
	}
	encPool.AddCert(stdCertFromSM(t, smEncCert))

	serverConfig := &Config{
		Version:         Version11,
		SignCertificate: signCert,
		EncCertificate:  encCert,
		CipherSuites:    []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
	}

	clientConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify:   false,
		SignRootCAs:          signPool,
		EncRootCAs:           encPool,
		SignRootCertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		EncRootCertificates:  []*x509.Certificate{stdCertFromSM(t, smEncCert)},
	}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("verify ok"))
}

// TestCertificateVerify_WithRootCA 测试带根 CA 池的证书验证。
func TestCertificateVerify_WithRootCA(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	// 从证书 DER 构建 CA 池（SM2 证书需通过 smx509 解析后转换）
	signPool := x509.NewCertPool()
	smSignCert, err := smx509.ParseCertificate(signCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse sign cert: %v", err)
	}
	signPool.AddCert(stdCertFromSM(t, smSignCert))

	encPool := x509.NewCertPool()
	smEncCert, err := smx509.ParseCertificate(encCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse enc cert: %v", err)
	}
	encPool.AddCert(stdCertFromSM(t, smEncCert))

	serverConfig := &Config{
		Version:         Version11,
		SignCertificate: signCert,
		EncCertificate:  encCert,
		CipherSuites:    []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
	}

	clientConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify:   false,
		SignRootCAs:          signPool,
		EncRootCAs:           encPool,
		SignRootCertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		EncRootCertificates:  []*x509.Certificate{stdCertFromSM(t, smEncCert)},
	}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("verify with root CA"))
}

// TestClientAuth_ECDHE 测试客户端认证（ECDHE 模式）。
func TestClientAuth_ECDHE(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	// 构建 CA 池（客户端验证服务端）
	signPool := x509.NewCertPool()
	smSignCert, _ := smx509.ParseCertificate(signCert.Certificate[0])
	signPool.AddCert(stdCertFromSM(t, smSignCert))
	encPool := x509.NewCertPool()
	smEncCert, _ := smx509.ParseCertificate(encCert.Certificate[0])
	encPool.AddCert(stdCertFromSM(t, smEncCert))

	serverConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		ClientAuth:           RequireAndVerifyClientCert,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert), stdCertFromSM(t, smEncCert)},
		InsecureSkipVerify:   true,
	}

	clientConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify:   false,
		SignRootCAs:          signPool,
		EncRootCAs:           encPool,
		SignRootCertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		EncRootCertificates:  []*x509.Certificate{stdCertFromSM(t, smEncCert)},
	}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("client auth ECDHE"))
}

// TestClientAuth_ECC 测试客户端认证（ECC 模式）。
func TestClientAuth_ECC(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	signPool := x509.NewCertPool()
	smSignCert, _ := smx509.ParseCertificate(signCert.Certificate[0])
	signPool.AddCert(stdCertFromSM(t, smSignCert))
	encPool := x509.NewCertPool()
	smEncCert, _ := smx509.ParseCertificate(encCert.Certificate[0])
	encPool.AddCert(stdCertFromSM(t, smEncCert))

	serverConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		ClientAuth:           RequireAndVerifyClientCert,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		InsecureSkipVerify:   true,
	}

	clientConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		InsecureSkipVerify:   false,
		SignRootCAs:          signPool,
		EncRootCAs:           encPool,
		SignRootCertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		EncRootCertificates:  []*x509.Certificate{stdCertFromSM(t, smEncCert)},
	}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("client auth ECC"))
}

func TestClientAuth_RequireVerifyWithoutClientCAsFails(t *testing.T) {
	signCert, encCert := generateTestCertPair(t)

	signPool := x509.NewCertPool()
	smSignCert, _ := smx509.ParseCertificate(signCert.Certificate[0])
	signPool.AddCert(stdCertFromSM(t, smSignCert))
	encPool := x509.NewCertPool()
	smEncCert, _ := smx509.ParseCertificate(encCert.Certificate[0])
	encPool.AddCert(stdCertFromSM(t, smEncCert))

	serverConfig := &Config{
		Version:            Version11,
		SignCertificate:    signCert,
		EncCertificate:     encCert,
		CipherSuites:       []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		ClientAuth:         RequireAndVerifyClientCert,
		InsecureSkipVerify: true,
		// 故意不设置 ClientCACertificates，测试无 CA 时的失败
	}
	clientConfig := &Config{
		Version:              Version11,
		SignCertificate:      signCert,
		EncCertificate:       encCert,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify:   false,
		SignRootCAs:          signPool,
		EncRootCAs:           encPool,
		SignRootCertificates: []*x509.Certificate{stdCertFromSM(t, smSignCert)},
		EncRootCertificates:  []*x509.Certificate{stdCertFromSM(t, smEncCert)},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- Server(serverConn, serverConfig).Handshake()
	}()

	clientErr := Client(clientConn, clientConfig).Handshake()
	serverErr := <-serverErrCh
	if serverErr == nil {
		t.Fatal("server handshake should fail when RequireAndVerifyClientCert has no ClientCACertificates")
	}
	if clientErr == nil {
		t.Fatal("client handshake should fail after server rejects missing client certs")
	}
}

// generateClientCertPair 生成一对由指定 CA 签发的 SM2 客户端证书（签名 + 加密），
// 含 ExtKeyUsageClientAuth。与 generateTestCertPair 不同，证书非自签名，
// 用于测试 mTLS 客户端证书链校验（受信 CA 签发→接受，不受信→拒绝）。
func generateClientCertPair(t *testing.T, caCert *smx509.Certificate, caKey *sm2.PrivateKey) (signCert, encCert *tls.Certificate) {
	t.Helper()

	curve := sm2.P256()

	signPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate rogue sign key: %v", err)
	}
	sm2SignPriv := new(sm2.PrivateKey)
	if _, err := sm2SignPriv.FromECPrivateKey(signPriv); err != nil {
		t.Fatalf("convert rogue sign key: %v", err)
	}

	encPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate rogue enc key: %v", err)
	}
	sm2EncPriv := new(sm2.PrivateKey)
	if _, err := sm2EncPriv.FromECPrivateKey(encPriv); err != nil {
		t.Fatalf("convert rogue enc key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	base := &smx509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rogue-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []smx509.ExtKeyUsage{smx509.ExtKeyUsageClientAuth},
	}

	signT := *base
	signT.KeyUsage = smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign
	signDER, err := smx509.CreateCertificate(rand.Reader, &signT, caCert, &signPriv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create rogue sign cert: %v", err)
	}

	encT := *base
	encT.KeyUsage = smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment
	encDER, err := smx509.CreateCertificate(rand.Reader, &encT, caCert, &encPriv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create rogue enc cert: %v", err)
	}

	signCert = &tls.Certificate{Certificate: [][]byte{signDER}, PrivateKey: sm2SignPriv}
	encCert = &tls.Certificate{Certificate: [][]byte{encDER}, PrivateKey: sm2EncPriv}
	return
}

// generateSM2CA 生成一个自签名 SM2 CA 证书 + 私钥（用于测试）。
func generateSM2CA(t *testing.T, cn string) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(sm2.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	smPriv := new(sm2.PrivateKey)
	if _, err := smPriv.FromECPrivateKey(priv); err != nil {
		t.Fatalf("convert CA key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, smPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, smPriv
}

// TestClientAuth_RogueCertRejected 验证 RequireAndVerifyClientCert 模式下，
// 不受信 CA 签发的客户端证书被拒绝（链校验回归保护）。
//
// 回归背景：v0.2.1 原生引擎的 ClientCACertificates 未接入验签路径，
// 任何持有私钥的客户端证书都能握手成功。此测试守护修复。
func TestClientAuth_RogueCertRejected(t *testing.T) {
	// 1. 服务端证书对（自签名，作为受信 CA）
	serverSign, serverEnc := generateTestCertPair(t)
	smServerSignCA, _ := smx509.ParseCertificate(serverSign.Certificate[0])

	// 2. 独立的 rogue CA + 由其签发的客户端证书对
	rogueCA, rogueKey := generateSM2CA(t, "rogue-ca")
	rogueSign, rogueEnc := generateClientCertPair(t, rogueCA, rogueKey)

	// 3. 服务端只信任自己的签名 CA，不信任 rogue CA
	serverConfig := &Config{
		Version:              Version11,
		SignCertificate:      serverSign,
		EncCertificate:       serverEnc,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		ClientAuth:           RequireAndVerifyClientCert,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, smServerSignCA)},
		InsecureSkipVerify:   true,
	}

	// 4. 客户端用 rogue 证书对（InsecureSkipVerify 跳过服务端校验，聚焦客户端校验）
	clientConfig := &Config{
		Version:            Version11,
		SignCertificate:    rogueSign,
		EncCertificate:     rogueEnc,
		CipherSuites:       []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- Server(serverConn, serverConfig).Handshake()
	}()

	clientErr := Client(clientConn, clientConfig).Handshake()
	serverErr := <-serverErrCh
	if serverErr == nil {
		t.Fatal("服务端应拒绝不受信 CA 签发的客户端证书，但握手成功（链校验缺失）")
	}
	if clientErr == nil {
		t.Fatal("客户端应在服务端拒绝后收到握手失败")
	}
	t.Logf("正确拒绝 rogue 证书: serverErr=%v", serverErr)
}

// TestClientAuth_TrustedCertAccepted 验证 RequireAndVerifyClientCert 模式下，
// 受信 CA 签发的客户端叶子证书（含 ClientAuth EKU，客户端只发叶子不发 CA）被接受。
// 正向对照，确保链校验 + KeyUsages=ClientAuth 没有误拒真实场景。
func TestClientAuth_TrustedCertAccepted(t *testing.T) {
	// 1. 服务端证书对（自签名）
	serverSign, serverEnc := generateTestCertPair(t)

	// 2. 独立的受信 CA + 由其签发的客户端叶子证书对（含 ClientAuth EKU）
	trustedCA, trustedKey := generateSM2CA(t, "trusted-client-ca")
	trustedSign, trustedEnc := generateClientCertPair(t, trustedCA, trustedKey)

	// 3. 服务端信任该 CA
	serverConfig := &Config{
		Version:              Version11,
		SignCertificate:      serverSign,
		EncCertificate:       serverEnc,
		CipherSuites:         []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		ClientAuth:           RequireAndVerifyClientCert,
		ClientCACertificates: []*x509.Certificate{stdCertFromSM(t, trustedCA)},
		InsecureSkipVerify:   true,
	}
	clientConfig := &Config{
		Version:            Version11,
		SignCertificate:    trustedSign,
		EncCertificate:     trustedEnc,
		CipherSuites:       []uint16{SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	client, server := handshakeOverPipe(t, serverConfig, clientConfig)
	defer client.Close()
	defer server.Close()

	transferData(t, client, server, []byte("trusted client auth ok"))
}
