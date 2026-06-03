package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	polluxSm2 "github.com/ycq/pollux/sm2"
	polluxSmx509 "github.com/ycq/pollux/smx509"
	polluxTlcp "github.com/ycq/pollux/tlcp"
)

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeKey(t *testing.T, key interface{}) []byte {
	t.Helper()
	sm2Key, ok := key.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("key is not *sm2.PrivateKey: %T", key)
	}
	pemData, err := polluxSm2.WritePrivateKeyToPEM(sm2Key)
	if err != nil {
		t.Fatalf("write key PEM: %v", err)
	}
	return pemData
}

// generateTestTLCPConfig 生成 TLCP 双证书配置。
func generateTestTLCPConfig(t *testing.T) *polluxTlcp.Config {
	t.Helper()

	curve := sm2.P256()

	signPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2SignPriv := new(sm2.PrivateKey)
	if _, err := sm2SignPriv.FromECPrivateKey(signPriv); err != nil {
		t.Fatal(err)
	}

	encPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm2EncPriv := new(sm2.PrivateKey)
	if _, err := sm2EncPriv.FromECPrivateKey(encPriv); err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
	}

	signTmpl := *template
	signTmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	signDER, err := polluxSmx509.CreateCertificate(&signTmpl, &signTmpl, &signPriv.PublicKey, sm2SignPriv)
	if err != nil {
		t.Fatal(err)
	}

	encTmpl := *template
	encTmpl.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	encDER, err := polluxSmx509.CreateCertificate(&encTmpl, &encTmpl, &encPriv.PublicKey, sm2EncPriv)
	if err != nil {
		t.Fatal(err)
	}

	return &polluxTlcp.Config{
		SignCertificate: &tls.Certificate{
			Certificate: [][]byte{signDER},
			PrivateKey:  sm2SignPriv,
		},
		EncCertificate: &tls.Certificate{
			Certificate: [][]byte{encDER},
			PrivateKey:  sm2EncPriv,
		},
		CipherSuites:       []uint16{polluxTlcp.SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}
}

func TestTLCPServer(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello tlcp")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	go func() {
		_ = serveTLCP(ln, handler, tlcpConfig)
	}()

	// 用 TLCP 客户端请求
	transport, err := NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://" + addr + "/test")
	if err != nil {
		t.Fatalf("TLCP GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "hello tlcp" {
		t.Errorf("body: got %q, want %q", string(buf[:n]), "hello tlcp")
	}
}

func TestTLSServer(t *testing.T) {
	// 使用 httptest 生成标准 TLS 证书
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello tls")
	}))
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/test")
	if err != nil {
		t.Fatalf("TLS GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestListenAndServeTLCP(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "tlcp ok")
	})

	// 先获取一个空闲端口，然后释放
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ListenAndServeTLCP(addr, handler, tlcpConfig)
	}()

	// 等待服务端绑定端口
	time.Sleep(100 * time.Millisecond)

	transport, err := NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d", resp.StatusCode)
	}
}

func TestDetectMode(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	// SM2 证书应检测为 TLCP
	mode := DetectMode(tlcpConfig.SignCertificate)
	if mode != ModeTLCP {
		t.Errorf("SM2 cert: got %v, want ModeTLCP", mode)
	}

	// nil 应检测为 TLS
	mode = DetectMode(nil)
	if mode != ModeTLS {
		t.Errorf("nil cert: got %v, want ModeTLS", mode)
	}
}

func TestNewClient(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	opts := &ClientOptions{
		SignCert:           tlcpConfig.SignCertificate,
		EncCert:            tlcpConfig.EncCertificate,
		CipherSuites:       []uint16{polluxTlcp.SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}

	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	if client.Transport == nil {
		t.Fatal("transport should not be nil")
	}
}

func TestHybridServer(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	// 生成标准 TLS 证书（使用标准 P256 曲线，非 SM2）
	tlsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	tlsPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsDER, err := x509.CreateCertificate(rand.Reader, tlsTemplate, tlsTemplate, &tlsPriv.PublicKey, tlsPriv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{tlsDER},
		PrivateKey:  tlsPriv,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello hybrid")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	tlcpCfg, _ := (&ServerOptions{
		SignCert:           tlcpConfig.SignCertificate,
		EncCert:            tlcpConfig.EncCertificate,
		CipherSuites:       []uint16{polluxTlcp.SuiteECDHE_SM2_SM4_GCM_SM3},
		InsecureSkipVerify: true,
	}).buildTLCPConfig()
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	go func() {
		srv := &http.Server{Handler: handler}
		_ = srv.Serve(NewHybridListener(ln, tlcpCfg, tlsCfg))
	}()

	// TLCP 客户端连接
	tlcpTransport, err := NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	tlcpClient := &http.Client{Transport: tlcpTransport}

	resp, err := tlcpClient.Get("https://" + addr + "/tlcp")
	if err != nil {
		t.Fatalf("hybrid TLCP GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("TLCP status: got %d, want 200", resp.StatusCode)
	}

	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "hello hybrid" {
		t.Errorf("TLCP body: got %q, want %q", string(buf[:n]), "hello hybrid")
	}

	// 标准 TLS 客户端连接
	tlsTransport := NewTLSTransport(&tls.Config{InsecureSkipVerify: true})
	tlsClient := &http.Client{Transport: tlsTransport}

	resp2, err := tlsClient.Get("https://" + addr + "/tls")
	if err != nil {
		t.Fatalf("hybrid TLS GET: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Errorf("TLS status: got %d, want 200", resp2.StatusCode)
	}

	n, _ = resp2.Body.Read(buf)
	if string(buf[:n]) != "hello hybrid" {
		t.Errorf("TLS body: got %q, want %q", string(buf[:n]), "hello hybrid")
	}
}

func TestServerOptions_LoadTLCPCertificatesFromPEM(t *testing.T) {
	tlcpConfig := generateTestTLCPConfig(t)

	opts := &ServerOptions{
		Addr:    ":0",
		Handler: http.NewServeMux(),
	}

	signCertPEM := pemEncodeCert(tlcpConfig.SignCertificate.Certificate[0])
	signKeyPEM := pemEncodeKey(t, tlcpConfig.SignCertificate.PrivateKey)
	encCertPEM := pemEncodeCert(tlcpConfig.EncCertificate.Certificate[0])
	encKeyPEM := pemEncodeKey(t, tlcpConfig.EncCertificate.PrivateKey)

	if err := opts.LoadTLCPCertificatesFromPEM(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM); err != nil {
		t.Fatalf("LoadTLCPCertificatesFromPEM: %v", err)
	}
	if opts.SignCert == nil || opts.EncCert == nil {
		t.Error("certificates should be loaded")
	}
}

func TestNewTLCPTransport_NilConfig(t *testing.T) {
	_, err := NewTLCPTransport(nil)
	if err == nil {
		t.Error("NewTLCPTransport with nil config should return error")
	}
}

func TestTLSConfig_CurvePreferences(t *testing.T) {
	opts := &ServerOptions{
		Addr: ":0",
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{{0x30, 0x00}},
			PrivateKey:  mustGenerateP256Key(t),
		}},
	}
	cfg, err := opts.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if len(cfg.CurvePreferences) == 0 {
		t.Error("TLS config should have CurvePreferences set")
	}
}

func mustGenerateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
