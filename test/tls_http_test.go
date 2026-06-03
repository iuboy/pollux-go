package test

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	polluxHTTP "github.com/ycq/pollux/http"
)

func TestTLSServerWithRSACert(t *testing.T) {
	cert, err := tls.LoadX509KeyPair(certPath("rsa_cert.pem"), certPath("rsa_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	addr := getFreeAddr(t)
	var srvErr serverErr
	defer srvErr.check(t)

	go func() {
		srvErr.set(polluxHTTP.ListenAndServeTLSNat(addr, echoHandler(), tlsConfig))
	}()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + addr + "/tls-test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestTLSClientWithRSACert(t *testing.T) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	transport := polluxHTTP.NewTLSTransport(tlsConfig)
	client := &http.Client{Transport: transport}

	// 连接公开 HTTPS 站点验证 TLS transport
	resp, err := client.Get("https://www.baidu.com/")
	if err != nil {
		t.Skipf("TLS to baidu: %v (network?)", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d", resp.StatusCode)
	}
}
