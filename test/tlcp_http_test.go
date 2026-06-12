package test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	polluxHTTP "github.com/iuboy/pollux-go/http"
)

func TestTLCPServerWithTongsuoCerts(t *testing.T) {
	tlcpConfig := buildTLCPConfig(t)

	addr := getFreeAddr(t)
	var srvErr serverErr
	defer srvErr.check(t)

	go func() {
		srvErr.set(polluxHTTP.ListenAndServeTLCP(addr, echoHandler(), tlcpConfig))
	}()
	time.Sleep(200 * time.Millisecond)

	transport, err := polluxHTTP.NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://" + addr + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if body != "GET /hello" {
		t.Errorf("body: got %q, want %q", body, "GET /hello")
	}
}

func TestTLCPServerLoadFromFile(t *testing.T) {
	opts := &polluxHTTP.ServerOptions{
		Addr:    getFreeAddr(t),
		Handler: echoHandler(),
	}

	err := opts.LoadTLCPCertificates(
		certPath("sm2_sign_cert.pem"), certPath("sm2_sign_key.pem"),
		certPath("sm2_enc_cert.pem"), certPath("sm2_enc_key.pem"),
	)
	if err != nil {
		t.Fatalf("LoadTLCPCertificates: %v", err)
	}
	if opts.SignCert == nil || opts.EncCert == nil {
		t.Error("certificates should be loaded")
	}
}

func TestTLCPMultipleRequests(t *testing.T) {
	tlcpConfig := buildTLCPConfig(t)

	addr := getFreeAddr(t)
	var srvErr serverErr
	defer srvErr.check(t)

	go func() {
		srvErr.set(polluxHTTP.ListenAndServeTLCP(addr, echoHandler(), tlcpConfig))
	}()
	time.Sleep(200 * time.Millisecond)

	transport, err := polluxHTTP.NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	client := &http.Client{Transport: transport}

	for i := 0; i < 5; i++ {
		resp, err := client.Get(fmt.Sprintf("https://%s/req/%d", addr, i))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("request %d: status %d", i, resp.StatusCode)
		}
	}
}
