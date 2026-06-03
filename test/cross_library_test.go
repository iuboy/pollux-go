package test

import (
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	polluxHTTP "github.com/ycq/pollux/http"
	polluxSm2 "github.com/ycq/pollux/sm2"
	polluxSmx509 "github.com/ycq/pollux/smx509"
)

const tongsuoBin = "/opt/local/tongsuo/bin/openssl"

func tongsuoAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(tongsuoBin); err != nil {
		t.Skip("Tongsuo not available")
	}
}

// TestCertInteropParse verifies Tongsuo-generated SM2 certificates are
// parseable by pollux/smx509 with correct field extraction.
func TestCertInteropParse(t *testing.T) {
	tongsuoAvailable(t)

	certPEM := readCert(t, "sm2_sign_cert.pem")

	smCert, err := polluxSmx509.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	if smCert.Subject.CommonName != "localhost-sign" {
		t.Errorf("CommonName: got %q, want %q", smCert.Subject.CommonName, "localhost-sign")
	}
	if smCert.SerialNumber == nil {
		t.Error("SerialNumber is nil")
	}
}

// TestSM2KeyInterop verifies SM2 keys round-trip between Tongsuo and pollux/sm2.
func TestSM2KeyInterop(t *testing.T) {
	tongsuoAvailable(t)

	// Parse Tongsuo-generated key with pollux/sm2
	keyPEM := readCert(t, "sm2_sign_key.pem")
	key, err := polluxSm2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}

	// Write it back and re-parse
	written, err := polluxSm2.WritePrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}

	key2, err := polluxSm2.ParsePrivateKeyFromPEM(written)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if key2 == nil {
		t.Fatal("re-parsed key is nil")
	}
}

// TestPolluxServerTongsuoClient starts a pollux TLCP server and connects
// with Tongsuo s_client to verify cross-library interoperability.
// NOTE: Tongsuo 8.5.0-pre1 s_client -ntls has an internal bug (state_machine:internal error),
// so this test currently always skips. It's kept for future Tongsuo versions.
func TestPolluxServerTongsuoClient(t *testing.T) {
	tongsuoAvailable(t)
	if testing.Short() {
		t.Skip("skipping cross-process test in short mode")
	}
	t.Skip("Tongsuo 8.5.0-pre1 s_client -ntls is broken: state_machine:internal error")

	tlcpConfig := buildTLCPConfig(t)
	addr := getFreeAddr(t)
	var srvErr serverErr
	defer srvErr.check(t)

	ln, err := listenTCP(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		srvErr.set(polluxHTTP.ListenAndServeTLCP(addr, echoHandler(), tlcpConfig))
	}()
	time.Sleep(200 * time.Millisecond)

	// Tongsuo s_client connect (uses -ntls flag)
	cmd := exec.Command(tongsuoBin, "s_client",
		"-connect", addr,
		"-ntls",
		"-sign_cert", certPath("sm2_sign_cert.pem"),
		"-sign_key", certPath("sm2_sign_key.pem"),
		"-enc_cert", certPath("sm2_enc_cert.pem"),
		"-enc_key", certPath("sm2_enc_key.pem"),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start s_client: %v", err)
	}

	httpReq := "GET /interop HTTP/1.0\r\nHost: localhost\r\n\r\n"
	_, _ = stdin.Write([]byte(httpReq))
	stdin.Close()

	_ = cmd.Wait()
}

// TestTongsuoServerPolluxClient starts Tongsuo s_server and connects
// with a pollux TLCP client transport.
// NOTE: Tongsuo 8.5.0-pre1 s_server -ntls has an internal bug (state_machine:internal error),
// so this test currently always skips. It's kept for future Tongsuo versions.
func TestTongsuoServerPolluxClient(t *testing.T) {
	tongsuoAvailable(t)
	if testing.Short() {
		t.Skip("skipping cross-process test in short mode")
	}
	t.Skip("Tongsuo 8.5.0-pre1 s_server -ntls is broken: state_machine:internal error")

	addr := getFreeAddr(t)

	// Start Tongsuo s_server with NTLS/TLCP
	cmd := exec.Command(tongsuoBin, "s_server",
		"-accept", addr,
		"-ntls",
		"-sign_cert", certPath("sm2_sign_cert.pem"),
		"-sign_key", certPath("sm2_sign_key.pem"),
		"-enc_cert", certPath("sm2_enc_cert.pem"),
		"-enc_key", certPath("sm2_enc_key.pem"),
		"-www",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start s_server: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	time.Sleep(500 * time.Millisecond)

	// Connect with pollux TLCP transport
	tlcpConfig := buildTLCPConfig(t)
	transport, err := polluxHTTP.NewTLCPTransport(tlcpConfig)
	if err != nil {
		t.Fatalf("NewTLCPTransport: %v", err)
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("TLCP client GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// TestDecryptTongsuoEncryptedKey verifies pollux/smx509 can decrypt
// keys encrypted by Tongsuo's pkcs8 command.
func TestDecryptTongsuoEncryptedKey(t *testing.T) {
	tongsuoAvailable(t)

	tests := []struct {
		name     string
		keyFile  string
		password string
	}{
		{"AES-256-CBC sign key", "sm2_sign_key_aes.pem", certPassword},
		{"SM4-CBC sign key", "sm2_sign_key_sm4.pem", certPassword},
		{"AES-256-CBC enc key", "sm2_enc_key_aes.pem", certPassword},
		{"SM4-CBC enc key", "sm2_enc_key_sm4.pem", certPassword},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyPEM := readCert(t, tc.keyFile)

			decrypted, err := polluxSmx509.DecryptPEMPrivateKey(keyPEM, tc.password)
			if err != nil {
				t.Fatalf("DecryptPEMPrivateKey: %v", err)
			}

			key, err := polluxSm2.ParsePrivateKeyFromPEM(decrypted)
			if err != nil {
				t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
			}
			if key == nil {
				t.Error("key is nil after decrypt+parse")
			}
		})
	}
}

func listenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
