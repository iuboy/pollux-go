package tlcp

import (
	"net"
	"sync"
	"testing"
)

// TestConnCloseConcurrentHandshake exercises the data race between Conn.Close
// (which spawns an alert goroutine reaching writeRecord) and a concurrent
// Conn.Handshake (which writes c.vers/c.haveVers). Run with -race to observe.
//
// Before the fix in this commit, writeRecord read c.vers/c.haveVers outside
// out.mu while the handshake wrote them under handshakeMutex only, so the
// close-notify goroutine raced with the handshake. The fix reads those fields
// under out.mu and writes them under out.mu too; this test must be race-free.
func TestConnCloseConcurrentHandshake(t *testing.T) {
	t.Run("client close during handshake", func(t *testing.T) {
		serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})

		// net.Pipe is synchronous: the client blocks reading ServerHello right
		// after sending ClientHello, maximizing the window for Close to race.
		clientNet, serverNet := net.Pipe()
		defer clientNet.Close()
		defer serverNet.Close()

		server := Server(serverNet, serverConfig)
		client := Client(clientNet, clientConfig)

		// Drive the server handshake in the background; it will proceed until it
		// needs the client's follow-up flight, then block.
		var serverErr error
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			serverErr = server.Handshake()
		}()

		// Run the client handshake; we will Close it from another goroutine to
		// race the alert path against the handshake's writes to vers/haveVers.
		handshakeDone := make(chan struct{})
		go func() {
			_ = client.Handshake()
			close(handshakeDone)
		}()

		// Close concurrently with the in-flight handshake.
		_ = client.Close()

		// Tear down the server side so goroutines can exit.
		_ = serverNet.Close()
		<-serverDone
		<-handshakeDone
		_ = serverErr
	})

	t.Run("repeated close+write after handshake", func(t *testing.T) {
		// After a completed handshake, exercise concurrent Close + Write to
		// stress the buffering atomic and the out.mu-protected record path.
		serverConfig, clientConfig := testConfig(t, []uint16{SuiteECDHE_SM2_SM4_GCM_SM3})
		clientNet, serverNet := net.Pipe()

		server := Server(serverNet, serverConfig)
		client := Client(clientNet, clientConfig)

		shake := func(c *Conn) func() {
			return func() {
				_ = c.Handshake()
			}
		}
		go shake(server)()
		if err := client.Handshake(); err != nil {
			clientNet.Close()
			serverNet.Close()
			t.Skipf("handshake failed (pipe race window): %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = client.Write([]byte("hello"))
		}()
		go func() {
			defer wg.Done()
			_ = client.Close()
		}()
		wg.Wait()
		_ = server.Close()
	})
}
