package http

import (
	"net"
	"testing"
	"time"

	"crypto/tls"
	"github.com/iuboy/pollux-go/tlcp"
)

func TestSetHandshakeTimeout(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer baseLn.Close()

	hln := NewHybridListener(baseLn, &tlcp.Config{}, &tls.Config{})
	hln.SetHandshakeTimeout(5 * time.Second)

	if hln.handshakeTimeout != 5*time.Second {
		t.Error("handshake timeout not set")
	}
}

func TestSetProtocolMask(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer baseLn.Close()

	hln := NewHybridListener(baseLn, &tlcp.Config{}, &tls.Config{})
	mask := ProtocolMask{AllowTLCP: true, AllowTLS: false}
	hln.SetProtocolMask(mask)

	if hln.protocolMask.AllowTLCP != true || hln.protocolMask.AllowTLS != false {
		t.Error("protocol mask not set correctly")
	}
}

func TestAccept(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer baseLn.Close()

	hln := NewHybridListener(baseLn, &tlcp.Config{}, &tls.Config{})

	// Try to accept with a short timeout - should block
	done := make(chan error, 1)
	go func() {
		_, err := hln.Accept()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("accept should fail without connection")
		}
	case <-time.After(100 * time.Millisecond):
		// Timeout is expected - no connection attempted
	}
}
