package quicgm

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// countingReplay wraps an AntiReplayCache and counts how often Check accepts.
type countingReplay struct {
	inner    AntiReplayCache
	accepted atomic.Int32
}

func (c *countingReplay) Check(digest []byte, age time.Duration) bool {
	ok := c.inner.Check(digest, age)
	if ok {
		c.accepted.Add(1)
	}
	return ok
}

// runEchoServer accepts connections on ln until it is closed, echoing each
// stream (buffer until the client half-closes, then write back).
func runEchoServer(t *testing.T, ln *Listener) {
	t.Helper()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		go func() {
			defer conn.Close()
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer stream.Close()
					data, err := io.ReadAll(stream)
					if err != nil {
						return
					}
					if len(data) > 0 {
						stream.Write(data)
					}
				}()
			}
		}()
	}
}

// waitForTicket polls the connection for a session ticket up to the timeout.
func waitForTicket(t *testing.T, conn *Conn, timeout time.Duration) ([]byte, uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if psk, ageAdd, ok := conn.SessionTicket(); ok {
			return psk, ageAdd
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no session ticket received within %v", timeout)
	return nil, 0
}

// Test0RTT_TicketHarvest verifies the end-to-end ticket flow: a full handshake
// produces a NewSessionTicket that the client surfaces via SessionTicket(), and
// the harvested PSK can drive a PSK-resumption handshake on a second
// connection. This is the prerequisite for 0-RTT.
func Test0RTT_TicketHarvest(t *testing.T) {
	cert, key := generateSM2ServerCert(t)

	ln, err := Listen(context.Background(), ServerConfig{
		Addr:           "127.0.0.1:0",
		Certificate:    cert,
		PrivateKey:     key,
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go runEchoServer(t, ln)

	// Phase 1: full handshake, drive it to completion with a stream exchange,
	// then harvest the ticket.
	conn1, err := Dial(context.Background(), ClientConfig{
		Addr:               ln.Addr().String(),
		InsecureSkipVerify: true,
		MaxIdleTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial (full): %v", err)
	}
	s1, err := conn1.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream 1: %v", err)
	}
	if _, err := s1.Write([]byte("warmup")); err != nil {
		t.Fatalf("warmup write: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("warmup close: %v", err)
	}
	echo := make([]byte, 6)
	if _, err := io.ReadFull(s1, echo); err != nil {
		t.Fatalf("warmup echo read: %v", err)
	}

	psk, ageAdd := waitForTicket(t, conn1, 3*time.Second)
	if len(psk) == 0 {
		t.Fatal("harvested PSK is empty")
	}
	conn1.Close()

	// Phase 2: resume with the PSK. A successful handshake here proves the
	// ticket carried a usable resumption PSK (binder verifies server-side).
	conn2, err := Dial(context.Background(), ClientConfig{
		Addr:                          ln.Addr().String(),
		InsecureSkipVerify:            true,
		MaxIdleTimeout:                5 * time.Second,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: ageAdd,
	})
	if err != nil {
		t.Fatalf("Dial (resumption): %v", err)
	}
	defer conn2.Close()
	s2, err := conn2.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream 2: %v", err)
	}
	msg := []byte("resumed")
	if _, err := s2.Write(msg); err != nil {
		t.Fatalf("resumed write: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("resumed close: %v", err)
	}
	echo2 := make([]byte, len(msg))
	if _, err := io.ReadFull(s2, echo2); err != nil {
		t.Fatalf("resumed echo read: %v", err)
	}
	if string(echo2) != string(msg) {
		t.Fatalf("resumption echo mismatch: got %q want %q", echo2, msg)
	}
}

// Test0RTT_DialEarly is the full 0-RTT end-to-end: a first connection harvests
// a resumption PSK; a second connection dials early (0-RTT), sends data before
// the handshake completes, and the server accepts and echoes it. A third
// attempt reusing the same PSK has its 0-RTT rejected by the anti-replay cache.
func Test0RTT_DialEarly(t *testing.T) {
	cert, key := generateSM2ServerCert(t)

	replay := &countingReplay{inner: NewAntiReplayCache(30*time.Second, 3600*time.Second)}
	ln, err := Listen(context.Background(), ServerConfig{
		Addr:           "127.0.0.1:0",
		Certificate:    cert,
		PrivateKey:     key,
		AllowEarlyData: true,
		AntiReplay:     replay,
		MaxIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go runEchoServer(t, ln)

	// Phase 1: full handshake, harvest the ticket.
	conn1, err := Dial(context.Background(), ClientConfig{
		Addr:               ln.Addr().String(),
		InsecureSkipVerify: true,
		MaxIdleTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial (full): %v", err)
	}
	// Drive the handshake to completion + ticket issuance with a stream exchange.
	s0, err := conn1.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream warmup: %v", err)
	}
	s0.Write([]byte("warmup"))
	s0.Close()
	io.ReadAll(s0)

	psk, ageAdd := waitForTicket(t, conn1, 3*time.Second)
	conn1.Close()

	// Phase 2: DialEarly + send 0-RTT data before the handshake completes.
	conn2, err := DialEarly(context.Background(), ClientConfig{
		Addr:                          ln.Addr().String(),
		InsecureSkipVerify:            true,
		MaxIdleTimeout:                5 * time.Second,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: ageAdd,
		EarlyData:                     true,
	})
	if err != nil {
		t.Fatalf("DialEarly: %v", err)
	}
	defer conn2.Close()

	stream, err := conn2.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream (0-RTT): %v", err)
	}
	payload := []byte("0-rtt payload")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("0-RTT write: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("0-RTT close: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatalf("0-RTT echo read: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("0-RTT echo mismatch: got %q want %q", echo, payload)
	}
	if !conn2.ConnectionState().Used0RTT {
		t.Fatal("client reports 0-RTT was not used (Used0RTT=false)")
	}

	// Phase 3: replay — reuse the same PSK. The anti-replay cache already saw
	// this PSK in Phase 2, so the server must refuse 0-RTT this time. The
	// connection still completes (1-RTT PSK resumption); Used0RTT is false and
	// any data the client tried to send as 0-RTT is not echoed.
	conn3, err := DialEarly(context.Background(), ClientConfig{
		Addr:                          ln.Addr().String(),
		InsecureSkipVerify:            true,
		MaxIdleTimeout:                5 * time.Second,
		ResumptionPSK:                 psk,
		ResumptionObfuscatedTicketAge: ageAdd,
		EarlyData:                     true,
	})
	if err != nil {
		t.Fatalf("DialEarly (replay): %v", err)
	}
	defer conn3.Close()
	// Allow the handshake to settle so ConnectionState reflects the final verdict.
	// A fresh stream exchange drives 1-RTT completion.
	s3, err := conn3.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream (replay): %v", err)
	}
	s3.Write([]byte("after-replay"))
	s3.Close()
	io.ReadAll(s3)
	if conn3.ConnectionState().Used0RTT {
		t.Fatalf("replayed PSK was accepted for 0-RTT (anti-replay failed); acceptor accepted %d times", replay.accepted.Load())
	}
	t.Logf("anti-replay accepted %d time(s) total (expect 1: phase 2 only)", replay.accepted.Load())
}

