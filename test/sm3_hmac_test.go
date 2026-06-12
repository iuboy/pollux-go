package test

import (
	"bytes"
	"testing"

	polluxSM3 "github.com/iuboy/pollux-go/sm3"
)

func TestBlackBox_SM3_HMAC_BasicRoundtrip(t *testing.T) {
	key := []byte("test-hmac-key-1234567890123456")
	h := polluxSM3.NewHMAC(key)
	h.Write([]byte("test message"))
	mac := h.Sum(nil)
	if len(mac) != 32 {
		t.Errorf("HMAC-SM3 output length: got %d, want 32", len(mac))
	}
}

func TestBlackBox_SM3_HMAC_DifferentKeys(t *testing.T) {
	msg := []byte("same message")
	h1 := polluxSM3.NewHMAC([]byte("key-aaaa"))
	h1.Write(msg)
	mac1 := h1.Sum(nil)

	h2 := polluxSM3.NewHMAC([]byte("key-bbbb"))
	h2.Write(msg)
	mac2 := h2.Sum(nil)

	if bytes.Equal(mac1, mac2) {
		t.Error("different keys should produce different MACs")
	}
}

func TestBlackBox_SM3_HMAC_DifferentMessages(t *testing.T) {
	key := []byte("same-key-for-test")
	h1 := polluxSM3.NewHMAC(key)
	h1.Write([]byte("message A"))
	mac1 := h1.Sum(nil)

	h2 := polluxSM3.NewHMAC(key)
	h2.Write([]byte("message B"))
	mac2 := h2.Sum(nil)

	if bytes.Equal(mac1, mac2) {
		t.Error("different messages should produce different MACs")
	}
}

func TestBlackBox_SM3_HMAC_EmptyKey(t *testing.T) {
	h := polluxSM3.NewHMAC(nil)
	h.Write([]byte("message"))
	mac := h.Sum(nil)
	if len(mac) != 32 {
		t.Errorf("empty key HMAC length: got %d, want 32", len(mac))
	}
}

func TestBlackBox_SM3_HMAC_EmptyMessage(t *testing.T) {
	h := polluxSM3.NewHMAC([]byte("key"))
	mac := h.Sum(nil)
	if len(mac) != 32 {
		t.Errorf("empty message HMAC length: got %d, want 32", len(mac))
	}
}

func TestBlackBox_SM3_HMAC_StreamingWrite(t *testing.T) {
	key := []byte("streaming-test-key")

	// One-shot
	h1 := polluxSM3.NewHMAC(key)
	h1.Write([]byte("hello world"))
	mac1 := h1.Sum(nil)

	// Streaming
	h2 := polluxSM3.NewHMAC(key)
	h2.Write([]byte("hello"))
	h2.Write([]byte(" "))
	h2.Write([]byte("world"))
	mac2 := h2.Sum(nil)

	if !bytes.Equal(mac1, mac2) {
		t.Error("streaming Write should produce same MAC as one-shot")
	}
}

func TestBlackBox_SM3_HMAC_Reset(t *testing.T) {
	key := []byte("reset-test-key")
	h := polluxSM3.NewHMAC(key)

	h.Write([]byte("first"))
	mac1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte("second"))
	mac2 := h.Sum(nil)

	if bytes.Equal(mac1, mac2) {
		t.Error("Reset + different write should produce different MAC")
	}

	// Verify reset produces same result as fresh HMAC
	h2 := polluxSM3.NewHMAC(key)
	h2.Write([]byte("second"))
	mac3 := h2.Sum(nil)
	if !bytes.Equal(mac2, mac3) {
		t.Error("Reset should produce same result as fresh HMAC")
	}
}
