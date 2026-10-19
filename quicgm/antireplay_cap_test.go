package quicgm

// 第三轮审查 P2 低危批(quicgm 侧)回归测试:
//   - B3 anti-replay 缓存容量上限(满时 fail-safe 拒绝新 0-RTT)
//   - B7 ObfuscatedTicketAge 帮助函数
//   - B8 负值传输参数拒绝(此前静默进入 quic.Config)

import (
	"errors"
	"testing"
	"time"
)

// TestAntiReplayCache_CapFailsSafe 锁定 B3:达到容量上限后新摘要被拒绝
// (fail-safe,恢复走 1-RTT),而非无限增长。
func TestAntiReplayCache_CapFailsSafe(t *testing.T) {
	cache := NewAntiReplayCacheWithCap(10*time.Minute, time.Hour, 3)
	digest := func(b byte) []byte { return []byte{b} }

	for i := byte(0); i < 3; i++ {
		if !cache.Check(digest(i), time.Second) {
			t.Fatalf("容量 3 内第 %d 条应被接受", i)
		}
	}
	if cache.Check(digest(0xEE), time.Second) {
		t.Fatal("达到容量上限后新摘要必须被拒绝(fail-safe)")
	}
	// 已在缓存内的摘要仍按重放拒绝(不因容量问题放行重放)。
	if cache.Check(digest(0), time.Second) {
		t.Fatal("缓存内摘要的重放必须被拒绝")
	}
	// 过期/未来票据照常拒绝。
	if cache.Check(digest(0xDD), -time.Second) {
		t.Fatal("负年龄必须被拒绝")
	}
}

// TestAntiReplayCache_NonPositiveCapRejecting 锁定 B3 边界:非正容量得到
// 全拒缓存(无界缓存正是该上限要防的故障模式)。
func TestAntiReplayCache_NonPositiveCapRejecting(t *testing.T) {
	if cache := NewAntiReplayCacheWithCap(time.Minute, time.Hour, 0); cache.Check([]byte("x"), time.Second) {
		t.Fatal("maxEntries<=0 应得到全拒缓存")
	}
}

// TestObfuscatedTicketAge 锁定 B7:RFC 8446 §4.2.10 的混淆年龄 =
// ticket_age_add + 收票以来经过的毫秒数。
func TestObfuscatedTicketAge(t *testing.T) {
	if got := ObfuscatedTicketAge(1000, 1500*time.Millisecond); got != 2500 {
		t.Fatalf("ObfuscatedTicketAge = %d, want 2500", got)
	}
	if got := ObfuscatedTicketAge(0xFFFFFFFF, 1*time.Millisecond); got != 0 {
		t.Fatalf("uint32 回绕应与 RFC 一致(加法模 2^32), got %d", got)
	}
}

// TestClientConfig_RejectsNegativeKnobs 锁定 B8:负 MaxIdleTimeout 不再
// 静默落入 quic.Config。
func TestClientConfig_RejectsNegativeKnobs(t *testing.T) {
	cfg := ClientConfig{
		NextProtos:     []string{"echo"},
		ServerName:     "example.com",
		MaxIdleTimeout: -time.Second,
	}
	if _, err := cfg.tls13ClientConfig(); !errors.Is(err, errNegativeConfig) {
		t.Fatalf("负 MaxIdleTimeout 应返回 errNegativeConfig, got %v", err)
	}
}
