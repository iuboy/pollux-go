package crl

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// stubGenerator 计数式 Generator 桩。
type stubGenerator struct {
	Generator // 未覆盖方法不参与测试

	updateCalls atomic.Int32
	getCalls    atomic.Int32
	err         error
}

func (s *stubGenerator) Update(_ context.Context) error {
	s.updateCalls.Add(1)
	return s.err
}

func (s *stubGenerator) Get() []byte {
	s.getCalls.Add(1)
	return []byte("primary-cache")
}

// StopAutoUpdate 覆盖嵌入的 nil 接口方法（fanout 停止时会调子实例）
func (s *stubGenerator) StopAutoUpdate() {}

func TestFanout_UpdateFansOutToAll(t *testing.T) {
	primary := &stubGenerator{}
	other1 := &stubGenerator{}
	other2 := &stubGenerator{}

	fanout := NewFanout(primary, other1, other2)
	if err := fanout.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	for name, g := range map[string]*stubGenerator{
		"primary": primary, "other1": other1, "other2": other2,
	} {
		if got := g.updateCalls.Load(); got != 1 {
			t.Errorf("%s updated %d times, want 1", name, got)
		}
	}
}

func TestFanout_PrimaryNotDuplicated(t *testing.T) {
	// primary 只应被刷新一次（NewFanout 不应把 primary 重复计入 others）
	primary := &stubGenerator{}
	fanout := NewFanout(primary)
	_ = fanout.Update(context.Background())
	if got := primary.updateCalls.Load(); got != 1 {
		t.Errorf("primary updated %d times, want 1", got)
	}
}

func TestFanout_UpdatePartialFailure(t *testing.T) {
	primary := &stubGenerator{}
	failing := &stubGenerator{err: errors.New("boom")}
	okay := &stubGenerator{}

	fanout := NewFanout(primary, failing, okay)
	err := fanout.Update(context.Background())
	if err == nil {
		t.Fatal("aggregated error expected when one instance fails")
	}
	// 失败不阻断其余实例
	if got := primary.updateCalls.Load(); got != 1 {
		t.Errorf("primary updated %d times, want 1", got)
	}
	if got := okay.updateCalls.Load(); got != 1 {
		t.Errorf("okay updated %d times, want 1", got)
	}
}

func TestFanout_GetDelegatesToPrimary(t *testing.T) {
	primary := &stubGenerator{}
	fanout := NewFanout(primary, &stubGenerator{})
	if got := fanout.Get(); string(got) != "primary-cache" {
		t.Errorf("Get() = %q, want primary cache", got)
	}
}

func TestFanout_AutoUpdateDrivesAll(t *testing.T) {
	primary := &stubGenerator{}
	other := &stubGenerator{}
	fanout := NewFanout(primary, other)

	fanout.StartAutoUpdate(5 * time.Millisecond)
	defer fanout.StopAutoUpdate()

	time.Sleep(30 * time.Millisecond)
	fanout.StopAutoUpdate()

	if primary.updateCalls.Load() == 0 {
		t.Error("primary was never updated by auto-update loop")
	}
	if other.updateCalls.Load() == 0 {
		t.Error("other was never updated by auto-update loop")
	}
}

// crlNumberOf 读取 crlGenerator 的进程内 CRL 编号（每次 Generate 递增），
// 用作“扇出循环是否仍在驱动子实例”的观察窗口。
func crlNumberOf(g *crlGenerator) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.crlNumber
}

// TestFanout_AutoUpdateSelfExitsWhenAllChildrenStopped 锁定泄漏保护修复：
// 调用方只单独停掉全部子实例而未停扇出时，循环会在下一个 tick 探测到
// （allStopped）并自行退出——此前 ticker 会永续空转（只监听 f.stop）。
func TestFanout_AutoUpdateSelfExitsWhenAllChildrenStopped(t *testing.T) {
	auth := newHardeningAuth(t)
	g1 := NewGenerator(auth, NewMemoryCache()).(*crlGenerator)
	g2 := NewGenerator(auth, NewMemoryCache()).(*crlGenerator)
	fanout := NewFanout(g1, g2)

	if err := fanout.StartAutoUpdate(5 * time.Millisecond); err != nil {
		t.Fatalf("StartAutoUpdate: %v", err)
	}
	defer fanout.StopAutoUpdate()

	// 先让若干 tick 跑起来，确认循环在驱动子实例。
	time.Sleep(20 * time.Millisecond)
	base := crlNumberOf(g1)
	if base == 0 {
		t.Fatal("fanout loop never drove children before stop")
	}

	// 只停子实例、不停扇出：泄漏场景。
	g1.StopAutoUpdate()
	g2.StopAutoUpdate()

	// 循环最迟在下个 tick（5ms）退出；留足余量后再取基准。
	time.Sleep(20 * time.Millisecond)
	frozen := crlNumberOf(g1)

	// 再等数个 tick 周期，编号不应继续增长（循环已退出）。
	time.Sleep(40 * time.Millisecond)
	if got := crlNumberOf(g1); got != frozen {
		t.Fatalf("fanout loop still driving children after all children stopped: crlNumber %d -> %d", frozen, got)
	}
}

// TestFanout_AutoUpdateKeepsRunningWhileAnyChildActive 锁定 allStopped 的
// 保守面：只要有子实例仍在运行（这里 g2 未停），扇出循环就不得退出。
func TestFanout_AutoUpdateKeepsRunningWhileAnyChildActive(t *testing.T) {
	auth := newHardeningAuth(t)
	g1 := NewGenerator(auth, NewMemoryCache()).(*crlGenerator)
	g2 := NewGenerator(auth, NewMemoryCache()).(*crlGenerator)
	fanout := NewFanout(g1, g2)

	if err := fanout.StartAutoUpdate(5 * time.Millisecond); err != nil {
		t.Fatalf("StartAutoUpdate: %v", err)
	}
	defer fanout.StopAutoUpdate()

	g1.StopAutoUpdate() // 仅停一个子实例
	time.Sleep(25 * time.Millisecond)

	if crlNumberOf(g2) == 0 {
		t.Fatal("fanout loop exited although g2 is still active")
	}
}
