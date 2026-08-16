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
