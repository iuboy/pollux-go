package crl

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// fanoutGenerator 扇出生成器：Update/自动更新作用于全部实例，Get/Generate 委托
// primary（保持 Generator 单实例语义）。启停语义与 crlGenerator 一致（单次
// 生命周期内各只生效一次；stop 通道于构造时创建，stop-before-start 亦能正确
// 终止后继启动的循环，与单实例行为对称）。
//
// 停机入口：fanout 自身的 StopAutoUpdate 是扇出定时循环的唯一规范停机入口
// （它会停掉循环并逐一停子实例）。单独停某个子实例不会停扇出循环——但作为
// 泄漏保护，循环在每个 tick 探测到全部子实例均已单独停止时会自行退出
// （见 allStopped），避免 ticker 永续空转。
//
// 用途：authority.Revoke 的 GenerateOnRevoke 钩子与自动更新循环只持有一个
// Generator，而多 issuer 部署下每个 issuer 有独立生成器（各自缓存）。把全部
// 实例聚合进 fanout 后注入 authority，任一 issuer 的证书吊销后所有 CRL 同步
// 刷新，消除「状态端点读到永不被刷新的平行实例」。
type fanoutGenerator struct {
	Generator // primary：Get/Generate/GenerateWithOptions 委托

	others []Generator

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
}

// NewFanout 创建扇出生成器。primary 同时参与 Update 扇出。
func NewFanout(primary Generator, others ...Generator) Generator {
	return &fanoutGenerator{
		Generator: primary,
		others:    others,
		stop:      make(chan struct{}),
	}
}

// Update 刷新全部实例。单个实例失败不阻断其余（聚合错误返回，调用方按
// warn 日志处理，不影响吊销主流程）。
func (f *fanoutGenerator) Update(ctx context.Context) error {
	var errs []error
	for _, g := range f.all() {
		if g == nil {
			continue
		}
		if err := g.Update(ctx); err != nil {
			errs = append(errs, err)
			slog.Warn("CRL 刷新失败（fanout）", "error", err)
		}
	}
	return errors.Join(errs...)
}

// StartAutoUpdate 启动扇出定时刷新（子实例不再各自起循环，由 fanout 统一驱动）。
// interval 非正返回错误（与单实例一致：ticker 对非正 interval 会 panic 且
// 位于子 goroutine 不可 recover，直接崩溃进程）。
//
// 停机：调用 fanout 的 StopAutoUpdate（唯一规范入口）。若调用方只单独停了
// 全部子实例而未停扇出，循环会在下一个 tick 探测到（allStopped）后自行退出，
// 防止 ticker 永续空转。
func (f *fanoutGenerator) StartAutoUpdate(interval time.Duration) error {
	if interval <= 0 {
		return errors.New("crl: auto-update interval must be positive")
	}
	f.startOnce.Do(func() {
		go func(stop chan struct{}) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					// 泄漏保护：StopAutoUpdate（fanout 级）是唯一规范停机入口，
					// 单独停子实例不会停扇出。若全部子实例都已单独停止，扇出
					// 已无事可驱动，直接退出以免 ticker 永续空转。
					if f.allStopped() {
						slog.Warn("fanout 全部子生成器均已单独停止，扇出自动更新循环自行退出（常规停机应调用 fanout 的 StopAutoUpdate）")
						return
					}
					// 与单实例 autoUpdateLoop 一致的超时：防止某个 issuer 的
					// Authority 挂起卡死整条扇出链（顺序 Update 下其余 issuer
					// 的 CRL 也会停摆）。
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					if err := f.Update(ctx); err != nil {
						slog.Warn("CRL 自动更新失败（fanout）", "error", err)
					}
					cancel()
				case <-stop:
					return
				}
			}
		}(f.stop)
	})
	return nil
}

// StopAutoUpdate 停止扇出循环并停止全部子实例的循环。这是扇出定时循环的
// 唯一规范停机入口：单独停止某个（乃至全部）子实例不会（在下一个 tick 之前）
// 停止扇出循环——全部子实例均单独停止时循环会自行退出（泄漏保护，见
// allStopped），但那不应作为常规停机方式。
func (f *fanoutGenerator) StopAutoUpdate() {
	f.stopOnce.Do(func() {
		close(f.stop)
		for _, g := range f.all() {
			if g == nil {
				continue
			}
			g.StopAutoUpdate()
		}
	})
}

// allStopped 报告全部子生成器是否均已单独停止（各自的 stopCh 已关闭）。
// Generator 接口不暴露停止状态，但本包的 *crlGenerator 可直接探测；其它
// 实现（含测试桩）无从查询，一律按“仍在运行”处理——宁可保守多跑 tick，
// 也不误停仍在服务的扇出。全部子实例停止 = 扇出无事可驱动，用于循环的
// 泄漏保护退出（见 StartAutoUpdate）。
func (f *fanoutGenerator) allStopped() bool {
	for _, g := range f.all() {
		if g == nil {
			continue
		}
		cg, ok := g.(*crlGenerator)
		if !ok {
			return false
		}
		select {
		case <-cg.stopCh:
			// 该子实例已停止
		default:
			return false
		}
	}
	return true
}

func (f *fanoutGenerator) all() []Generator {
	return append([]Generator{f.Generator}, f.others...)
}
