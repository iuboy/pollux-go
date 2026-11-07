package https

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/iuboy/pollux-go/tlcp"
)

// Transport-level defaults applied where the zero value would mean
// "unlimited". Without them a malicious or stalled server can pin client
// goroutines and sockets indefinitely (TLSHandshakeTimeout) and idle
// connections accumulate forever (IdleConnTimeout). They mirror
// http.DefaultTransport (10s/90s) plus a 30s response-header bound.
const (
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
	// defaultClientTimeout bounds the whole request (connect + headers +
	// body) when ClientOptions.Timeout is nil. Long-polling callers should
	// set an explicit larger Timeout (or a non-nil zero to opt out).
	defaultClientTimeout = 120 * time.Second
)

// NewTLCPTransport returns an *http.Transport that dials using TLCP.
// HTTP/2 is disabled since TLCP 1.1 does not support ALPN negotiation.
//
// Context cancellation is fully honored: the dial runs under tlcp.DialContext
// and a watchdog closes the in-flight connection when ctx is done (dialers
// alone only observe deadlines, not cancellation).
//
// Handshake duration bound: when ctx carries no deadline, a default handshake
// deadline of defaultTLSHandshakeTimeout (10s, the same bound NewTLSTransport
// applies via TLSHandshakeTimeout) is layered on top. A deadline-bearing ctx —
// including one with a longer deadline — is never overridden. Without this a
// stalled TLCP server could pin the dial goroutine and socket indefinitely
// (tlcp.DialContext only propagates a deadline the caller supplied).
func NewTLCPTransport(config *tlcp.Config) (*http.Transport, error) {
	if config == nil {
		return nil, errors.New("pollux/https: nil config")
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// net/http backfills ServerName from the URL host on its standard
			// TLS path, but NOT for custom dialers — and the tlcp engine now
			// rejects "verification enabled + empty ServerName" (hostname
			// matching would be silently skipped). Backfill from addr so
			// callers get net/http-equivalent behavior. The engine treats
			// Config as read-only (configToNative copies what it needs), so a
			// shallow copy with one field overridden is safe to dial with.
			cfg := config
			if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
				if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
					copied := *cfg
					copied.ServerName = host
					cfg = &copied
				}
			}
			// 握手时长上界：ctx 未携带 deadline 时补 defaultTLSHandshakeTimeout
			// （10s，与 NewTLSTransport 的 TLSHandshakeTimeout 对齐）；已有
			// deadline（含更长者）不覆盖。tlcp.DialContext 只传播调用方给出
			// 的 deadline，这里不补的话，无 deadline 的 ctx 会把握手时长交给
			// 对端决定（恶意/僵死服务器可无限拖延）。
			dialCtx := ctx
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithTimeout(ctx, defaultTLSHandshakeTimeout)
				defer cancel()
			}
			// tlcp.DialContext honors ctx cancellation for both the dial and
			// the handshake (a cancel closes the in-flight connection from
			// inside and returns the context error). The race below is kept as
			// a belt-and-braces reap: on cancel it closes the connection if
			// DialContext is still winding down, so nothing leaks even if the
			// return path is slow. dialCtx.Err()（而非 ctx.Err()）保证超时
			// 路径也返回非 nil 错误。
			type dialResult struct {
				conn net.Conn
				err  error
			}
			resCh := make(chan dialResult, 1)
			go func() {
				c, err := tlcp.DialContext(dialCtx, network, addr, cfg)
				// typed-nil 归一化：失败路径的 c 是 (*tlcp.Conn)nil，赋给具体
				// 类型变量再存入 net.Conn 接口字段仍是「非 nil 接口包 nil
				// 指针」，下方 watchdog 的 r.conn != nil 判定会失效并对 nil
				// 接收者调用 tlcp.Conn.Close（其无 nil 防护，panic）。此处用
				// 接口变量在失败时存入真正的 nil。
				var conn net.Conn
				if err == nil {
					conn = c
				}
				resCh <- dialResult{conn, err}
			}()
			select {
			case r := <-resCh:
				return r.conn, r.err
			case <-dialCtx.Done():
				go func() {
					if r := <-resCh; r.conn != nil {
						_ = r.conn.Close()
					}
				}()
				return nil, dialCtx.Err()
			}
		},
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       defaultIdleConnTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
	}, nil
}

// NewTLSTransport returns an *http.Transport that dials using standard TLS.
func NewTLSTransport(config *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:       config,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		IdleConnTimeout:       defaultIdleConnTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
	}
}

// NewClient creates an *http.Client configured for TLCP or TLS.
// Mode is auto-detected from the configured certificates.
func NewClient(opts *ClientOptions) (*http.Client, error) {
	if opts == nil {
		return nil, errors.New("pollux/https: nil client options")
	}
	mode := opts.Mode
	if mode == ModeUnset {
		mode = DetectMode(opts.SignCert)
	}

	var transport http.RoundTripper

	switch mode {
	case ModeTLCP:
		cfg, cfgErr := opts.buildTLCPClientConfig()
		if cfgErr != nil {
			return nil, cfgErr
		}
		t, tErr := NewTLCPTransport(cfg)
		if tErr != nil {
			return nil, tErr
		}
		transport = t
	case ModeTLS:
		cfg, cfgErr := opts.buildTLSClientConfig()
		if cfgErr != nil {
			return nil, cfgErr
		}
		transport = NewTLSTransport(cfg)
	default:
		return nil, fmt.Errorf("pollux/https: unsupported client mode: %d", mode)
	}

	client := &http.Client{
		Transport: transport,
	}
	// Pointer semantics: nil → conservative default (bounded end-to-end
	// request time, the same fail-safe posture as ServerOptions); non-nil
	// applies the pointed-to value (which may itself be zero — explicit
	// opt-out). The old nil-means-unlimited default produced clients that a
	// stalled server could pin forever when combined with the transport's
	// per-phase timeouts.
	if opts.Timeout != nil {
		client.Timeout = *opts.Timeout
	} else {
		client.Timeout = defaultClientTimeout
	}

	// Configure redirect policy.
	maxRedirects := opts.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 10 // explicit default
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if maxRedirects < 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("pollux/https: stopped after %d redirects", maxRedirects)
		}
		return nil
	}

	return client, nil
}
