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
func NewTLCPTransport(config *tlcp.Config) (*http.Transport, error) {
	if config == nil {
		return nil, errors.New("pollux/https: nil config")
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// tlcp.DialContext honors the ctx deadline, but a blocked dial or
			// handshake cannot be interrupted by ctx.Done() from inside. Race
			// the dial against cancellation; on cancel, reap the eventual
			// connection (the dial goroutine hands it over and we close it) so
			// nothing leaks.
			type dialResult struct {
				conn net.Conn
				err  error
			}
			resCh := make(chan dialResult, 1)
			go func() {
				conn, err := tlcp.DialContext(ctx, network, addr, config)
				resCh <- dialResult{conn, err}
			}()
			select {
			case r := <-resCh:
				return r.conn, r.err
			case <-ctx.Done():
				go func() {
					if r := <-resCh; r.conn != nil {
						_ = r.conn.Close()
					}
				}()
				return nil, ctx.Err()
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
