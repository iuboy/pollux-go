package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/iuboy/pollux-go/tlcp"
)

// NewTLCPTransport returns an *http.Transport that dials using TLCP.
// HTTP/2 is disabled since TLCP 1.1 does not support ALPN negotiation.
func NewTLCPTransport(config *tlcp.Config) (*http.Transport, error) {
	if config == nil {
		return nil, errors.New("pollux/http: nil config")
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			if deadline, ok := ctx.Deadline(); ok {
				dialer.Deadline = deadline
			}
			return tlcp.DialWithDialer(dialer, network, addr, config)
		},
		ForceAttemptHTTP2: false,
	}, nil
}

// NewTLSTransport returns an *http.Transport that dials using standard TLS.
func NewTLSTransport(config *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig: config,
	}
}

// NewClient creates an *http.Client configured for TLCP or TLS.
// Mode is auto-detected from the configured certificates.
func NewClient(opts *ClientOptions) (*http.Client, error) {
	mode := opts.Mode
	if mode == 0 {
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
		return nil, fmt.Errorf("pollux/http: unsupported client mode: %d", mode)
	}

	client := &http.Client{
		Transport: transport,
	}
	if opts.Timeout > 0 {
		client.Timeout = opts.Timeout
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
			return fmt.Errorf("pollux/http: stopped after %d redirects", maxRedirects)
		}
		return nil
	}

	return client, nil
}
