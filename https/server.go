package https

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/iuboy/pollux-go/tlcp"
)

// ListenAndServe starts an HTTP server with TLS or TLCP.
// Mode is auto-detected from the configured certificates.
func ListenAndServe(opts *ServerOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	mode := opts.DetectMode()
	rawLn, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}

	ln, err := wrapListener(rawLn, opts, mode)
	if err != nil {
		rawLn.Close() // wrap failed; clean up the raw TCP listener
		return err
	}

	// http.Server.Serve closes the passed Listener when it returns (Go stdlib
	// documented behavior). We must NOT defer rawLn.Close() here — that would
	// race with Serve's close of the wrapper (which closes the underlying
	// raw listener transitively), causing a double-close on the raw TCP
	// socket. If Serve fails to close the wrapper for any reason, the
	// wrapper's own Close path still reaches rawLn.
	srv := buildHTTPServer(opts)
	return srv.Serve(ln)
}

// ListenAndServeTLCP starts an HTTP server using the TLCP protocol.
// This is the TLCP equivalent of http.ListenAndServeTLS.
func ListenAndServeTLCP(addr string, handler http.Handler, config *tlcp.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	return serveTLCP(ln, handler, config)
}

// ListenAndServeTLSNat starts an HTTP server using standard crypto/tls.
func ListenAndServeTLSNat(addr string, handler http.Handler, config *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	return serveTLS(ln, handler, config)
}

// Serve accepts incoming connections on the listener using the given options.
// This allows custom listener wrapping (e.g. for graceful shutdown).
func Serve(ln net.Listener, opts *ServerOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	mode := opts.DetectMode()
	wrapped, err := wrapListener(ln, opts, mode)
	if err != nil {
		return err
	}

	srv := buildHTTPServer(opts)
	return srv.Serve(wrapped)
}

// serveTLCP runs an HTTP server on a pre-wrapped TLCP listener.
//
// The 30s/120s timeouts are hardcoded for the convenience API. Callers
// needing custom timeouts should use ListenAndServe with ServerOptions
// (which exposes ReadTimeout/WriteTimeout/IdleTimeout fields), or
// construct an *http.Server directly.
func serveTLCP(ln net.Listener, handler http.Handler, config *tlcp.Config) error {
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	// http.Server.Serve closes the passed listener (tlcp.NewListener wraps
	// ln) when it returns — the caller must NOT also close ln.
	return srv.Serve(tlcp.NewListener(ln, config))
}

// serveTLS runs an HTTP server on a pre-wrapped standard TLS listener.
// See serveTLCP for the timeout/customization note.
func serveTLS(ln net.Listener, handler http.Handler, config *tls.Config) error {
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	// http.Server.Serve closes the passed listener (tls.NewListener wraps
	// ln) when it returns — the caller must NOT also close ln.
	return srv.Serve(tls.NewListener(ln, config))
}

func wrapListener(ln net.Listener, opts *ServerOptions, mode Mode) (net.Listener, error) {
	switch mode {
	case ModeTLCP:
		cfg, err := opts.buildTLCPConfig()
		if err != nil {
			return nil, err
		}
		return tlcp.NewListener(ln, cfg), nil

	case ModeTLS:
		cfg, err := opts.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		return tls.NewListener(ln, cfg), nil

	case ModeHybrid:
		tlcpCfg, err := opts.buildTLCPConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg, err := opts.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		return NewHybridListener(ln, tlcpCfg, tlsCfg), nil

	default:
		return nil, errMissingCertificate
	}
}

// Conservative server timeouts applied when the caller leaves the
// corresponding *time.Duration field nil. They match the values hardcoded by
// serveTLCP/serveTLS, keeping the ListenAndServe/Serve convenience path
// consistent and preventing Slowloris-style resource exhaustion from slow
// clients. Callers can opt out per-field via NoTimeout() (NOT recommended
// outside a reverse-proxy front-end).
const (
	defaultReadTimeout  = 30 * time.Second
	defaultWriteTimeout = 30 * time.Second
	defaultIdleTimeout  = 120 * time.Second
)

func buildHTTPServer(opts *ServerOptions) *http.Server {
	// *time.Duration pointer semantics:
	//   - nil           → conservative default (Slowloris protection)
	//   - non-nil zero  → explicitly no timeout (opt-out; risky)
	//   - non-nil value → use it
	// See ServerOptions docs and Duration()/NoTimeout() helpers.
	return &http.Server{
		Handler:      opts.Handler,
		ReadTimeout:  resolveTimeout(opts.ReadTimeout, defaultReadTimeout),
		WriteTimeout: resolveTimeout(opts.WriteTimeout, defaultWriteTimeout),
		IdleTimeout:  resolveTimeout(opts.IdleTimeout, defaultIdleTimeout),
	}
}

func (o *ServerOptions) validate() error {
	if o.Addr == "" {
		return errMissingAddr
	}
	return nil
}
