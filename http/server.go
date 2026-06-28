package http

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
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	ln, err = wrapListener(ln, opts, mode)
	if err != nil {
		return err
	}

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

func serveTLCP(ln net.Listener, handler http.Handler, config *tlcp.Config) error {
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.Serve(tlcp.NewListener(ln, config))
}

func serveTLS(ln net.Listener, handler http.Handler, config *tls.Config) error {
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
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

// Conservative server timeouts applied when the caller does not set them.
// They match the values hardcoded by serveTLCP/serveTLS, keeping the
// ListenAndServe/Serve convenience path consistent and preventing
// Slowloris-style resource exhaustion from slow clients.
const (
	defaultReadTimeout  = 30 * time.Second
	defaultWriteTimeout = 30 * time.Second
	defaultIdleTimeout  = 120 * time.Second
)

func buildHTTPServer(opts *ServerOptions) *http.Server {
	// Zero-valued durations mean "no timeout". Fill conservative defaults so
	// the main ListenAndServe/Serve path is not left unprotected, mirroring the
	// TLCP/TLS convenience servers. opts itself is not mutated.
	readTimeout := opts.ReadTimeout
	if readTimeout == 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := opts.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = defaultWriteTimeout
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}
	return &http.Server{
		Handler:      opts.Handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}

func (o *ServerOptions) validate() error {
	if o.Addr == "" {
		return errMissingAddr
	}
	return nil
}
