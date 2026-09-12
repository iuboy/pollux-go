package https

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/iuboy/pollux-go/tls13"
)

// TLS13ServerOptions holds configuration for an HTTP server enforcing TLS 1.3.
type TLS13ServerOptions struct {
	Addr         string
	Handler      http.Handler
	Certificates []tls.Certificate
	ClientCAs    *x509.CertPool
	ClientAuth   tls.ClientAuthType
	NextProtos   []string
}

// TLS13ClientOptions holds configuration for an HTTP client enforcing TLS 1.3.
type TLS13ClientOptions struct {
	ServerName         string
	RootCAs            *x509.CertPool
	Certificates       []tls.Certificate
	NextProtos         []string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// NewTLS13Server creates an *http.Server that only accepts TLS 1.3 connections.
func NewTLS13Server(opts TLS13ServerOptions) (*http.Server, error) {
	cfg, err := tls13.ServerConfig(tls13.ServerOptions{
		Certificates: opts.Certificates,
		ClientCAs:    opts.ClientCAs,
		ClientAuth:   opts.ClientAuth,
		NextProtos:   opts.NextProtos,
	})
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:         opts.Addr,
		Handler:      opts.Handler,
		TLSConfig:    cfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}, nil
}

// NewTLS13Client creates an *http.Client that only connects with TLS 1.3.
func NewTLS13Client(opts TLS13ClientOptions) (*http.Client, error) {
	cfg, err := tls13.ClientConfig(tls13.ClientOptions{
		ServerName:         opts.ServerName,
		RootCAs:            opts.RootCAs,
		Certificates:       opts.Certificates,
		NextProtos:         opts.NextProtos,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       cfg,
			TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
			IdleConnTimeout:       defaultIdleConnTimeout,
			ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		},
	}
	// A zero Timeout leaves requests unlimited; the convenience constructor
	// applies the package default unless the caller opts out with an explicit
	// zero/negative-free choice (Timeout > 0 required to override).
	if opts.Timeout > 0 {
		client.Timeout = opts.Timeout
	} else {
		client.Timeout = defaultClientTimeout
	}
	return client, nil
}

// ListenAndServeTLS13 starts an HTTP server that only accepts TLS 1.3 connections.
//
// cfg may be nil (a TLS 1.3-only config is created) or a caller-supplied
// *tls.Config (which is cloned, never mutated). The MinVersion is forced up to
// TLS 1.3 regardless of the caller's setting so the function name's contract
// holds; if a caller-supplied MaxVersion is lower than TLS 1.3 the call fails
// fast with a clear error rather than producing an unsatisfiable Min>Max range.
func ListenAndServeTLS13(addr string, handler http.Handler, cfg *tls.Config) error {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		// Clone to avoid mutating caller-owned config.
		cfg = cfg.Clone()
	}
	cfg.MinVersion = tls.VersionTLS13
	// Reject a caller-supplied MaxVersion that conflicts with the forced TLS 1.3
	// floor. A MaxVersion < TLS 1.3 leaves MinVersion > MaxVersion, which makes
	// the subsequent TLS handshake fail with a cryptic error. Fail fast with a
	// clear message instead.
	if cfg.MaxVersion != 0 && cfg.MaxVersion < cfg.MinVersion {
		return errors.New("https: TLS 1.3 floor conflicts with caller-supplied MaxVersion (lower than TLS 1.3)")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// No defer ln.Close() here: http.Server.Serve closes the listener it is
	// handed (tls.NewListener wraps ln and propagates Close), so an extra
	// defer would double-close ln — the same invariant documented on
	// ListenAndServe/serveTLS in server.go.

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.Serve(tls.NewListener(ln, cfg))
}
