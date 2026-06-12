package http

import (
	"crypto/tls"
	"crypto/x509"
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
			TLSClientConfig: cfg,
		},
	}
	if opts.Timeout > 0 {
		client.Timeout = opts.Timeout
	}
	return client, nil
}

// ListenAndServeTLS13 starts an HTTP server that only accepts TLS 1.3 connections.
func ListenAndServeTLS13(addr string, handler http.Handler, cfg *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.Serve(tls.NewListener(ln, cfg))
}
