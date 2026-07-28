// Package http is a deprecated alias for [github.com/iuboy/pollux-go/https].
//
// This package exists solely to give downstream code a deprecation window
// after the v2 rename from `http` to `https` (the rename avoids a name clash
// with the Go standard library's net/http at import sites). The shim
// re-exports the public API of `https` via type aliases and wrapper
// functions so existing imports keep compiling, but every use will surface
// a deprecation notice via staticcheck SA1019 (since Go 1.18, references to
// deprecated package-level identifiers emit build warnings).
//
// Migration: replace every
//
//	import polluxhttp "github.com/iuboy/pollux-go/http"
//
// with
//
//	import "github.com/iuboy/pollux-go/https"
//
// and update the `polluxhttp.` prefixes to `https.`. The API surface is
// identical aside from the package name.
//
// This shim will be removed in the next minor release after v2.0.
package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	newpkg "github.com/iuboy/pollux-go/https"
	polluxTLS "github.com/iuboy/pollux-go/tlcp"
)

// Type aliases (zero-cost, identity at the type system level).
type (
	// Deprecated: use github.com/iuboy/pollux-go/https.ServerOptions
	ServerOptions = newpkg.ServerOptions
	// Deprecated: use github.com/iuboy/pollux-go/https.ClientOptions
	ClientOptions = newpkg.ClientOptions
	// Deprecated: use github.com/iuboy/pollux-go/https.Mode
	Mode = newpkg.Mode
	// Deprecated: use github.com/iuboy/pollux-go/https.ProtocolMask
	ProtocolMask = newpkg.ProtocolMask
)

// Constants re-export.
const (
	// Deprecated: use github.com/iuboy/pollux-go/https.ModeTLS
	ModeTLS = newpkg.ModeTLS
	// Deprecated: use github.com/iuboy/pollux-go/https.ModeTLCP
	ModeTLCP = newpkg.ModeTLCP
	// Deprecated: use github.com/iuboy/pollux-go/https.ModeHybrid
	ModeHybrid = newpkg.ModeHybrid
)

// Function re-exports. These are thin wrappers because Go does not support
// function aliases — only type aliases. Each one delegates to the new
// package's implementation.

// Deprecated: use github.com/iuboy/pollux-go/https.ListenAndServe
func ListenAndServe(opts *ServerOptions) error { return newpkg.ListenAndServe(opts) }

// Deprecated: use github.com/iuboy/pollux-go/https.ListenAndServeTLCP
func ListenAndServeTLCP(addr string, handler http.Handler, config *polluxTLS.Config) error {
	return newpkg.ListenAndServeTLCP(addr, handler, config)
}

// Deprecated: use github.com/iuboy/pollux-go/https.ListenAndServeTLSNat
func ListenAndServeTLSNat(addr string, handler http.Handler, config *tls.Config) error {
	return newpkg.ListenAndServeTLSNat(addr, handler, config)
}

// Deprecated: use github.com/iuboy/pollux-go/https.Serve
func Serve(ln net.Listener, opts *ServerOptions) error { return newpkg.Serve(ln, opts) }

// Deprecated: use github.com/iuboy/pollux-go/https.NewClient
func NewClient(opts *ClientOptions) (*http.Client, error) { return newpkg.NewClient(opts) }

// Deprecated: use github.com/iuboy/pollux-go/https.NewTLCPTransport
func NewTLCPTransport(config *polluxTLS.Config) (*http.Transport, error) {
	return newpkg.NewTLCPTransport(config)
}

// Deprecated: use github.com/iuboy/pollux-go/https.NewTLSTransport
func NewTLSTransport(config *tls.Config) *http.Transport {
	return newpkg.NewTLSTransport(config)
}

// Deprecated: use github.com/iuboy/pollux-go/https.DetectMode
func DetectMode(signCert *tls.Certificate) Mode { return newpkg.DetectMode(signCert) }

// Deprecated: use github.com/iuboy/pollux-go/https.DefaultProtocolMask
func DefaultProtocolMask() ProtocolMask { return newpkg.DefaultProtocolMask() }

// Deprecated: use github.com/iuboy/pollux-go/https.Duration
func Duration(d time.Duration) *time.Duration { return newpkg.Duration(d) }

// Deprecated: use github.com/iuboy/pollux-go/https.NoTimeout
func NoTimeout() *time.Duration { return newpkg.NoTimeout() }

// TLS 1.3 helpers (NewTLS13Server/NewTLS13Client/ListenAndServeTLS13) and
// their option structs.

// Deprecated: use github.com/iuboy/pollux-go/https.TLS13ServerOptions
type TLS13ServerOptions = newpkg.TLS13ServerOptions

// Deprecated: use github.com/iuboy/pollux-go/https.TLS13ClientOptions
type TLS13ClientOptions = newpkg.TLS13ClientOptions

// Deprecated: use github.com/iuboy/pollux-go/https.NewTLS13Server
func NewTLS13Server(opts TLS13ServerOptions) (*http.Server, error) {
	return newpkg.NewTLS13Server(opts)
}

// Deprecated: use github.com/iuboy/pollux-go/https.NewTLS13Client
func NewTLS13Client(opts TLS13ClientOptions) (*http.Client, error) {
	return newpkg.NewTLS13Client(opts)
}

// Deprecated: use github.com/iuboy/pollux-go/https.ListenAndServeTLS13
func ListenAndServeTLS13(addr string, handler http.Handler, config *tls.Config) error {
	return newpkg.ListenAndServeTLS13(addr, handler, config)
}
