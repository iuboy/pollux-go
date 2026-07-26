// Package https provides net/http-compatible helpers for serving HTTP over
// standard TLS, TLCP (national, GB/T 38636-2020), TLS 1.3, or a hybrid mode
// that accepts both TLS and TLCP on the same port.
//
// The package is named https (not http) to avoid collision with the Go
// standard library's net/http at import sites — a long-standing design issue
// that forced every caller to write `import polluxhttp "github.com/iuboy/pollux-go/http"`.
// The v2 rename removes that ergonomic wart.
//
// It produces standard *http.Server and *http.Transport instances, so it works
// with any Go HTTP framework (Gin, Echo, Chi) without adapter code.
//
// Status: HTTP helpers for TLS, TLCP, and TLS 1.3
package https
