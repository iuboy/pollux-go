// Package http provides net/http-compatible helpers for serving HTTP over
// standard TLS, TLCP (national, GB/T 38636-2020), TLS 1.3, or a hybrid mode
// that accepts both TLS and TLCP on the same port.
//
// It produces standard *http.Server and *http.Transport instances, so it works
// with any Go HTTP framework (Gin, Echo, Chi) without adapter code.
//
// Status: HTTP helpers for TLS, TLCP, and TLS 1.3
package http
