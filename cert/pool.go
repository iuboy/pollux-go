package cert

import (
	"crypto/x509"
	"encoding/pem"
	"sync"

	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

// Pool is a thread-safe certificate pool that preserves raw DER bytes.
// It works for both standard X.509 and SM2 certificates.
type Pool struct {
	mu    sync.RWMutex
	certs []*x509.Certificate
	raw   [][]byte
}

// NewPool creates an empty certificate pool.
func NewPool() *Pool {
	return &Pool{}
}

// NewPoolFromCerts creates a pool from a list of certificates.
// Uses a single lock acquisition for all additions.
func NewPoolFromCerts(certs ...*x509.Certificate) *Pool {
	p := NewPool()
	p.AddCerts(certs...)
	return p
}

// AddCert adds a certificate to the pool. The certificate's raw DER is preserved.
func (p *Pool) AddCert(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certs = append(p.certs, cert)
	// Always append a matching raw entry to keep certs[i] / raw[i] in lock-step,
	// even when cert.Raw is empty (prevents positional desynchronization).
	rawCopy := make([]byte, len(cert.Raw))
	copy(rawCopy, cert.Raw)
	p.raw = append(p.raw, rawCopy)
}

// AddCerts adds multiple certificates to the pool in a single lock acquisition.
func (p *Pool) AddCerts(certs ...*x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		p.certs = append(p.certs, cert)
		rawCopy := make([]byte, len(cert.Raw))
		copy(rawCopy, cert.Raw)
		p.raw = append(p.raw, rawCopy)
	}
}

// AppendCertsFromPEM parses PEM-encoded certificates and adds them to the pool.
// Returns true if at least one certificate was successfully parsed.
//
// All successfully-parsed certificates are added in a single AddCerts call
// (one lock acquisition) rather than per-cert AddCert, avoiding repeated lock
// contention when the PEM carries a multi-cert chain.
//
// Silent-skip behavior: parse failures (both smx509 and stdlib reject the
// block) and non-CERTIFICATE PEM blocks (PRIVATE KEY, etc.) are silently
// skipped — the function returns only a bool, so a caller cannot tell from
// the return value whether any blocks were skipped. This matches
// x509.CertPool.AppendCertsFromPEM's contract (which also returns only bool)
// and is intentional for the pool-builder use case where a partial pool is
// acceptable. If you need to detect skipped blocks, use ParseCertificatesPEM
// (which returns a partial slice + error) or scan the PEM yourself before
// calling this.
func (p *Pool) AppendCertsFromPEM(pemData []byte) bool {
	var parsed []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		parsed = append(parsed, cert)
	}
	if len(parsed) > 0 {
		p.AddCerts(parsed...)
		return true
	}
	return false
}

// Certificates returns a copy of the certificate slice headers in the pool.
//
// Note: the copy is shallow — the returned []*x509.Certificate entries point
// at the same underlying *x509.Certificate objects the Pool holds. Callers
// MUST NOT mutate the returned certificates (e.g. setting cert.PublicKey);
// doing so would corrupt Pool state. The slice itself is independent, so
// appending to or reordering the returned slice is safe. If you need to
// mutate, deep-copy the entries first.
func (p *Pool) Certificates() []*x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*x509.Certificate, len(p.certs))
	copy(out, p.certs)
	return out
}

// RawDER returns the raw DER bytes for all certificates in the pool.
//
// The returned slice is fully independent: the outer slice header is a fresh
// copy, AND each inner []byte is freshly allocated and populated via copy, so
// mutating any returned entry (or the outer slice) has no effect on the
// Pool's internal state. This is a TRUE deep copy, unlike Certificates()
// (which is shallow — only the outer slice is copied, the *x509.Certificate
// pointers are shared). The deep copy is deliberate here because raw DER is
// often fed to gmsm/smx509 parsers that may retain the slice, and sharing
// the backing array would let a caller's later overwrite corrupt the parse.
func (p *Pool) RawDER() [][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([][]byte, len(p.raw))
	for i, r := range p.raw {
		out[i] = make([]byte, len(r))
		copy(out[i], r)
	}
	return out
}

// Len returns the number of certificates in the pool.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.certs)
}

// Clear removes all certificates from the pool.
func (p *Pool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certs = nil
	p.raw = nil
}

// ToStandardPool converts to a standard *x509.CertPool.
//
// Concurrency note: the returned *x509.CertPool shares the Pool's
// *x509.Certificate pointer entries (AddCert copies the pointer, not the
// underlying struct). This matches crypto/tls.Config.Clone's behavior for
// *CertPool. Callers MUST NOT mutate the certificates reachable from the
// returned pool; doing so would corrupt both the returned pool and the
// source Pool. If you need independent certificate objects, deep-copy the
// source Pool's Certificates() before converting.
func (p *Pool) ToStandardPool() *x509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pool := x509.NewCertPool()
	for _, cert := range p.certs {
		pool.AddCert(cert)
	}
	return pool
}

// ToSMX509Pool converts to an *smx509.CertPool (preserves raw DER for SM2 verification).
//
// Concurrency note: same shared-pointer caveat as ToStandardPool — the
// returned *smx509.CertPool's entries point at the same *x509.Certificate
// objects the source Pool holds. Mutating them corrupts both pools.
func (p *Pool) ToSMX509Pool() *polluxSmx509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pool := polluxSmx509.NewCertPool()
	for _, cert := range p.certs {
		pool.AddCert(cert)
	}
	return pool
}
