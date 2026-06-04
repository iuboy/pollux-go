package cert

import (
	"crypto/x509"
	"encoding/pem"
	"sync"

	polluxSmx509 "github.com/ycq/pollux/smx509"
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
func NewPoolFromCerts(certs ...*x509.Certificate) *Pool {
	p := NewPool()
	for _, c := range certs {
		p.AddCert(c)
	}
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
	if len(cert.Raw) > 0 {
		rawCopy := make([]byte, len(cert.Raw))
		copy(rawCopy, cert.Raw)
		p.raw = append(p.raw, rawCopy)
	}
}

// AppendCertsFromPEM parses PEM-encoded certificates and adds them to the pool.
// Returns true if at least one certificate was successfully parsed.
func (p *Pool) AppendCertsFromPEM(pemData []byte) bool {
	ok := false
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		p.AddCert(cert)
		ok = true
	}
	return ok
}

// Certificates returns a copy of the certificates in the pool.
func (p *Pool) Certificates() []*x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*x509.Certificate, len(p.certs))
	copy(out, p.certs)
	return out
}

// RawDER returns a copy of the raw DER bytes for all certificates in the pool.
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
func (p *Pool) ToSMX509Pool() *polluxSmx509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pool := polluxSmx509.NewCertPool()
	for _, cert := range p.certs {
		pool.AddCert(cert)
	}
	return pool
}
