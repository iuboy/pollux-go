package smx509

import (
	"crypto/x509"
	"encoding/pem"
	"sync"
)

// CertPool is a set of SM2-aware certificates that preserves raw DER bytes.
// Unlike x509.CertPool, it retains the original DER encoding so that
// certificates can be re-parsed with gmsm/smx509 without loss.
type CertPool struct {
	mu    sync.RWMutex
	certs []*x509.Certificate
	raw   [][]byte
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{}
}

// AddCert adds a certificate to the pool. It stores both the parsed
// certificate and its raw DER bytes.
func (p *CertPool) AddCert(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certs = append(p.certs, cert)
	der := make([]byte, len(cert.Raw))
	copy(der, cert.Raw)
	p.raw = append(p.raw, der)
}

// Certificates returns all certificates in the pool.
func (p *CertPool) Certificates() []*x509.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*x509.Certificate, len(p.certs))
	copy(out, p.certs)
	return out
}

// RawDER returns the raw DER bytes of all certificates in the pool.
func (p *CertPool) RawDER() [][]byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([][]byte, len(p.raw))
	for i, r := range p.raw {
		b := make([]byte, len(r))
		copy(b, r)
		out[i] = b
	}
	return out
}

// Len returns the number of certificates in the pool.
func (p *CertPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.certs)
}

// AppendCertsFromPEM parses PEM-encoded certificates and adds them to the pool.
// Returns true if at least one certificate was successfully parsed.
func (p *CertPool) AppendCertsFromPEM(pemData []byte) bool {
	ok := false
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
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
