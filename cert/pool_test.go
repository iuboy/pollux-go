package cert

import (
	"crypto/x509"
	"sync"
	"testing"
)

// TestPool_AddCerts_Batch verifies batch addition skips nil entries in a single
// lock acquisition.
func TestPool_AddCerts_Batch(t *testing.T) {
	c1, _ := generateTestCert(t)
	c2, _ := generateTestCert(t)
	pool := NewPool()
	pool.AddCerts(c1, nil, c2, nil)
	if pool.Len() != 2 {
		t.Errorf("expected 2 certs (nil skipped), got %d", pool.Len())
	}
}

// TestPool_Concurrent stresses the RWMutex: concurrent writers must not race
// (run with -race) and the final length must match the number of additions.
func TestPool_Concurrent(t *testing.T) {
	const n = 50
	certs := make([]*x509.Certificate, n)
	for i := range certs {
		certs[i], _ = generateTestCert(t)
	}
	pool := NewPool()

	var wg sync.WaitGroup
	wg.Add(n)
	for _, c := range certs {
		go func(cert *x509.Certificate) {
			defer wg.Done()
			pool.AddCert(cert)
		}(c)
	}
	wg.Wait()

	if pool.Len() != n {
		t.Errorf("expected %d certs, got %d", n, pool.Len())
	}
	// Concurrent reads after writes.
	var rwg sync.WaitGroup
	rwg.Add(2)
	go func() { defer rwg.Done(); _ = pool.Certificates() }()
	go func() { defer rwg.Done(); _ = pool.RawDER() }()
	rwg.Wait()
}

// TestPool_Clear verifies Clear empties both the certificate and raw-DER slices.
func TestPool_Clear(t *testing.T) {
	c1, _ := generateTestCert(t)
	c2, _ := generateTestCert(t)
	pool := NewPoolFromCerts(c1, c2)
	if pool.Len() != 2 {
		t.Fatalf("setup: expected 2, got %d", pool.Len())
	}
	pool.Clear()
	if pool.Len() != 0 {
		t.Errorf("expected 0 after Clear, got %d", pool.Len())
	}
	if len(pool.RawDER()) != 0 {
		t.Error("RawDER should be empty after Clear")
	}
}

// TestPool_Conversions verifies both pool conversions round-trip the certs.
func TestPool_Conversions(t *testing.T) {
	c1, _ := generateTestCert(t)
	c2, _ := generateTestCert(t)
	pool := NewPoolFromCerts(c1, c2)
	// ToStandardPool must yield a usable standard pool: c1 verifies against it.
	if _, err := c1.Verify(x509.VerifyOptions{Roots: pool.ToStandardPool()}); err != nil {
		t.Errorf("c1 should verify against ToStandardPool: %v", err)
	}
	if got := pool.ToSMX509Pool().Len(); got != 2 {
		t.Errorf("ToSMX509Pool len = %d, want 2", got)
	}
}
