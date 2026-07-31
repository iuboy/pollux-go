package tlcp

import (
	"container/list"
	"encoding/hex"
	"sync"
	"time"
)

// This file implements TLCP session-state caching for connection resumption
// (GB/T 38636-2020 §6.4.5.2.1). A successful full handshake stores a
// SessionState keyed by sessionId; a later ClientHello carrying that sessionId
// lets both sides skip Certificate/SKE/SHD/CKE and reuse the cached master
// secret, exchanging only ClientHello + ServerHello + Finished messages.
//
// Reference: gotlcp/tlcp/session.go (logic consulted, independently written).

// tlcpSessionState captures the resumption material from a full handshake.
// masterSecret is stored as a copy; the cache zeroes it on eviction.
//
// Concurrency note: tlcpLRUSessionCache.Get returns a *shallow copy* of the
// cached state (independent slice headers for masterSecret/peerCertificates),
// so a caller reading the returned state cannot race with a concurrent Put
// that zeroes the cached masterSecret on eviction. The copy is made under the
// cache lock; callers receive an independent object they own for the duration
// of the handshake.
type tlcpSessionState struct {
	sessionID        []byte
	version          uint16
	cipherSuite      uint16
	masterSecret     []byte
	peerCertificates [][]byte // DER list, role-dependent (client sees server certs)
	createdAt        time.Time
}

// clone returns a deep-enough copy of the state for safe handoff to a caller
// that may outlive the cache entry. masterSecret and peerCertificates get
// fresh backing arrays; scalar fields copy by value.
func (s *tlcpSessionState) clone() *tlcpSessionState {
	if s == nil {
		return nil
	}
	out := &tlcpSessionState{
		version:     s.version,
		cipherSuite: s.cipherSuite,
		createdAt:   s.createdAt,
	}
	out.sessionID = append([]byte(nil), s.sessionID...)
	out.masterSecret = append([]byte(nil), s.masterSecret...)
	if len(s.peerCertificates) > 0 {
		out.peerCertificates = make([][]byte, len(s.peerCertificates))
		for i, der := range s.peerCertificates {
			out.peerCertificates[i] = append([]byte(nil), der...)
		}
	}
	return out
}

// tlcpSessionCache is the contract for a session store. Implementations must be
// safe for concurrent use. A Get with the empty key returns the most-recently
// used session (LRU front); Put with a nil state deletes the entry.
type tlcpSessionCache interface {
	Get(sessionKey string) (*tlcpSessionState, bool)
	Put(sessionKey string, cs *tlcpSessionState)
}

// tlcpLRUSessionCache is a bounded LRU session cache. On eviction the evicted
// masterSecret is zeroed so it does not linger in memory.
type tlcpLRUSessionCache struct {
	mu    sync.Mutex
	m     map[string]*list.Element
	order *list.List
	cap   int
}

// NewTLCPLRUSessionCache returns an LRU session cache with the given capacity.
// A capacity < 1 defaults to 64.
func NewTLCPLRUSessionCache(capacity int) tlcpSessionCache {
	if capacity < 1 {
		capacity = 64
	}
	return &tlcpLRUSessionCache{
		m:     make(map[string]*list.Element),
		order: list.New(),
		cap:   capacity,
	}
}

type tlcpLruEntry struct {
	key string
	cs  *tlcpSessionState
}

// Get returns a *clone* of the cached session state (independent slice
// backing arrays), so the caller cannot race with a concurrent Put that
// zeroes the cached masterSecret on eviction. Callers receive an independent
// object they own for the duration of the handshake.
func (c *tlcpLRUSessionCache) Get(sessionKey string) (*tlcpSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sessionKey == "" {
		// Empty key: return the most-recently used entry, if any.
		front := c.order.Front()
		if front == nil {
			return nil, false
		}
		return front.Value.(*tlcpLruEntry).cs.clone(), true
	}
	el, ok := c.m[sessionKey]
	if !ok || el == nil {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*tlcpLruEntry).cs.clone(), true
}

func (c *tlcpLRUSessionCache) Put(sessionKey string, cs *tlcpSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs == nil {
		// Delete semantics.
		if el, ok := c.m[sessionKey]; ok {
			oldEntry := el.Value.(*tlcpLruEntry)
			zeroBytes(oldEntry.cs.masterSecret)
			c.order.Remove(el)
			delete(c.m, sessionKey)
		}
		return
	}
	if el, ok := c.m[sessionKey]; ok {
		oldEntry := el.Value.(*tlcpLruEntry)
		zeroBytes(oldEntry.cs.masterSecret)
		oldEntry.cs = cs
		c.order.MoveToFront(el)
		return
	}
	entry := &tlcpLruEntry{key: sessionKey, cs: cs}
	el := c.order.PushFront(entry)
	c.m[sessionKey] = el
	// Evict the least-recently used if over capacity.
	for c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		oldEntry := oldest.Value.(*tlcpLruEntry)
		c.order.Remove(oldest)
		delete(c.m, oldEntry.key)
		// Zero the evicted master secret so it does not linger.
		zeroBytes(oldEntry.cs.masterSecret)
	}
}

// tlcpSessionKeyHex returns the hex-encoded cache key for a sessionId.
func tlcpSessionKeyHex(sessionID []byte) string {
	return hex.EncodeToString(sessionID)
}

// sessionCacheKey returns the address-key under which a session is cached for
// resumption by peer identity. It binds both the remote address and the
// configured ServerName (SNI) so that a session established with one server
// identity is NOT reused against a different service sharing the same address
// (e.g. virtual hosts behind one IP, or NAT'd backends). TLS resumption
// deliberately does not re-verify the peer certificate, so the cache key must
// itself encode the identity the session was authenticated under; otherwise a
// resume to the same IP but a different/rotated certificate silently skips
// certificate verification (a cross-service identity-confusion risk).
//
// When serverName is empty the key degrades to the plain remote address to
// preserve backward compatibility for callers that do not set ServerName.
func sessionCacheKey(remoteAddr, serverName string) string {
	if serverName == "" {
		return remoteAddr
	}
	return serverName + "\x00" + remoteAddr
}
