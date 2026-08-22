package tlcp

import (
	"container/list"
	"encoding/hex"
	"strings"
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

// SessionState captures the resumption material from a full handshake.
// masterSecret is stored as a copy; the cache zeroes it on eviction.
//
// The fields are intentionally unexported (mirroring crypto/tls
// ClientSessionState): callers pass SessionState values through the
// [SessionCache] and must not inspect or forge resumption material.
//
// Concurrency note: lruSessionCache.Get returns a *shallow copy* of the
// cached state (independent slice headers for masterSecret/peerCertificates),
// so a caller reading the returned state cannot race with a concurrent Put
// that zeroes the cached masterSecret on eviction. The copy is made under the
// cache lock; callers receive an independent object they own for the duration
// of the handshake.
type SessionState struct {
	sessionID        []byte
	version          uint16
	cipherSuite      uint16
	masterSecret     []byte
	peerCertificates [][]byte // DER list, role-dependent (client sees server certs)
	createdAt        time.Time
}

// sessionLifetime bounds how long a cached session may be resumed. TLCP
// resumption skips certificate verification, so a long window extends the
// blast radius of a compromised master secret; 24h mirrors conservative TLS
// 1.2 session-ticket deployments (RFC 5077 caps at 7 days).
const sessionLifetime = 24 * time.Hour

// sessionFresh reports whether a cached session is still resumable. Expired
// sessions are ignored (never resumed) by both endpoints.
func sessionFresh(s *SessionState) bool {
	return s != nil && time.Since(s.createdAt) <= sessionLifetime
}

// clone returns a deep-enough copy of the state for safe handoff to a caller
// that may outlive the cache entry. masterSecret and peerCertificates get
// fresh backing arrays; scalar fields copy by value.
func (s *SessionState) clone() *SessionState {
	if s == nil {
		return nil
	}
	out := &SessionState{
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

// SessionCache is the contract for a TLCP session store used for connection
// resumption (GB/T 38636-2020 §6.4.5.2.1). Wire it into [Config.SessionCache]
// to enable resumption. Implementations must be safe for concurrent use.
// Put with a nil state deletes the entry. Entries expire after
// sessionLifetime; caches should treat old entries as opaque and may evict
// them at will (the engine re-checks freshness on every Get result).
type SessionCache interface {
	Get(sessionKey string) (*SessionState, bool)
	Put(sessionKey string, cs *SessionState)
}

// lruSessionCache is a bounded LRU session cache. On eviction the evicted
// masterSecret is zeroed so it does not linger in memory.
type lruSessionCache struct {
	mu    sync.Mutex
	m     map[string]*list.Element
	order *list.List
	cap   int
}

// NewLRUSessionCache returns an LRU session cache with the given capacity.
// A capacity < 1 defaults to 64.
func NewLRUSessionCache(capacity int) SessionCache {
	if capacity < 1 {
		capacity = 64
	}
	return &lruSessionCache{
		m:     make(map[string]*list.Element),
		order: list.New(),
		cap:   capacity,
	}
}

type lruEntry struct {
	key string
	cs  *SessionState
}

// Get returns a *clone* of the cached session state (independent slice
// backing arrays), so the caller cannot race with a concurrent Put that
// zeroes the cached masterSecret on eviction. Callers receive an independent
// object they own for the duration of the handshake.
func (c *lruSessionCache) Get(sessionKey string) (*SessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[sessionKey]
	if !ok || el == nil {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*lruEntry).cs.clone(), true
}

func (c *lruSessionCache) Put(sessionKey string, cs *SessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs == nil {
		// Delete semantics.
		if el, ok := c.m[sessionKey]; ok {
			oldEntry := el.Value.(*lruEntry)
			zeroBytes(oldEntry.cs.masterSecret)
			c.order.Remove(el)
			delete(c.m, sessionKey)
		}
		return
	}
	if el, ok := c.m[sessionKey]; ok {
		oldEntry := el.Value.(*lruEntry)
		zeroBytes(oldEntry.cs.masterSecret)
		oldEntry.cs = cs
		c.order.MoveToFront(el)
		return
	}
	entry := &lruEntry{key: sessionKey, cs: cs}
	el := c.order.PushFront(entry)
	c.m[sessionKey] = el
	// Evict the least-recently used if over capacity.
	for c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		oldEntry := oldest.Value.(*lruEntry)
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
// resumption by peer identity.
//
// When a ServerName (SNI) is configured, the key is the SNI alone: the server
// identity is the security-relevant binding (TLS resumption deliberately does
// not re-verify the peer certificate, so the cache key must encode the identity
// the session was authenticated under). Keying on the SNI — rather than the
// remote address — means a session established with one server identity is NOT
// reused against a different service, and is stable across reconnections that
// pick a different ephemeral source port.
//
// When serverName is empty the key degrades to the plain remote address,
// preserving backward compatibility for callers that do not set ServerName.
// This is inherently less stable (it depends on local port reuse) and less
// precise (it keys on transport address, not identity); callers that rely on
// resumption should set ServerName.
func sessionCacheKey(remoteAddr, serverName string) string {
	if serverName == "" {
		return remoteAddr
	}
	// RFC 6066: SNI 大小写不敏感——规范化避免 "Example.com" 与
	// "example.com" 形成两个缓存条目(复用失效 + 缓存碎片)。
	return "sni:" + strings.ToLower(serverName)
}
