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
type tlcpSessionState struct {
	sessionID        []byte
	version          uint16
	cipherSuite      uint16
	masterSecret     []byte
	peerCertificates [][]byte // DER list, role-dependent (client sees server certs)
	createdAt        time.Time
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

func (c *tlcpLRUSessionCache) Get(sessionKey string) (*tlcpSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sessionKey == "" {
		// Empty key: return the most-recently used entry, if any.
		front := c.order.Front()
		if front == nil {
			return nil, false
		}
		return front.Value.(*tlcpLruEntry).cs, true
	}
	el, ok := c.m[sessionKey]
	if !ok || el == nil {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*tlcpLruEntry).cs, true
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
