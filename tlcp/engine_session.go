package tlcp

import (
	"bytes"
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

// removeIfSession 仅当 sessionKey 处缓存的会话与 want 同源（sessionID 相同）
// 时删除该条目，返回是否实际删除。比较与删除在缓存锁内原子完成——并行连接
// 共享同一身份键（sni/addr）时，另一连接在「本会话读取之后、删除之前」写入
// 的新会话不会被误删（loss 仅一次重握手的无守卫版本已废弃）。删除时清零被
// 移除条目的 masterSecret（与 Put(nil)/淘汰的清理语义一致）。
func (c *lruSessionCache) removeIfSession(sessionKey string, want *SessionState) bool {
	if want == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[sessionKey]
	if !ok || el == nil {
		return false
	}
	cur := el.Value.(*lruEntry).cs
	if cur == nil || !bytes.Equal(cur.sessionID, want.sessionID) {
		return false // 键已被其他连接的新会话接管：不动
	}
	zeroBytes(cur.masterSecret)
	c.order.Remove(el)
	delete(c.m, sessionKey)
	return true
}

// tlcpSessionKeyHex returns the hex-encoded base for a sessionId cache key.
func tlcpSessionKeyHex(sessionID []byte) string {
	return hex.EncodeToString(sessionID)
}

// clientSessionKey 返回客户端角色的 sessionId 缓存键（"c:"+hex）。角色前缀
// 隔离客户端/服务端两套 sessionId 命名空间：共享缓存部署（同一 SessionCache
// 同时挂到 Config.SessionCache 两端）下，客户端按 hex 写入的会话不得被服务端
// 命中——两端 SessionState 语义相反（peerCertificates 方向、身份绑定不同），
// 跨角色命中会让一端以对端视角的会话状态恢复连接。
func clientSessionKey(sessionID []byte) string {
	return "c:" + tlcpSessionKeyHex(sessionID)
}

// serverSessionKey 返回服务端角色的 sessionId 缓存键（"s:"+hex），见
// clientSessionKey。
func serverSessionKey(sessionID []byte) string {
	return "s:" + tlcpSessionKeyHex(sessionID)
}

// sessionCacheKey 返回客户端按对端身份缓存会话所用的键。配置了 ServerName
// （SNI）时键为 "sni:"+规范化（小写）主机名：TLS resume 刻意不复验对端证书，
// 缓存键必须编码会话认证时的服务端身份——按 SNI 而非远端地址作键，一个服务
// 身份下建立的会话不会被复用于共享同 IP 的其他服务，且重连换临时源端口时键
// 保持稳定。RFC 6066：SNI 大小写不敏感——规范化避免 "Example.com" 与
// "example.com" 形成两个缓存条目（复用失效 + 缓存碎片）。
//
// serverName 为空时退化为 "addr:"+远端地址（调用方未设置 ServerName 的降级
// 面）：依赖本地端口复用，稳定性与精确度都更差，依赖 resume 的调用方应设置
// ServerName。"addr:"/"sni:" 前缀与 clientSessionKey/serverSessionKey 的
// "c:"/"s:" 风格统一，与 sessionId 键隔离命名空间——裸地址作键会与未来按身
// 份缓存的键共享同一字符串空间，存在跨命名空间碰撞面。
func sessionCacheKey(remoteAddr, serverName string) string {
	if serverName == "" {
		return "addr:" + remoteAddr
	}
	return "sni:" + strings.ToLower(serverName)
}
