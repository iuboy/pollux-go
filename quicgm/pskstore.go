package quicgm

import "sync"

// pskStore is a process-local registry of resumption PSKs a server has issued.
// It lets a stateful server accept PSK resumption (and 0-RTT) on a connection
// other than the one that issued the ticket: each GMCryptoSetup is per-
// connection, so the issued-PSK memory must outlive any single connection and
// be shared across them via the Listener.
//
// Single-process only. Multi-replica deployments must back this with a shared
// store (Redis, etc.), exactly like AntiReplayCache.
type pskStore struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

func newPSKStore() *pskStore { return &pskStore{seen: make(map[string]struct{})} }

// record stores a freshly issued PSK so a later lookup accepts it.
func (s *pskStore) record(psk []byte) {
	if len(psk) == 0 {
		return
	}
	s.mu.Lock()
	s.seen[string(psk)] = struct{}{}
	s.mu.Unlock()
}

// lookup resolves a client-offered identity to the PSK. In tls13gm the identity
// IS the PSK (carried verbatim in NewSessionTicket.Ticket), so a previously
// recorded PSK is returned as-is; unknown identities yield ok=false, after
// which the binder check still rejects them.
func (s *pskStore) lookup(identity []byte) ([]byte, bool) {
	s.mu.RLock()
	_, ok := s.seen[string(identity)]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return append([]byte(nil), identity...), true
}
