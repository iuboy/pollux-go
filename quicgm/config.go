package quicgm

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/sm3"
	"github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
)

const defaultIdleTimeout = 30 * time.Second

var (
	errNoServerCert = errors.New("quicgm: server Certificate and PrivateKey are required")
	errNoServerName = errors.New("quicgm: ServerName is required when not skipping verify")
)

// ServerConfig holds QUIC server configuration for the RFC 8998 GM stack
// (Route C). The server certificate must be an SM2 certificate; its private key
// signs CertificateVerify.
type ServerConfig struct {
	Addr               string
	Certificate        *x509.Certificate
	PrivateKey         *sm2.PrivateKey
	ClientCAs          *smx509.CertPool
	MaxIdleTimeout     time.Duration
	MaxIncomingStreams int64
	// SessionTicketKey optionally seeds the server's session-ticket encryption
	// key (TEK). If nil, the Listener generates a random TEK on startup. For
	// multi-replica deployments, inject the same key on every replica so tickets
	// issued by one are resumable on another. The Listener rotates the TEK over
	// time (current + previous) for forward secrecy.
	SessionTicketKey []byte
	// AllowEarlyData lets the server accept 0-RTT from resuming clients. It MUST
	// be paired with a non-nil AntiReplay; if AntiReplay is nil, 0-RTT is
	// rejected even when this is true (fail-safe).
	AllowEarlyData bool
	AntiReplay     AntiReplayCache
}

// ClientConfig holds QUIC client configuration for the RFC 8998 GM stack.
type ClientConfig struct {
	Addr               string
	ServerName         string
	Roots              *smx509.CertPool
	InsecureSkipVerify bool
	MaxIdleTimeout     time.Duration
	// ResumptionPSK is the resumption PSK the client derived from a prior
	// connection's NewSessionTicket (via the resumption master secret). It keys
	// the pre_shared_key binder and the 0-RTT early secret. Pair with
	// ResumptionIdentity and ResumptionObfuscatedTicketAge.
	ResumptionPSK []byte
	// ResumptionIdentity is the opaque pre_shared_key identity — the Ticket
	// field from a server NewSessionTicket (an encrypted stateless ticket). The
	// server decrypts it to recover the PSK; the client never uses it as a key.
	ResumptionIdentity []byte
	// ResumptionObfuscatedTicketAge is the obfuscated ticket age
	// (age + ticket_age_add) for the pre_shared_key identity.
	ResumptionObfuscatedTicketAge uint32
	// EarlyData, when true with ResumptionPSK, makes the client attempt 0-RTT
	// (the ClientHello carries early_data; early traffic keys are derived).
	EarlyData bool
}

func (c *ServerConfig) idleTimeout() time.Duration {
	if c.MaxIdleTimeout > 0 {
		return c.MaxIdleTimeout
	}
	return defaultIdleTimeout
}

func (c *ClientConfig) idleTimeout() time.Duration {
	if c.MaxIdleTimeout > 0 {
		return c.MaxIdleTimeout
	}
	return defaultIdleTimeout
}

// tls13ServerConfig builds the tls13gm server handshaker config. DCID and
// TransportParameters are filled by the QUIC transport (GMCryptoSetup), not here.
// ticketKeys returns the current TEK list (newest first) for stateless
// session-ticket encrypt/decrypt; the Listener owns TEK rotation.
func (c *ServerConfig) tls13ServerConfig(ticketKeys func() [][]byte) *tls13gm.ServerConfig {
	cfg := &tls13gm.ServerConfig{
		Certificate:       c.Certificate,
		PrivateKey:        c.PrivateKey,
		SessionTicketKeys: ticketKeys,
	}
	// AllowEarlyData is honored only when an anti-replay cache is configured
	// (fail-safe). PSK resumption itself works regardless of 0-RTT.
	allowEarly := c.AllowEarlyData && c.AntiReplay != nil
	cfg.AllowEarlyData = allowEarly
	if allowEarly {
		cache := c.AntiReplay
		cfg.EarlyDataAcceptor = func(psk []byte, realAge time.Duration) bool {
			// Digest the PSK so the raw key never becomes the cache map key, and
			// pass the reconstructed real ticket age so the cache can reject
			// expired/future tickets (RFC 8446 §8).
			digest := sm3.Sum(psk)
			return cache.Check(digest[:], realAge)
		}
	}
	return cfg
}

// tls13ClientConfig builds the tls13gm client handshaker config.
func (c *ClientConfig) tls13ClientConfig() (*tls13gm.ClientConfig, error) {
	if c.ServerName == "" && !c.InsecureSkipVerify {
		return nil, errNoServerName
	}
	return &tls13gm.ClientConfig{
		ServerName:                    c.ServerName,
		Roots:                         c.Roots,
		InsecureSkipVerify:            c.InsecureSkipVerify,
		ResumptionPSK:                 c.ResumptionPSK,
		ResumptionIdentity:            c.ResumptionIdentity,
		ResumptionObfuscatedTicketAge: c.ResumptionObfuscatedTicketAge,
		EarlyData:                     c.EarlyData,
	}, nil
}
