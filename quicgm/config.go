package quicgm

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/iuboy/pollux-go/sm2"
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
	// ResumptionPSK enables PSK resumption. It is the Ticket from a server
	// NewSessionTicket obtained on a prior connection.
	ResumptionPSK []byte
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
// store records issued PSKs and resolves them on resumption (shared across all
// connections accepted by one Listener).
func (c *ServerConfig) tls13ServerConfig(store *pskStore) *tls13gm.ServerConfig {
	cfg := &tls13gm.ServerConfig{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		// Record every issued PSK so a later connection can resume against it.
		OnPSKIssued: store.record,
		// Resolve a client-offered identity (== PSK) against the issued set.
		PSKLookup: store.lookup,
	}
	// AllowEarlyData is honored only when an anti-replay cache is configured
	// (fail-safe). PSK resumption itself works regardless of 0-RTT.
	allowEarly := c.AllowEarlyData && c.AntiReplay != nil
	cfg.AllowEarlyData = allowEarly
	if allowEarly {
		cache := c.AntiReplay
		cfg.EarlyDataAcceptor = func(psk []byte) bool {
			return cache.Check(psk, 0) // age 0: ticket-age tracking is a follow-up
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
		ServerName:                   c.ServerName,
		Roots:                        c.Roots,
		InsecureSkipVerify:           c.InsecureSkipVerify,
		ResumptionPSK:                c.ResumptionPSK,
		ResumptionObfuscatedTicketAge: c.ResumptionObfuscatedTicketAge,
	}, nil
}
