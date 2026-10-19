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
	errEmptyALPN    = errors.New("quicgm: NextProtos is required (RFC 9001 §8.1 mandates ALPN for QUIC)")
)

// ServerConfig holds QUIC server configuration for the RFC 8998 GM stack
// (Route C). The server certificate must be an SM2 certificate; its private key
// signs CertificateVerify.
type ServerConfig struct {
	Addr string
	// Certificate is the server's leaf certificate. It MUST be an SM2
	// certificate (public key on the SM2 P256 curve); the GM handshake layer
	// rejects non-SM2 keys at tls13gm.NewServerHandshakerWithConfig. The
	// static type is the stdlib *x509.Certificate because Go's type system
	// cannot distinguish "SM2 cert" from "RSA/ECDSA cert" — smx509 and stdlib
	// share the same *x509.Certificate type. If you need compile-time SM2
	// enforcement, wrap the cert in a smx509-validated loader that rejects
	// non-SM2 keys before constructing ServerConfig.
	Certificate        *x509.Certificate
	PrivateKey         *sm2.PrivateKey
	ClientCAs          *smx509.CertPool
	MaxIdleTimeout     time.Duration
	MaxIncomingStreams int64
	// NextProtos is the server's ALPN protocol list. REQUIRED: RFC 9001 §8.1
	// mandates ALPN negotiation for QUIC (cross-protocol confusion protection);
	// Listen fails without it. The first client-offered protocol also present
	// here is negotiated.
	NextProtos []string
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
	// NextProtos is the client's ALPN protocol offer. REQUIRED: RFC 9001 §8.1
	// mandates ALPN negotiation for QUIC; Dial fails without it. The server
	// must select one of these or the handshake fails closed.
	NextProtos []string
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
	// (age + ticket_age_add) for the pre_shared_key identity. Compute it at
	// dial time via ObfuscatedTicketAge(ticketAgeAdd, elapsed-since-harvest);
	// passing the harvested ticketAgeAdd verbatim reports an age of ~0 and
	// defeats the server-side anti-replay/expiry age gate.
	ResumptionObfuscatedTicketAge uint32
	// ResumptionAppData is the server's transport parameters harvested with
	// the ticket (the serverParams value from Conn.SessionTicket). REQUIRED
	// for 0-RTT: EarlyData without it fails configuration — the client would
	// send 0-RTT under unknown flow-control limits (crypto/tls likewise
	// refuses 0-RTT without the session's saved parameters).
	ResumptionAppData []byte
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

// errNegativeConfig rejects silently-forwarded invalid transport knob values:
// a negative MaxIdleTimeout previously fell through the > 0 defaulting branch
// into quic.Config verbatim, and a negative MaxIncomingStreams likewise flowed
// into transport state — both only surfaced (if at all) deep in the stack.
var errNegativeConfig = errors.New("quicgm: MaxIdleTimeout and MaxIncomingStreams must not be negative")

// validateTransportKnobs is shared by the client and server config builders.
func validateTransportKnobs(idleTimeout time.Duration, maxIncomingStreams int64) error {
	if idleTimeout < 0 || maxIncomingStreams < 0 {
		return errNegativeConfig
	}
	return nil
}

// ObfuscatedTicketAge computes the value for ClientConfig.
// ResumptionObfuscatedTicketAge at dial time: per RFC 8446 §4.2.10 it is
// ticket_age_add + the milliseconds elapsed since the ticket was received.
// Harvesting returns the server's ticketAgeAdd, and the caller must add the
// elapsed time themselves — passing the harvested value verbatim reports an
// age of ~0, which defeats the server-side anti-replay/expiry age gate (the
// ticket's real age is then bounded only by the TEK rotation window).
func ObfuscatedTicketAge(ticketAgeAdd uint32, elapsed time.Duration) uint32 {
	ms := uint32(elapsed.Milliseconds())
	return ticketAgeAdd + ms
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
		NextProtos:        c.NextProtos,
	}
	// AllowEarlyData is honored only when an anti-replay cache is configured
	// (fail-safe). PSK resumption itself works regardless of 0-RTT.
	allowEarly := c.AllowEarlyData && c.AntiReplay != nil
	cfg.AllowEarlyData = allowEarly
	if allowEarly {
		cache := c.AntiReplay
		cfg.EarlyDataAcceptor = func(psk []byte, realAge time.Duration) bool {
			// Defense in depth: a nil PSK means the offered ticket was declined
			// by the server (tls13gm gates on this before calling the acceptor,
			// but a callback cannot tell how it was invoked). 0-RTT keys derived
			// from a zero PSK are publicly computable — never accept them.
			if psk == nil {
				return false
			}
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
	if err := validateTransportKnobs(c.MaxIdleTimeout, 0); err != nil {
		return nil, err
	}
	// RFC 9001 §8.1: ALPN is mandatory for QUIC — without a negotiated
	// application protocol a GM QUIC connection could be confused with any
	// other QUIC dialect sharing the wire. Fail closed at configuration time.
	if len(c.NextProtos) == 0 {
		return nil, errEmptyALPN
	}
	// 0-RTT requires a resumption PSK to key the early secret and binder;
	// without one the offer is meaningless and the handshake will fail or
	// behave undefinedly. Fail closed with a clear error instead.
	if c.EarlyData && len(c.ResumptionPSK) == 0 {
		return nil, errors.New("quicgm: EarlyData requires a non-empty ResumptionPSK")
	}
	// RFC 8446 §4.2.11: a client offering pre_shared_key MUST pair the PSK with
	// a non-empty opaque identity (the server-issued ticket). Reject the
	// misconfiguration early rather than letting the binder/transcript math
	// produce a malformed ClientHello.
	if c.EarlyData && len(c.ResumptionIdentity) == 0 {
		return nil, errors.New("quicgm: EarlyData requires a non-empty ResumptionIdentity (the server-issued ticket)")
	}
	// 0-RTT also requires the server's transport parameters harvested with
	// the ticket: they restore the flow-control limits the 0-RTT data must
	// respect, and the server's ValidFor0RTT gate rejects tickets whose saved
	// parameters no longer match. crypto/tls refuses 0-RTT without them too.
	if c.EarlyData && len(c.ResumptionAppData) == 0 {
		return nil, errors.New("quicgm: EarlyData requires ResumptionAppData (the serverParams harvested with the ticket)")
	}
	return &tls13gm.ClientConfig{
		ServerName:                    c.ServerName,
		Roots:                         c.Roots,
		InsecureSkipVerify:            c.InsecureSkipVerify,
		NextProtos:                    c.NextProtos,
		ResumptionPSK:                 c.ResumptionPSK,
		ResumptionIdentity:            c.ResumptionIdentity,
		ResumptionObfuscatedTicketAge: c.ResumptionObfuscatedTicketAge,
		ResumptionAppData:             c.ResumptionAppData,
		EarlyData:                     c.EarlyData,
	}, nil
}
