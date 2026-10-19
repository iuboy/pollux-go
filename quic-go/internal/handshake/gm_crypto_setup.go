// gm_crypto_setup.go implements the CryptoSetup interface (interface.go) using
// pollux-go's tls13gm TLS 1.3 GM handshake engine. It is the Route C counterpart
// to crypto_setup.go (which wraps crypto/tls's tls.QUICConn): instead of a
// tls.QUICConn it drives a tls13gm.ClientHandshaker / ServerHandshaker, maps the
// derived HandshakeSecrets to the sealer/opener adapters in gm_sealer.go, and
// surfaces handshake progress as the Event sequence quic-go's connection layer
// expects (see connection.go handleHandshakeEvents).
//
// P0 scope: 1-RTT only. No HRR, PSK, 0-RTT, session resumption, or key update.
// Get0RTTSealer/Opener and GetSessionTicket return "not available"; key phase is
// fixed; SetLargest1RTTAcked is a no-op. P1–P3 fill those in.

package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/iuboy/pollux-go/tls13gm"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// GMCryptoSetup drives an RFC 8998 GM TLS 1.3 handshake for a QUIC connection.
// It implements CryptoSetup.
type GMCryptoSetup struct {
	perspective protocol.Perspective
	version     protocol.Version
	logger      utils.Logger

	// Exactly one of these is non-nil, matching the perspective.
	clientHs *tls13gm.ClientHandshaker
	serverHs *tls13gm.ServerHandshaker

	// ourParams is the local transport parameters, already injected into the
	// handshaker's ClientHello/EncryptedExtensions at construction time.
	ourParams *wire.TransportParameters

	events []Event

	// clientSessionIdentity / clientSessionPSK / clientTicketAgeAdd cache the
	// opaque ticket identity, the derived PSK, and ticket_age_add from the last
	// NewSessionTicket received (1-RTT post-handshake), so the application can
	// reuse them for a resumption / 0-RTT attempt.
	clientSessionIdentity []byte
	clientSessionPSK      []byte
	clientTicketAgeAdd    uint32
	// peerParamsRaw is the server's marshaled QUIC transport parameters from
	// EncryptedExtensions (client side). It is forwarded with the harvested
	// ticket so the application can restore the server's 0-RTT limits on the
	// next connection (tls13gm.ResumptionAppData round-trip).
	peerParamsRaw []byte
	// restoredParamsRaw is the server's transport parameters harvested with
	// the resumption ticket (clientCfg.ResumptionAppData). When 0-RTT keys
	// exist it is restored via EventRestoredTransportParameters.
	restoredParamsRaw []byte
	// onClientSessionTicket, when non-nil, is invoked once per freshly received
	// NewSessionTicket (client side only), delivering the identity, the derived
	// PSK, ticket_age_add, and the server's transport parameters to the
	// application.
	onClientSessionTicket func(identity, psk []byte, ticketAgeAdd uint32, serverParams []byte)

	// Packet-protection codecs, populated lazily as keys become available.
	initialSealer   LongHeaderSealer
	initialOpener   LongHeaderOpener
	handshakeSealer LongHeaderSealer
	handshakeOpener LongHeaderOpener
	// zeroRTTSealer/zeroRTTOpener cache the 0-RTT codecs. They were formerly
	// rebuilt on every Get call, resetting the opener's highestRcvdPN per
	// packet: 1/2-byte truncated packet numbers then decoded against a zero
	// baseline, the reconstructed header no longer matched the AEAD AAD, and
	// 0-RTT packets silently failed decryption once the peer's PN exceeded
	// the truncation window (upstream caches zeroRTTOpener likewise).
	// Guarded by stateMutex (get-or-build from the packet-handling goroutine).
	zeroRTTSealer LongHeaderSealer
	zeroRTTOpener LongHeaderOpener
	oneRTTAEAD    *gmUpdatableAEAD

	initialDropped   bool
	handshakeDropped bool
	handshakeDone    bool

	// stateMutex guards the fields application goroutines read via
	// ConnectionState / ClientSessionTicket against the handshake goroutine's
	// writes inside HandleMessage / StartHandshake (tls13gm handshakers carry
	// no internal locks, unlike crypto/tls's mutex-protected ConnectionState).
	// The events slice and the packet codecs stay single-goroutine (the
	// connection's run loop drives HandleMessage and NextEvent).
	stateMutex sync.Mutex
}

var _ CryptoSetup = &GMCryptoSetup{}

// NewGMCryptoSetupClient builds a client-side GMCryptoSetup. clientCfg supplies
// the TLS configuration (server name, roots, …); its DCID and TransportParameters
// fields are overwritten with connID and the marshaled tp. tp carries the QUIC
// transport parameters advertised in the ClientHello.
func NewGMCryptoSetupClient(
	connID protocol.ConnectionID,
	clientCfg *tls13gm.ClientConfig,
	tp *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
	onClientSessionTicket func(identity, psk []byte, ticketAgeAdd uint32, serverParams []byte),
) (*GMCryptoSetup, error) {
	if clientCfg == nil {
		return nil, fmt.Errorf("handshake: GM client config is required")
	}
	cfg := *clientCfg
	cfg.DCID = connID.Bytes()
	if tp != nil {
		cfg.TransportParameters = tp.Marshal(protocol.PerspectiveClient)
	}
	hs, err := tls13gm.NewClientHandshakerWithConfig(cfg)
	if err != nil {
		return nil, err
	}
	g := &GMCryptoSetup{
		perspective:           protocol.PerspectiveClient,
		version:               version,
		logger:                logger,
		clientHs:              hs,
		ourParams:             tp,
		events:                make([]Event, 0, 8),
		onClientSessionTicket: onClientSessionTicket,
		restoredParamsRaw:     clientCfg.ResumptionAppData,
	}
	if err := g.initInitialKeys(hs.Secrets()); err != nil {
		return nil, err
	}
	return g, nil
}

// NewGMCryptoSetupServer builds a server-side GMCryptoSetup. serverCfg supplies
// the server certificate and key; its DCID and TransportParameters fields are
// overwritten. tp is advertised in EncryptedExtensions. allow0RTT is the
// quic.Config-level early-data admission switch: it is ANDed into the
// tls13gm-level AllowEarlyData so the two knobs cannot disagree (a GM server
// must not accept 0-RTT that the transport-level config forbids, and the
// EncryptedExtensions early_data echo follows the same gate).
func NewGMCryptoSetupServer(
	connID protocol.ConnectionID,
	serverCfg *tls13gm.ServerConfig,
	tp *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
	allow0RTT bool,
) (*GMCryptoSetup, error) {
	if serverCfg == nil {
		return nil, fmt.Errorf("handshake: GM server config is required")
	}
	cfg := *serverCfg
	cfg.DCID = connID.Bytes()
	if tp != nil {
		cfg.TransportParameters = tp.Marshal(protocol.PerspectiveServer)
	}
	cfg.AllowEarlyData = cfg.AllowEarlyData && allow0RTT
	hs, err := tls13gm.NewServerHandshakerWithConfig(cfg)
	if err != nil {
		return nil, err
	}
	g := &GMCryptoSetup{
		perspective: protocol.PerspectiveServer,
		version:     version,
		logger:      logger,
		serverHs:    hs,
		ourParams:   tp,
		events:      make([]Event, 0, 8),
	}
	if err := g.initInitialKeys(hs.Secrets()); err != nil {
		return nil, err
	}
	return g, nil
}

// initInitialKeys builds the Initial-level sealer/opener from the keys the
// handshaker derived at construction time (seeded by the DCID).
func (g *GMCryptoSetup) initInitialKeys(secrets tls13gm.HandshakeSecrets) error {
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	if g.perspective == protocol.PerspectiveClient {
		sealKeys, openKeys = secrets.ClientInitialKeys, secrets.ServerInitialKeys
	} else {
		sealKeys, openKeys = secrets.ServerInitialKeys, secrets.ClientInitialKeys
	}
	sealer, err := newGMLongSealer(sealKeys)
	if err != nil {
		return err
	}
	opener, err := newGMLongOpener(openKeys)
	if err != nil {
		return err
	}
	g.initialSealer, g.initialOpener = sealer, opener
	return nil
}

func (g *GMCryptoSetup) enqueue(ev Event) { g.events = append(g.events, ev) }

// StartHandshake kicks off the handshake. The client emits its ClientHello as
// EventWriteInitialData; the server waits for the peer's ClientHello. It returns
// immediately — the connection layer drains events via NextEvent.
func (g *GMCryptoSetup) StartHandshake(_ context.Context) error {
	// The whole handshake-driving entry points serialize on stateMutex so
	// ConnectionState (application goroutines) never observes mid-write
	// handshaker fields; see the field comment.
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	if g.perspective == protocol.PerspectiveClient {
		ch, err := g.clientHs.ClientHello()
		if err != nil {
			return fmt.Errorf("handshake: GM ClientHello: %w", err)
		}
		g.enqueue(Event{Kind: EventWriteInitialData, Data: ch})
		// 0-RTT (upstream cryptoSetup.StartHandshake contract): only when the
		// client holds BOTH the 0-RTT keys (PSK + early_data) and the server's
		// transport parameters saved with the ticket. The event restores the
		// peer's parameters and releases DialEarly's early connection. Without
		// saved parameters there is no safe 0-RTT — the client would send
		// under unknown flow-control limits — so the 0-RTT keys are dropped
		// and the handshake completes at 1-RTT.
		if g.clientHs.Secrets().ClientEarlyKeys != nil {
			if params, ok := g.parseRestoredParams(); ok {
				g.enqueue(Event{Kind: EventRestoredTransportParameters, TransportParameters: params})
			} else {
				g.clientHs.DiscardEarlyKeys()
				g.discard0RTTCodecs()
			}
		}
	}
	return nil
}

// parseRestoredParams unmarshals the server transport parameters saved with
// the resumption ticket. ok is false when none were saved or they no longer
// parse.
func (g *GMCryptoSetup) parseRestoredParams() (*wire.TransportParameters, bool) {
	if len(g.restoredParamsRaw) == 0 {
		return nil, false
	}
	var tp wire.TransportParameters
	if err := tp.Unmarshal(g.restoredParamsRaw, protocol.PerspectiveServer); err != nil {
		g.logger.Errorf("GM 0-RTT: saved transport parameters no longer parse, declining 0-RTT: %v", err)
		return nil, false
	}
	return &tp, true
}

// savedParamsValidFor0RTT reports whether the transport parameters saved in
// the resuming client's ticket are still valid for 0-RTT under the server's
// current parameters (upstream handleSessionTicket's ValidFor0RTT gate).
// Tickets without saved parameters (issued by a pre-upgrade server or a
// non-QUIC issuer) fail closed: 0-RTT under unknown historical limits is not
// admissible.
func (g *GMCryptoSetup) savedParamsValidFor0RTT() bool {
	saved := g.serverHs.ResumptionAppData()
	if len(saved) == 0 {
		g.logger.Debugf("GM 0-RTT: ticket carries no saved transport parameters, rejecting 0-RTT")
		return false
	}
	var savedTP wire.TransportParameters
	if err := savedTP.Unmarshal(saved, protocol.PerspectiveServer); err != nil {
		g.logger.Debugf("GM 0-RTT: saved transport parameters do not parse, rejecting 0-RTT: %v", err)
		return false
	}
	if !g.ourParams.ValidFor0RTT(&savedTP) {
		g.logger.Debugf("GM 0-RTT: transport parameters changed since the ticket was issued, rejecting 0-RTT")
		return false
	}
	return true
}

// HandleMessage feeds reassembled CRYPTO-stream bytes to the tls13gm handshaker.
// The data may carry several concatenated handshake messages; each is split out
// and dispatched by (perspective, encryption level, message type). Handshake
// progress produces Events consumed later by the connection layer.
func (g *GMCryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	for len(data) > 0 {
		msgType, _, n, err := tls13gm.ReadHandshakeMessage(data)
		if err != nil {
			return fmt.Errorf("handshake: GM parse message at %s: %w", encLevel, err)
		}
		msg := append([]byte(nil), data[:n]...) // copy: tls13gm may retain slices
		data = data[n:]
		if err := g.handleOneMessage(msgType, msg, encLevel); err != nil {
			return err
		}
	}
	return nil
}

func (g *GMCryptoSetup) handleOneMessage(msgType uint8, msg []byte, encLevel protocol.EncryptionLevel) error {
	if g.perspective == protocol.PerspectiveClient {
		return g.handleOneClient(msgType, msg, encLevel)
	}
	return g.handleOneServer(msgType, msg, encLevel)
}

func (g *GMCryptoSetup) handleOneClient(msgType uint8, msg []byte, encLevel protocol.EncryptionLevel) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		if msgType != tls13gm.HandshakeTypeServerHello {
			return fmt.Errorf("handshake: GM unexpected Initial message type %d", msgType)
		}
		if err := g.clientHs.HandleServerHello(msg); err != nil {
			if errors.Is(err, tls13gm.ErrHelloRetryRequest) {
				// Server sent a HelloRetryRequest (RFC 8446 §4.1.4): produce
				// ClientHello2 (carrying the echoed cookie) and resend it on the
				// Initial stream. The real ServerHello follows in another
				// HandleMessage call.
				hadEarlyKeys := g.clientHs.Secrets().ClientEarlyKeys != nil
				ch2, hrrErr := g.clientHs.HandleHelloRetryRequest(msg)
				if hrrErr != nil {
					return hrrErr
				}
				// RFC 8446 §4.2.10: 0-RTT offered with CH1 is dead after an
				// HRR (HandleHelloRetryRequest withdraws the offer and drops
				// the keys). If the client had already sealed 0-RTT data,
				// drop the level so the connection resets the 0-RTT streams
				// instead of silently retransmitting them at 1-RTT.
				if hadEarlyKeys {
					g.enqueue(Event{Kind: EventDiscard0RTTKeys})
				}
				g.enqueue(Event{Kind: EventWriteInitialData, Data: ch2})
				return nil
			}
			return err
		}
		return g.installHandshakeKeys(g.clientHs.Secrets())
	case protocol.EncryptionHandshake:
		switch msgType {
		case tls13gm.HandshakeTypeEncryptedExtensions:
			if err := g.clientHs.HandleEncryptedExtensions(msg); err != nil {
				return err
			}
			// 0-RTT rejection: the client offered early data (PSK + early_data)
			// but the server did not echo early_data in EncryptedExtensions.
			// Discard the 0-RTT keys so the connection drops the 0-RTT
			// encryption level and resets the 0-RTT streams (applications see
			// Err0RTTRejected); without this the 0-RTT stream data is silently
			// retransmitted at 1-RTT and the dialer never learns it was
			// rejected.
			if g.clientHs.EarlyDataOffered() && !g.clientHs.EarlyDataAccepted() {
				g.clientHs.DiscardEarlyKeys()
				g.discard0RTTCodecs()
				g.enqueue(Event{Kind: EventDiscard0RTTKeys})
			}
			return g.emitPeerTransportParameters(g.clientHs.PeerTransportParams())
		case tls13gm.HandshakeTypeCertificate:
			return g.clientHs.HandleCertificate(msg)
		case tls13gm.HandshakeTypeCertificateVerify:
			return g.clientHs.HandleCertificateVerify(msg)
		case tls13gm.HandshakeTypeFinished:
			if err := g.clientHs.HandleServerFinished(msg); err != nil {
				return err
			}
			return g.completeClientFlight()
		default:
			return fmt.Errorf("handshake: GM unexpected Handshake message type %d", msgType)
		}
	case protocol.Encryption1RTT:
		// Post-handshake messages on the 1-RTT stream. The only one the GM
		// server currently sends is NewSessionTicket; accept it (the client
		// surfaces the PSK via the CRYPTO stream for the application to cache).
		switch msgType {
		case tls13gm.HandshakeTypeNewSessionTicket:
			identity, psk, ageAdd, err := g.clientHs.HandleNewSessionTicket(msg[4:])
			if err != nil {
				return fmt.Errorf("handshake: GM process NewSessionTicket: %w", err)
			}
			g.clientSessionIdentity = identity
			g.clientSessionPSK = psk
			g.clientTicketAgeAdd = ageAdd
			if g.onClientSessionTicket != nil {
				g.onClientSessionTicket(identity, psk, ageAdd, g.peerParamsRaw)
			}
			return nil
		default:
			return fmt.Errorf("handshake: GM unexpected 1-RTT message type %d", msgType)
		}
	default:
		return fmt.Errorf("handshake: GM client received message at unexpected level %s", encLevel)
	}
}

// completeClientFlight finalizes the client side after the server Finished:
// install 1-RTT keys, emit the client Finished, and signal completion.
func (g *GMCryptoSetup) completeClientFlight() error {
	if err := g.install1RTTKeys(g.clientHs.Secrets()); err != nil {
		return err
	}
	cf, err := g.clientHs.ClientFinished()
	if err != nil {
		return err
	}
	g.enqueue(Event{Kind: EventWriteHandshakeData, Data: cf})
	g.handshakeDone = true
	g.enqueue(Event{Kind: EventHandshakeComplete})
	return nil
}

func (g *GMCryptoSetup) handleOneServer(msgType uint8, msg []byte, encLevel protocol.EncryptionLevel) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		if msgType != tls13gm.HandshakeTypeClientHello {
			return fmt.Errorf("handshake: GM unexpected Initial message type %d", msgType)
		}
		if err := g.serverHs.HandleClientHello(msg); err != nil {
			return err
		}
		// 0-RTT admission (upstream handleSessionTicket): the ticket's saved
		// transport parameters must still be valid for 0-RTT under the
		// CURRENT parameters — a client resuming after the server lowered its
		// flow-control limits would send 0-RTT under the stale limits and get
		// the connection killed with FLOW_CONTROL_ERROR. Dropping the early
		// keys declines the 0-RTT (EE carries no early_data; the client's
		// rejection path fires) while the PSK resumption itself continues.
		if g.ourParams != nil && g.serverHs.Secrets().ClientEarlyKeys != nil && !g.savedParamsValidFor0RTT() {
			g.serverHs.DiscardEarlyKeys()
			g.discard0RTTCodecs()
		}
		if err := g.emitPeerTransportParameters(g.serverHs.PeerTransportParams()); err != nil {
			return err
		}
		return g.emitServerFlight()
	case protocol.EncryptionHandshake:
		if msgType != tls13gm.HandshakeTypeFinished {
			return fmt.Errorf("handshake: GM unexpected Handshake message type %d", msgType)
		}
		if err := g.serverHs.HandleClientFinished(msg); err != nil {
			return err
		}
		g.handshakeDone = true
		// The client Finished is the last Handshake-level CRYPTO message —
		// only now are the server's 1-RTT read keys usable. Signaling at
		// ClientHello time (when the key schedule first derives the secrets)
		// would let the connection finish the Handshake CRYPTO stream early
		// and reject this very Finished as "crypto data after change of
		// encryption level".
		g.enqueue(Event{Kind: EventReceived1RTTReadKeys})
		g.enqueue(Event{Kind: EventHandshakeComplete})
		return nil
	default:
		return fmt.Errorf("handshake: GM server received message at unexpected level %s", encLevel)
	}
}

// emitServerFlight builds and emits the server flight (ServerHello on the Initial
// stream; EncryptedExtensions/Certificate/CertificateVerify/Finished on the
// Handshake stream) and installs the Handshake + 1-RTT keys.
func (g *GMCryptoSetup) emitServerFlight() error {
	sh, ee, cert, cv, fin, err := g.serverHs.ServerFlight()
	if err != nil {
		return err
	}
	if err := g.installHandshakeKeys(g.serverHs.Secrets()); err != nil {
		return err
	}
	if err := g.install1RTTKeys(g.serverHs.Secrets()); err != nil {
		return err
	}
	// ServerHello travels on the Initial stream; the rest on the Handshake stream.
	g.enqueue(Event{Kind: EventWriteInitialData, Data: sh})
	hsData := make([]byte, 0, len(ee)+len(cert)+len(cv)+len(fin))
	hsData = append(hsData, ee...)
	hsData = append(hsData, cert...)
	hsData = append(hsData, cv...)
	hsData = append(hsData, fin...)
	g.enqueue(Event{Kind: EventWriteHandshakeData, Data: hsData})
	return nil
}

// installHandshakeKeys builds the Handshake-level sealer/opener once the
// handshake secret is derived, and signals that read keys are available so the
// connection layer reattempts previously undecryptable packets (and finishes
// the Initial CRYPTO stream — upstream v0.62.0 keys that on the per-level
// read-keys events).
func (g *GMCryptoSetup) installHandshakeKeys(secrets tls13gm.HandshakeSecrets) error {
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	if g.perspective == protocol.PerspectiveClient {
		sealKeys, openKeys = secrets.ClientHandshakeKeys, secrets.ServerHandshakeKeys
	} else {
		sealKeys, openKeys = secrets.ServerHandshakeKeys, secrets.ClientHandshakeKeys
	}
	// 0-RTT read keys (server only): derived from the accepted resumption PSK
	// at the same moment as the handshake keys (both follow ClientHello
	// processing). Emit the 0-RTT signal first so the connection retries
	// buffered 0-RTT packets before the Initial stream is finished.
	if g.perspective == protocol.PerspectiveServer && secrets.ClientEarlyKeys != nil {
		g.enqueue(Event{Kind: EventReceived0RTTReadKeys})
	}
	sealer, err := newGMLongSealer(sealKeys)
	if err != nil {
		return err
	}
	opener, err := newGMLongOpener(openKeys)
	if err != nil {
		return err
	}
	g.handshakeSealer, g.handshakeOpener = sealer, opener
	g.enqueue(Event{Kind: EventReceivedHandshakeReadKeys})
	return nil
}

// install1RTTKeys builds the 1-RTT sealer/opener once the application secret is
// derived, fixed at key phase 0 for P0.
//
// Event timing is role-dependent (upstream v0.62.0 keys
// cryptoStreamManager.Finish(EncryptionHandshake) on this event, so it must
// only fire once the Handshake-level CRYPTO stream has been fully consumed):
//   - client: emitted here — install1RTTKeys runs from completeClientFlight,
//     after the whole server flight (including Finished) was consumed;
//   - server: NOT emitted here — at ClientHello time (emitServerFlight) the
//     client's Finished has not arrived yet. The server emits it from
//     handleOneServer once that Finished is verified.
func (g *GMCryptoSetup) install1RTTKeys(secrets tls13gm.HandshakeSecrets) error {
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	var sealSecret, openSecret []byte
	if g.perspective == protocol.PerspectiveClient {
		sealKeys, openKeys = secrets.ClientApplicationKeys, secrets.ServerApplicationKeys
		sealSecret, openSecret = secrets.ClientApplicationTrafficSecret, secrets.ServerApplicationTrafficSecret
	} else {
		sealKeys, openKeys = secrets.ServerApplicationKeys, secrets.ClientApplicationKeys
		sealSecret, openSecret = secrets.ServerApplicationTrafficSecret, secrets.ClientApplicationTrafficSecret
	}
	aead, err := newGMUpdatableAEAD(sealKeys, openKeys, sealSecret, openSecret)
	if err != nil {
		return err
	}
	g.oneRTTAEAD = aead
	if g.perspective == protocol.PerspectiveClient {
		g.enqueue(Event{Kind: EventReceived1RTTReadKeys})
	}
	return nil
}

// emitPeerTransportParameters unmarshals the peer's QUIC transport parameters
// (carried in the ClientHello/EncryptedExtensions) and surfaces them.
func (g *GMCryptoSetup) emitPeerTransportParameters(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	// Client side: retain the server's marshaled parameters so the harvested
	// ticket callback can hand them to the application (0-RTT restore input).
	if g.perspective == protocol.PerspectiveClient {
		g.peerParamsRaw = append(g.peerParamsRaw[:0], raw...)
	}
	var tp wire.TransportParameters
	if err := tp.Unmarshal(raw, g.perspective.Opposite()); err != nil {
		return fmt.Errorf("handshake: GM peer transport parameters: %w", err)
	}
	g.enqueue(Event{Kind: EventReceivedTransportParameters, TransportParameters: &tp})
	return nil
}

func (g *GMCryptoSetup) NextEvent() Event {
	if len(g.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := g.events[0]
	g.events[0] = Event{} // popped slot's Data (full flight bytes) must not pin memory
	g.events = g.events[1:]
	return ev
}

// --- getters ---

func (g *GMCryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if g.initialDropped {
		return nil, ErrKeysDropped
	}
	return g.initialOpener, nil
}

func (g *GMCryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if g.initialDropped {
		return nil, ErrKeysDropped
	}
	return g.initialSealer, nil
}

func (g *GMCryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if g.handshakeDropped {
		return nil, ErrKeysDropped
	}
	if g.handshakeOpener == nil {
		return nil, ErrKeysNotYetAvailable
	}
	return g.handshakeOpener, nil
}

func (g *GMCryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if g.handshakeDropped {
		return nil, ErrKeysDropped
	}
	if g.handshakeSealer == nil {
		return nil, ErrKeysNotYetAvailable
	}
	return g.handshakeSealer, nil
}

func (g *GMCryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if g.oneRTTAEAD == nil {
		return nil, ErrKeysNotYetAvailable
	}
	// Server: the AEAD is installed at ClientHello time (the key schedule
	// derives the 1-RTT secrets then), but packets may only be decrypted and
	// delivered to the application once the client's Finished is verified —
	// otherwise the connection layer's "handshake complete ⇒ peer
	// authenticated" invariant is broken. ErrKeysNotYetAvailable buffers early
	// 1-RTT packets; they are retried once the Finished processing fires
	// EventReceived1RTTReadKeys.
	if g.perspective == protocol.PerspectiveServer && !g.handshakeDone {
		return nil, ErrKeysNotYetAvailable
	}
	return g.oneRTTAEAD, nil
}

func (g *GMCryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if g.oneRTTAEAD == nil {
		return nil, ErrKeysNotYetAvailable
	}
	return g.oneRTTAEAD, nil
}

// Get0RTTOpener returns the 0-RTT packet opener (server side): the early
// traffic keys derived from the accepted resumption PSK, used to decrypt the
// client's 0-RTT data. Available after HandleClientHello accepted a PSK
// ClientHello carrying early_data (serverHs.Secrets().ClientEarlyKeys set).
func (g *GMCryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if g.perspective != protocol.PerspectiveServer {
		return nil, ErrKeysNotYetAvailable
	}
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	if g.zeroRTTOpener != nil {
		return g.zeroRTTOpener, nil
	}
	earlyKeys := g.serverHs.Secrets().ClientEarlyKeys
	if earlyKeys == nil {
		return nil, ErrKeysNotYetAvailable
	}
	opener, err := newGMLongOpener(earlyKeys)
	if err != nil {
		return nil, err
	}
	g.zeroRTTOpener = opener
	return opener, nil
}

// Get0RTTSealer returns the 0-RTT packet sealer (client side): the early
// traffic keys derived from the resumption PSK, used to encrypt 0-RTT data
// before the server responds. Available after ClientHello in PSK mode
// (clientHs.Secrets().ClientEarlyKeys set).
func (g *GMCryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	if g.perspective != protocol.PerspectiveClient {
		return nil, ErrKeysNotYetAvailable
	}
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	if g.zeroRTTSealer != nil {
		return g.zeroRTTSealer, nil
	}
	earlyKeys := g.clientHs.Secrets().ClientEarlyKeys
	if earlyKeys == nil {
		return nil, ErrKeysNotYetAvailable
	}
	sealer, err := newGMLongSealer(earlyKeys)
	if err != nil {
		return nil, err
	}
	g.zeroRTTSealer = sealer
	return sealer, nil
}

// --- lifecycle ---

// discard0RTTCodecs releases the cached 0-RTT codecs. Every DiscardEarlyKeys
// site must call it: a cached opener surviving its keys' logical death would
// keep decrypting with retired 0-RTT material.
func (g *GMCryptoSetup) discard0RTTCodecs() {
	g.zeroRTTSealer, g.zeroRTTOpener = nil, nil
}

func (g *GMCryptoSetup) DiscardInitialKeys() {
	g.initialDropped = true
	g.initialSealer, g.initialOpener = nil, nil
}

func (g *GMCryptoSetup) SetHandshakeConfirmed() {
	// Once the handshake is confirmed, the Handshake encryption level is dropped
	// (quic-go calls dropEncryptionLevel(Handshake), which removes the packet-
	// number space). Drop the handshake sealer/opener in lockstep so
	// GetHandshakeSealer returns ErrKeysDropped and packers skip the level.
	g.handshakeDropped = true
	g.handshakeSealer, g.handshakeOpener = nil, nil
	// Enable 1-RTT key updates (RFC 9001 §6): the first update is allowed once
	// the handshake is confirmed.
	if g.oneRTTAEAD != nil {
		g.oneRTTAEAD.SetHandshakeConfirmed()
	}
	// 0-RTT keys are obsolete once the handshake is confirmed (1-RTT protects
	// all further traffic). Only signal discard if 0-RTT was actually used.
	if g.perspective == protocol.PerspectiveServer && g.serverHs != nil && g.serverHs.Secrets().ClientEarlyKeys != nil {
		g.serverHs.DiscardEarlyKeys()
		g.discard0RTTCodecs()
		g.enqueue(Event{Kind: EventDiscard0RTTKeys})
	}
}

// SetLargest1RTTAcked feeds the key-update state machine (governs when a
// locally-initiated update is allowed) and detects a peer that failed to update.
func (g *GMCryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	if g.oneRTTAEAD != nil {
		return g.oneRTTAEAD.SetLargestAcked(pn)
	}
	return nil
}

// ChangeConnectionID re-derives the Initial packet-protection keys from the
// NEW destination connection ID (client side, after the connection accepted a
// validated Retry — RFC 9001 §5.2: Initial secrets are a function of the DCID,
// so the post-Retry Initial packets must be protected under the Retry's new
// DCID). The tls13gm handshake state is unaffected: the QUIC Retry restarts
// the packet layer, not the TLS handshake, and the CRYPTO stream contents are
// retransmitted by the connection layer under the new keys.
//
// Previously a no-op, which silently disabled address validation interop: a
// GM client hitting a Retry-sending server (upstream's
// Transport.VerifySourceAddress, or a future GM deployment) kept sealing
// Initial packets under the ORIGINAL DCID's keys and the handshake timed out.
func (g *GMCryptoSetup) ChangeConnectionID(destConnID protocol.ConnectionID) {
	if g.initialDropped {
		// The Initial level is already gone (handshake confirmed); replacing
		// the codecs would resurrect it. Upstream's drop-free design has no
		// equivalent state to guard.
		return
	}
	if err := g.reinitInitialKeys(destConnID); err != nil {
		// The CryptoSetup interface has no error return (mirroring upstream's
		// NewInitialAEAD, which cannot fail). Derivation failure is an
		// invariant violation (HKDF bug); fail closed loudly rather than
		// continue a Retry with stale keys.
		panic(fmt.Sprintf("handshake: GM ChangeConnectionID re-derive Initial keys: %v", err))
	}
}

// reinitInitialKeys rebuilds the Initial-level sealer/opener from the given
// connection ID (Retry path).
func (g *GMCryptoSetup) reinitInitialKeys(connID protocol.ConnectionID) error {
	clientIn, serverIn, err := tls13gm.DeriveQUICInitialSecrets(connID.Bytes())
	if err != nil {
		return err
	}
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	if sealKeys, err = tls13gm.DeriveQUICPacketKeys(clientIn); err != nil {
		return err
	}
	if openKeys, err = tls13gm.DeriveQUICPacketKeys(serverIn); err != nil {
		return err
	}
	sealer, err := newGMLongSealer(sealKeys)
	if err != nil {
		return err
	}
	opener, err := newGMLongOpener(openKeys)
	if err != nil {
		return err
	}
	g.initialSealer, g.initialOpener = sealer, opener
	return nil
}

// GetSessionTicket returns a NewSessionTicket (carrying a resumption PSK) for
// the server to send post-handshake, enabling the client to resume — and use
// 0-RTT — on a future connection. Only valid server-side, after
// HandleClientFinished.
func (g *GMCryptoSetup) GetSessionTicket() ([]byte, error) {
	if g.perspective != protocol.PerspectiveServer || g.serverHs == nil {
		return nil, nil
	}
	// RFC 8446 §4.6.1: ticket_age_add MUST be a fresh random per ticket so that
	// the obfuscated_ticket_age the client later sends does not reveal the real
	// ticket age to an on-path observer, AND so a malicious client cannot forge
	// a small age to bypass the server's anti-replay/expiry gate (the server
	// reconstructs realAge = obfuscated_ticket_age - ticket_age_add). A constant
	// 0 here made both protections no-ops.
	// Embed the server's current transport parameters in the ticket so the
	// resuming client can restore its 0-RTT limits (M11) and this server can
	// run the ValidFor0RTT admission check on the resumed handshake (M12).
	var serverParams []byte
	if g.ourParams != nil {
		serverParams = g.ourParams.Marshal(protocol.PerspectiveServer)
	}
	return g.serverHs.NewSessionTicketWithData(7200, serverParams)
}

// ClientSessionTicket returns the opaque ticket identity, the derived
// resumption PSK, and ticket_age_add from the most recent NewSessionTicket
// received from the server (client side), or (nil, nil, 0) if none. The
// identity is the pre_shared_key identity to echo on a later resumption; the
// PSK keys the binder / 0-RTT early secret; ticketAgeAdd is the ticket_age_add.
// Feed them back as ClientConfig.ResumptionIdentity / ResumptionPSK /
// ResumptionObfuscatedTicketAge. Not part of the CryptoSetup interface; cast
// to *GMCryptoSetup to access.
func (g *GMCryptoSetup) ClientSessionTicket() (identity, psk []byte, ticketAgeAdd uint32) {
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	return g.clientSessionIdentity, g.clientSessionPSK, g.clientTicketAgeAdd
}

// Close is invoked by quic-go when the connection is torn down. We use it to
// zero the handshaker's long-lived key-derivation intermediates (handshake /
// master / resumption-master secrets, traffic secrets, resumption PSK) so they
// do not linger on the heap. Best-effort, mirroring crypto/tls.
func (g *GMCryptoSetup) Close() error {
	if g.clientHs != nil {
		g.clientHs.Zero()
	}
	if g.serverHs != nil {
		g.serverHs.Zero()
	}
	// NOTE: the 1-RTT AEAD is deliberately NOT wiped here. The connection
	// teardown path seals the final CONNECTION_CLOSE with the 1-RTT keys AFTER
	// CryptoSetup.Close runs (upstream contract); wiping sendKM would nil-deref
	// the close packet's Overhead/Seal. gmUpdatableAEAD.Zero exists for
	// explicit post-connection wipe by owners that know no more packets will
	// be sent.
	// The harvested resumption PSK is live key material (a stolen PSK
	// impersonates the client on resume); the quicgm Conn wipes its own copy,
	// these copies previously lingered until GC.
	g.stateMutex.Lock()
	tls13gm.ZeroBytes(g.clientSessionPSK)
	g.clientSessionPSK, g.clientSessionIdentity = nil, nil
	g.discard0RTTCodecs()
	g.stateMutex.Unlock()
	return nil
}

func (g *GMCryptoSetup) ConnectionState() ConnectionState {
	g.stateMutex.Lock()
	defer g.stateMutex.Unlock()
	// tls.ConnectionState does not carry the cipher suite, so the GM suite
	// (TLS_SM4_GCM_SM3) is implied by the use of GMCryptoSetup.
	used0RTT := false
	if g.perspective == protocol.PerspectiveClient && g.clientHs != nil {
		// 0-RTT is "used" only when the server accepted it (echoed early_data).
		used0RTT = g.clientHs.EarlyDataAccepted()
	} else if g.serverHs != nil {
		used0RTT = g.serverHs.AcceptedEarlyData()
	}
	var negotiated string
	if g.perspective == protocol.PerspectiveClient && g.clientHs != nil {
		negotiated = g.clientHs.NegotiatedProtocol()
	} else if g.serverHs != nil {
		negotiated = g.serverHs.NegotiatedProtocol()
	}
	state := tls.ConnectionState{
		Version:            0x0304, // TLS 1.3
		HandshakeComplete:  g.handshakeDone,
		NegotiatedProtocol: negotiated,
	}
	return ConnectionState{state, used0RTT}
}
