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
	"fmt"

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

	// Packet-protection codecs, populated lazily as keys become available.
	initialSealer   LongHeaderSealer
	initialOpener   LongHeaderOpener
	handshakeSealer LongHeaderSealer
	handshakeOpener LongHeaderOpener
	oneRTTSealer   ShortHeaderSealer
	oneRTTOpener   ShortHeaderOpener

	initialDropped   bool
	handshakeDropped bool
	handshakeDone    bool
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
		perspective: protocol.PerspectiveClient,
		version:     version,
		logger:      logger,
		clientHs:    hs,
		ourParams:   tp,
		events:      make([]Event, 0, 8),
	}
	if err := g.initInitialKeys(hs.Secrets()); err != nil {
		return nil, err
	}
	return g, nil
}

// NewGMCryptoSetupServer builds a server-side GMCryptoSetup. serverCfg supplies
// the server certificate and key; its DCID and TransportParameters fields are
// overwritten. tp is advertised in EncryptedExtensions.
func NewGMCryptoSetupServer(
	connID protocol.ConnectionID,
	serverCfg *tls13gm.ServerConfig,
	tp *wire.TransportParameters,
	logger utils.Logger,
	version protocol.Version,
) (*GMCryptoSetup, error) {
	if serverCfg == nil {
		return nil, fmt.Errorf("handshake: GM server config is required")
	}
	cfg := *serverCfg
	cfg.DCID = connID.Bytes()
	if tp != nil {
		cfg.TransportParameters = tp.Marshal(protocol.PerspectiveServer)
	}
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
	if g.perspective == protocol.PerspectiveClient {
		ch, err := g.clientHs.ClientHello()
		if err != nil {
			return fmt.Errorf("handshake: GM ClientHello: %w", err)
		}
		g.enqueue(Event{Kind: EventWriteInitialData, Data: ch})
	}
	return nil
}

// HandleMessage feeds reassembled CRYPTO-stream bytes to the tls13gm handshaker.
// The data may carry several concatenated handshake messages; each is split out
// and dispatched by (perspective, encryption level, message type). Handshake
// progress produces Events consumed later by the connection layer.
func (g *GMCryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
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
			return err
		}
		return g.installHandshakeKeys(g.clientHs.Secrets())
	case protocol.EncryptionHandshake:
		switch msgType {
		case tls13gm.HandshakeTypeEncryptedExtensions:
			if err := g.clientHs.HandleEncryptedExtensions(msg); err != nil {
				return err
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
// connection layer reattempts previously undecryptable packets.
func (g *GMCryptoSetup) installHandshakeKeys(secrets tls13gm.HandshakeSecrets) error {
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	if g.perspective == protocol.PerspectiveClient {
		sealKeys, openKeys = secrets.ClientHandshakeKeys, secrets.ServerHandshakeKeys
	} else {
		sealKeys, openKeys = secrets.ServerHandshakeKeys, secrets.ClientHandshakeKeys
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
	g.enqueue(Event{Kind: EventReceivedReadKeys})
	return nil
}

// install1RTTKeys builds the 1-RTT sealer/opener once the application secret is
// derived, fixed at key phase 0 for P0.
func (g *GMCryptoSetup) install1RTTKeys(secrets tls13gm.HandshakeSecrets) error {
	var sealKeys, openKeys *tls13gm.QUICPacketKeys
	if g.perspective == protocol.PerspectiveClient {
		sealKeys, openKeys = secrets.ClientApplicationKeys, secrets.ServerApplicationKeys
	} else {
		sealKeys, openKeys = secrets.ServerApplicationKeys, secrets.ClientApplicationKeys
	}
	sealer, err := newGMShortSealer(sealKeys, protocol.KeyPhaseZero)
	if err != nil {
		return err
	}
	opener, err := newGMShortOpener(openKeys, protocol.KeyPhaseZero)
	if err != nil {
		return err
	}
	g.oneRTTSealer, g.oneRTTOpener = sealer, opener
	g.enqueue(Event{Kind: EventReceivedReadKeys})
	return nil
}

// emitPeerTransportParameters unmarshals the peer's QUIC transport parameters
// (carried in the ClientHello/EncryptedExtensions) and surfaces them.
func (g *GMCryptoSetup) emitPeerTransportParameters(raw []byte) error {
	if len(raw) == 0 {
		return nil
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
	if g.oneRTTOpener == nil {
		return nil, ErrKeysNotYetAvailable
	}
	return g.oneRTTOpener, nil
}

func (g *GMCryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if g.oneRTTSealer == nil {
		return nil, ErrKeysNotYetAvailable
	}
	return g.oneRTTSealer, nil
}

// 0-RTT is not supported in P0.
func (g *GMCryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) { return nil, ErrKeysNotYetAvailable }
func (g *GMCryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) { return nil, ErrKeysNotYetAvailable }

// --- lifecycle ---

func (g *GMCryptoSetup) DiscardInitialKeys() {
	g.initialDropped = true
	g.initialSealer, g.initialOpener = nil, nil
}

func (g *GMCryptoSetup) SetHandshakeConfirmed() {
	// Once the handshake is confirmed, the Handshake encryption level is dropped
	// (quic-go calls dropEncryptionLevel(Handshake), which removes the packet-
	// number space). Drop the handshake sealer/opener in lockstep so
	// GetHandshakeSealer returns ErrKeysDropped and packers skip the level —
	// otherwise a CONNECTION_CLOSE would try to packet-number-allocate for a
	// level whose pnSpace is gone and nil-deref.
	g.handshakeDropped = true
	g.handshakeSealer, g.handshakeOpener = nil, nil
}

// SetLargest1RTTAcked is a no-op in P0. P3 wires tls13gm.QUICKeyUpdate for key
// rotation.
func (g *GMCryptoSetup) SetLargest1RTTAcked(protocol.PacketNumber) error { return nil }

// ChangeConnectionID is a no-op in P0. (Retry/path validation support follows.)
func (g *GMCryptoSetup) ChangeConnectionID(protocol.ConnectionID) {}

// GetSessionTicket returns nothing in P0 (no PSK/resumption yet).
func (g *GMCryptoSetup) GetSessionTicket() ([]byte, error) { return nil, nil }

func (g *GMCryptoSetup) Close() error { return nil }

func (g *GMCryptoSetup) ConnectionState() ConnectionState {
	// P0: minimal state. tls.ConnectionState does not carry the cipher suite, so
	// the GM suite (TLS_SM4_GCM_SM3) is implied by the use of GMCryptoSetup.
	return ConnectionState{
		tls.ConnectionState{
			Version:           0x0304, // TLS 1.3
			HandshakeComplete: g.handshakeDone,
		},
		false, // Used0RTT
	}
}
