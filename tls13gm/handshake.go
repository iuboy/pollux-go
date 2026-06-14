package tls13gm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"fmt"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/smx509"
)

// HandshakeSecrets holds the QUIC packet-protection keys for all three
// encryption levels produced by a completed TLS 1.3 GM handshake. Each pair is
// derived from the corresponding traffic secret via DeriveQUICPacketKeys, so
// each side can build a quicgm.QUICPacketProtector for Initial, Handshake, and
// 1-RTT packets.
type HandshakeSecrets struct {
	// Initial level: derived from the DCID via DeriveQUICInitialSecrets.
	ClientInitialKeys, ServerInitialKeys *QUICPacketKeys
	// Handshake level: derived from the handshake secret (c/s hs traffic).
	ClientHandshakeKeys, ServerHandshakeKeys *QUICPacketKeys
	// Application (1-RTT) level: derived from the master secret (c/s ap traffic).
	ClientApplicationKeys, ServerApplicationKeys *QUICPacketKeys
}

// Zero securely zeroes every key set in the secret bundle. Call it once the
// connection that owns these keys has closed. Nil fields are skipped.
func (h *HandshakeSecrets) Zero() {
	if h == nil {
		return
	}
	for _, k := range []*QUICPacketKeys{
		h.ClientInitialKeys, h.ServerInitialKeys,
		h.ClientHandshakeKeys, h.ServerHandshakeKeys,
		h.ClientApplicationKeys, h.ServerApplicationKeys,
	} {
		if k != nil {
			k.Zero()
		}
	}
}

// equalConstantTime reports whether a and b are equal in constant time.
func equalConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ClientHandshaker drives the TLS 1.3 GM handshake from the client side. It is
// transport-agnostic: it produces and consumes raw handshake-message bytes
// (4-byte header + body), which QUIC carries in CRYPTO frames.
type ClientHandshaker struct {
	dcid       []byte
	ephemeral  *sm2.PrivateKey // ECDHE key for this handshake
	transcript *Transcript

	// Peer certificate verification. When insecureSkipVerify is false the server
	// leaf (taken from the Certificate message) is verified against rootPool and
	// serverName via smx509.Verify before its public key is trusted for
	// CertificateVerify. insecureSkipVerify disables that check (testing only).
	insecureSkipVerify bool
	rootPool           *smx509.CertPool
	intermediates      *smx509.CertPool
	serverName         string
	verifyPeerCert     func(rawCerts [][]byte) error

	// derived secrets
	handshakeSecret []byte
	masterSecret    []byte
	clientHSTraffic []byte
	serverHSTraffic []byte
	secrets         HandshakeSecrets
}

// ClientConfig configures a TLS 1.3 GM client handshaker.
//
// Security model: the server leaf is taken from the peer's Certificate message
// (not pre-supplied) and verified against Roots with ServerName before its
// public key is trusted for CertificateVerify. This is fail-closed — when
// InsecureSkipVerify is false, Roots MUST be non-empty or the handshake aborts.
type ClientConfig struct {
	// DCID seeds the QUIC Initial packet-protection keys (RFC 9001 §5.2). Required.
	DCID []byte

	// ServerName is the DNS name matched against the server leaf's SAN/CN
	// during PKI verification. Leave empty only when pinning via
	// VerifyPeerCertificate.
	ServerName string

	// Roots is the trusted root certificate pool for chain verification.
	// Required unless InsecureSkipVerify or VerifyPeerCertificate is set.
	Roots *smx509.CertPool

	// Intermediates is an optional pool of non-root intermediary certificates
	// used to build the chain when they are not sent in the Certificate message.
	Intermediates *smx509.CertPool

	// InsecureSkipVerify disables PKI verification. Intended for self-signed
	// test fixtures ONLY. Never enable in production code.
	InsecureSkipVerify bool

	// VerifyPeerCertificate, if set, is invoked with the raw DER certificate
	// chain from the Certificate message after default chain verification. It
	// overrides nothing — the default verification (or InsecureSkipVerify) still
	// runs first unless Roots is nil. Use it for certificate pinning.
	VerifyPeerCertificate func(rawCerts [][]byte) error
}

// NewClientHandshaker prepares a client handshaker from an explicit, fail-closed
// ClientConfig. See ClientConfig for the security model.
func NewClientHandshakerWithConfig(cfg ClientConfig) (*ClientHandshaker, error) {
	if len(cfg.DCID) == 0 {
		return nil, fmt.Errorf("tls13gm: dcid is required to seed Initial keys")
	}
	if !cfg.InsecureSkipVerify && cfg.VerifyPeerCertificate == nil && cfg.Roots == nil {
		return nil, fmt.Errorf("tls13gm: ClientConfig.Roots is required (use InsecureSkipVerify only for testing)")
	}
	priv, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: generate ECDHE keypair: %w", err)
	}
	clientIn, serverIn, err := DeriveQUICInitialSecrets(cfg.DCID)
	if err != nil {
		return nil, err
	}
	cInit, err := DeriveQUICPacketKeys(clientIn)
	if err != nil {
		return nil, err
	}
	sInit, err := DeriveQUICPacketKeys(serverIn)
	if err != nil {
		return nil, err
	}
	return &ClientHandshaker{
		dcid:               cfg.DCID,
		ephemeral:          priv,
		transcript:         NewTranscript(),
		insecureSkipVerify: cfg.InsecureSkipVerify,
		rootPool:           cfg.Roots,
		intermediates:      cfg.Intermediates,
		serverName:         cfg.ServerName,
		verifyPeerCert:     cfg.VerifyPeerCertificate,
		secrets:            HandshakeSecrets{ClientInitialKeys: cInit, ServerInitialKeys: sInit},
	}, nil
}

// NewClientHandshaker prepares a client handshaker. dcid seeds the Initial keys.
//
// Deprecated: this constructor skips PKI verification. The serverCert parameter
// is ignored — the peer leaf is always taken from the Certificate message. Use
// NewClientHandshakerWithConfig with explicit Roots for production callers.
func NewClientHandshaker(dcid []byte, _ *x509.Certificate) (*ClientHandshaker, error) {
	return NewClientHandshakerWithConfig(ClientConfig{
		DCID:               dcid,
		InsecureSkipVerify: true,
	})
}

// Secrets returns the packet-protection keys derived so far.
func (c *ClientHandshaker) Secrets() HandshakeSecrets { return c.secrets }

// ClientHello produces the ClientHello handshake message and records it in the
// transcript. It must be called once before HandleServerFlight.
func (c *ClientHandshaker) ClientHello() ([]byte, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	pub, ok := c.ephemeral.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("tls13gm: unexpected ECDHE public key type")
	}
	ch := &ClientHelloMsg{
		LegacyVersion: uint16(VersionTLS13),
		Random:        random,
		CipherSuites:  []uint16{TLS_SM4_GCM_SM3},
		Extensions: []Extension{
			{Type: ExtensionTypeSupportedVersions, Data: []byte{0x02, 0x03, 0x03}},
			{Type: ExtensionTypeSignatureAlgorithms, Data: []byte{0x00, 0x02, byte(SM2SigSM3 >> 8), byte(SM2SigSM3 & 0xff)}},
			{Type: ExtensionTypeSupportedGroups, Data: []byte{0x00, 0x02, byte(CurveSM2 >> 8), byte(CurveSM2 & 0xff)}},
			{Type: ExtensionTypeKeyShare, Data: marshalClientKeyShare(CurveSM2, sm2.MarshalUncompressed(pub))},
		},
	}
	full, err := MarshalHandshakeMessage(ch)
	if err != nil {
		return nil, err
	}
	c.transcript.AddMessage(HandshakeTypeClientHello, full[4:])
	return full, nil
}

// HandleServerFlight processes the server's flight: ServerHello, EncryptedExtensions,
// Certificate, CertificateVerify, Finished. It derives the Handshake and
// Application keys, and verifies the server CertificateVerify and Finished. Each
// argument is a complete handshake message (header + body).
func (c *ClientHandshaker) HandleServerFlight(serverHello, encryptedExt, certificate, certVerify, finished []byte) error {
	// --- ServerHello: extract server key share, derive handshake secret ---
	shType, shBody, _, err := ReadHandshakeMessage(serverHello)
	if err != nil {
		return fmt.Errorf("tls13gm: read ServerHello: %w", err)
	}
	if shType != HandshakeTypeServerHello {
		return fmt.Errorf("tls13gm: expected ServerHello, got type %d", shType)
	}
	var sh ServerHelloMsg
	if err := sh.unmarshalBody(shBody); err != nil {
		return fmt.Errorf("tls13gm: ServerHello: %w", err)
	}
	ks := findExtension(sh.Extensions, ExtensionTypeKeyShare)
	if ks == nil {
		return fmt.Errorf("tls13gm: ServerHello missing key_share extension")
	}
	serverKeyBytes, err := parseServerKeyShare(ks, CurveSM2)
	if err != nil {
		return fmt.Errorf("tls13gm: ServerHello key_share: %w", err)
	}
	serverPub, err := sm2.UnmarshalUncompressed(serverKeyBytes)
	if err != nil {
		return fmt.Errorf("tls13gm: decode server key share: %w", err)
	}
	sharedSecret, err := CurveSM2ECDHE(c.ephemeral, serverPub)
	if err != nil {
		return fmt.Errorf("tls13gm: ECDHE: %w", err)
	}
	c.transcript.AddMessage(shType, shBody)

	earlySecret := DeriveEarlySecret(nil)
	c.handshakeSecret, err = DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		return err
	}
	if c.clientHSTraffic, err = DeriveSecret(c.handshakeSecret, LabelClientHSTraffic, c.transcript.Sum()); err != nil {
		return err
	}
	if c.serverHSTraffic, err = DeriveSecret(c.handshakeSecret, LabelServerHSTraffic, c.transcript.Sum()); err != nil {
		return err
	}
	if c.secrets.ClientHandshakeKeys, err = DeriveQUICPacketKeys(c.clientHSTraffic); err != nil {
		return err
	}
	if c.secrets.ServerHandshakeKeys, err = DeriveQUICPacketKeys(c.serverHSTraffic); err != nil {
		return err
	}

	// --- EncryptedExtensions: record in transcript ---
	if err := c.addRawMessage(encryptedExt, HandshakeTypeEncryptedExtensions); err != nil {
		return err
	}

	// --- Certificate: parse leaf, verify chain, record in transcript ---
	_, certBody, _, err := ReadHandshakeMessage(certificate)
	if err != nil {
		return fmt.Errorf("tls13gm: read Certificate: %w", err)
	}
	var certMsg CertificateMsg
	if err := certMsg.unmarshalBody(certBody); err != nil {
		return fmt.Errorf("tls13gm: Certificate: %w", err)
	}
	if len(certMsg.CertificateList) == 0 {
		return fmt.Errorf("tls13gm: server sent an empty Certificate chain")
	}
	leaf, err := smx509.ParseCertificate(certMsg.CertificateList[0].Certificate)
	if err != nil {
		return fmt.Errorf("tls13gm: parse server leaf certificate: %w", err)
	}
	// PKI verification: chain to a trusted root, hostname match, validity,
	// SM2 signature. Fail-closed unless the caller opted out explicitly.
	if !c.insecureSkipVerify {
		opts := smx509.VerifyOptions{DNSName: c.serverName}
		if c.rootPool != nil {
			opts.Roots = c.rootPool
		}
		if c.intermediates != nil {
			opts.Intermediates = c.intermediates
		}
		if err := smx509.Verify(leaf, opts); err != nil {
			return fmt.Errorf("tls13gm: server certificate verification failed: %w", err)
		}
	}
	if c.verifyPeerCert != nil {
		rawCerts := make([][]byte, len(certMsg.CertificateList))
		for i, e := range certMsg.CertificateList {
			rawCerts[i] = e.Certificate
		}
		if err := c.verifyPeerCert(rawCerts); err != nil {
			return fmt.Errorf("tls13gm: VerifyPeerCertificate: %w", err)
		}
	}
	c.transcript.AddMessage(HandshakeTypeCertificate, certBody)

	// --- CertificateVerify: verify against the verified leaf (transcript = CH..Cert) ---
	cvType, cvBody, _, err := ReadHandshakeMessage(certVerify)
	if err != nil {
		return fmt.Errorf("tls13gm: read CertificateVerify: %w", err)
	}
	if cvType != HandshakeTypeCertificateVerify {
		return fmt.Errorf("tls13gm: expected CertificateVerify, got type %d", cvType)
	}
	var cv CertificateVerifyMsg
	if err := cv.unmarshalBody(cvBody); err != nil {
		return fmt.Errorf("tls13gm: CertificateVerify: %w", err)
	}
	if cv.SignatureScheme != SM2SigSM3 {
		return fmt.Errorf("tls13gm: CertificateVerify signature scheme %04x is not SM2SigSM3", cv.SignatureScheme)
	}
	serverPubCert, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("tls13gm: server cert public key is not ECDSA")
	}
	if !VerifyCertificateVerify(serverPubCert, ServerCertificateVerifyContext, c.transcript.Sum(), cv.Signature) {
		return fmt.Errorf("tls13gm: CertificateVerify signature verification failed")
	}
	c.transcript.AddMessage(cvType, cvBody)

	// --- Finished: verify (transcript = CH..CertVerify) ---
	finType, finBody, _, err := ReadHandshakeMessage(finished)
	if err != nil {
		return fmt.Errorf("tls13gm: read Finished: %w", err)
	}
	if finType != HandshakeTypeFinished {
		return fmt.Errorf("tls13gm: expected Finished, got type %d", finType)
	}
	var fin FinishedMsg
	if err := fin.unmarshalBody(finBody); err != nil {
		return fmt.Errorf("tls13gm: Finished: %w", err)
	}
	serverFinishedKey, err := DeriveFinishedKey(c.serverHSTraffic)
	if err != nil {
		return err
	}
	expected, err := ComputeFinishedVerifyData(serverFinishedKey, c.transcript.Sum())
	if err != nil {
		return err
	}
	if !equalConstantTime(expected, fin.VerifyData) {
		return fmt.Errorf("tls13gm: server Finished verify_data mismatch")
	}
	c.transcript.AddMessage(finType, finBody)

	// --- Application keys (transcript = CH..server Finished) ---
	c.masterSecret, err = DeriveMasterSecret(c.handshakeSecret)
	if err != nil {
		return err
	}
	cAP, err := DeriveSecret(c.masterSecret, LabelClientAPTraffic, c.transcript.Sum())
	if err != nil {
		return err
	}
	sAP, err := DeriveSecret(c.masterSecret, LabelServerAPTraffic, c.transcript.Sum())
	if err != nil {
		return err
	}
	if c.secrets.ClientApplicationKeys, err = DeriveQUICPacketKeys(cAP); err != nil {
		return err
	}
	if c.secrets.ServerApplicationKeys, err = DeriveQUICPacketKeys(sAP); err != nil {
		return err
	}
	return nil
}

// ClientFinished produces the client's Finished message (verify_data over the
// transcript CH..server Finished, keyed by the client handshake traffic secret)
// and records it. HandleServerFlight must have completed.
func (c *ClientHandshaker) ClientFinished() ([]byte, error) {
	if c.masterSecret == nil {
		return nil, fmt.Errorf("tls13gm: HandleServerFlight must complete before ClientFinished")
	}
	finishedKey, err := DeriveFinishedKey(c.clientHSTraffic)
	if err != nil {
		return nil, err
	}
	verifyData, err := ComputeFinishedVerifyData(finishedKey, c.transcript.Sum())
	if err != nil {
		return nil, err
	}
	full, err := MarshalHandshakeMessage(&FinishedMsg{VerifyData: verifyData})
	if err != nil {
		return nil, err
	}
	c.transcript.AddMessage(HandshakeTypeFinished, full[4:])
	return full, nil
}

func (c *ClientHandshaker) addRawMessage(msg []byte, wantType uint8) error {
	mt, body, _, err := ReadHandshakeMessage(msg)
	if err != nil {
		return fmt.Errorf("tls13gm: read type %d message: %w", wantType, err)
	}
	if mt != wantType {
		return fmt.Errorf("tls13gm: expected message type %d, got %d", wantType, mt)
	}
	c.transcript.AddMessage(mt, body)
	return nil
}

// ServerHandshaker drives the TLS 1.3 GM handshake from the server side.
type ServerHandshaker struct {
	dcid       []byte
	ephemeral  *sm2.PrivateKey   // ECDHE key for this handshake
	clientPub  *ecdsa.PublicKey  // peer curveSM2 public key (from ClientHello)
	serverCert *x509.Certificate // certificate to present
	serverKey  *sm2.PrivateKey   // cert private key, signs CertificateVerify
	transcript *Transcript

	// derived secrets
	handshakeSecret []byte
	masterSecret    []byte
	clientHSTraffic []byte
	serverHSTraffic []byte
	secrets         HandshakeSecrets
}

// NewServerHandshaker prepares a server handshaker. serverCert/serverKey are the
// server's SM2 certificate and its private key; dcid seeds the Initial keys.
func NewServerHandshaker(dcid []byte, serverCert *x509.Certificate, serverKey *sm2.PrivateKey) (*ServerHandshaker, error) {
	if len(dcid) == 0 {
		return nil, fmt.Errorf("tls13gm: dcid is required to seed Initial keys")
	}
	if serverCert == nil || serverKey == nil {
		return nil, fmt.Errorf("tls13gm: server certificate and key are required")
	}
	priv, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: generate ECDHE keypair: %w", err)
	}
	clientIn, serverIn, err := DeriveQUICInitialSecrets(dcid)
	if err != nil {
		return nil, err
	}
	cInit, err := DeriveQUICPacketKeys(clientIn)
	if err != nil {
		return nil, err
	}
	sInit, err := DeriveQUICPacketKeys(serverIn)
	if err != nil {
		return nil, err
	}
	return &ServerHandshaker{
		dcid:       dcid,
		ephemeral:  priv,
		serverCert: serverCert,
		serverKey:  serverKey,
		transcript: NewTranscript(),
		secrets:    HandshakeSecrets{ClientInitialKeys: cInit, ServerInitialKeys: sInit},
	}, nil
}

// Secrets returns the packet-protection keys derived so far.
func (s *ServerHandshaker) Secrets() HandshakeSecrets { return s.secrets }

// HandleClientHello records the ClientHello, extracts the client's curveSM2 key
// share, and stores the shared secret. The handshake secret and Handshake-level
// keys are derived in ServerFlight once the ServerHello is also in the transcript.
func (s *ServerHandshaker) HandleClientHello(ch []byte) error {
	mt, body, _, err := ReadHandshakeMessage(ch)
	if err != nil {
		return fmt.Errorf("tls13gm: read ClientHello: %w", err)
	}
	if mt != HandshakeTypeClientHello {
		return fmt.Errorf("tls13gm: expected ClientHello, got type %d", mt)
	}
	var chMsg ClientHelloMsg
	if err := chMsg.unmarshalBody(body); err != nil {
		return fmt.Errorf("tls13gm: ClientHello: %w", err)
	}
	// RFC 8998 capability gate: the server only speaks the GM suite, so reject a
	// ClientHello that does not offer the required SM4-GCM-SM3 cipher suite, TLS
	// 1.3, SM2SigSM3, and curveSM2 before doing any ECDHE work.
	if !containsCipherSuite(chMsg.CipherSuites, TLS_SM4_GCM_SM3) {
		return fmt.Errorf("tls13gm: ClientHello does not offer TLS_SM4_GCM_SM3")
	}
	if sv := findExtension(chMsg.Extensions, ExtensionTypeSupportedVersions); sv == nil ||
		!containsUint16List(sv, 1, uint16(VersionTLS13)) {
		return fmt.Errorf("tls13gm: ClientHello does not advertise TLS 1.3")
	}
	if sa := findExtension(chMsg.Extensions, ExtensionTypeSignatureAlgorithms); sa == nil ||
		!containsUint16List(sa, 2, SM2SigSM3) {
		return fmt.Errorf("tls13gm: ClientHello does not offer SM2SigSM3")
	}
	if sg := findExtension(chMsg.Extensions, ExtensionTypeSupportedGroups); sg == nil ||
		!containsUint16List(sg, 2, CurveSM2) {
		return fmt.Errorf("tls13gm: ClientHello does not offer curveSM2")
	}
	ks := findExtension(chMsg.Extensions, ExtensionTypeKeyShare)
	if ks == nil {
		return fmt.Errorf("tls13gm: ClientHello missing key_share extension")
	}
	clientKeyBytes, err := parseClientKeyShare(ks, CurveSM2)
	if err != nil {
		return fmt.Errorf("tls13gm: ClientHello key_share: %w", err)
	}
	clientPub, err := sm2.UnmarshalUncompressed(clientKeyBytes)
	if err != nil {
		return fmt.Errorf("tls13gm: decode client key share: %w", err)
	}
	s.transcript.AddMessage(mt, body)
	s.clientPub = clientPub
	return nil
}

// ServerFlight builds the server's flight (ServerHello, EncryptedExtensions,
// Certificate, CertificateVerify, Finished), derives the Handshake and
// Application keys, and records each message in the transcript.
func (s *ServerHandshaker) ServerFlight() (serverHello, encExt, certificate, certVerify, finished []byte, err error) {
	if s.clientPub == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("tls13gm: HandleClientHello must be called before ServerFlight")
	}
	clientPub := s.clientPub

	// --- ServerHello ---
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	pub, ok := s.ephemeral.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("tls13gm: unexpected ECDHE public key type")
	}
	shMsg := &ServerHelloMsg{
		LegacyVersion: uint16(VersionTLS13),
		Random:        random,
		CipherSuite:   TLS_SM4_GCM_SM3,
		Extensions: []Extension{
			{Type: ExtensionTypeSupportedVersions, Data: []byte{0x03, 0x03}},
			{Type: ExtensionTypeKeyShare, Data: marshalServerKeyShare(CurveSM2, sm2.MarshalUncompressed(pub))},
		},
	}
	if serverHello, err = MarshalHandshakeMessage(shMsg); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	s.transcript.AddMessage(HandshakeTypeServerHello, serverHello[4:])

	// --- Handshake secret + Handshake keys (transcript = CH+SH) ---
	sharedSecret, err := CurveSM2ECDHE(s.ephemeral, clientPub)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("tls13gm: ECDHE: %w", err)
	}
	earlySecret := DeriveEarlySecret(nil)
	s.handshakeSecret, err = DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.clientHSTraffic, err = DeriveSecret(s.handshakeSecret, LabelClientHSTraffic, s.transcript.Sum()); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.serverHSTraffic, err = DeriveSecret(s.handshakeSecret, LabelServerHSTraffic, s.transcript.Sum()); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.secrets.ClientHandshakeKeys, err = DeriveQUICPacketKeys(s.clientHSTraffic); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.secrets.ServerHandshakeKeys, err = DeriveQUICPacketKeys(s.serverHSTraffic); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// --- EncryptedExtensions (empty, minimal) ---
	if encExt, err = MarshalHandshakeMessage(&EncryptedExtensionsMsg{}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	s.transcript.AddMessage(HandshakeTypeEncryptedExtensions, encExt[4:])

	// --- Certificate (single self-signed server cert) ---
	if certificate, err = MarshalHandshakeMessage(&CertificateMsg{
		CertificateList: []CertificateEntry{{Certificate: s.serverCert.Raw}},
	}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	s.transcript.AddMessage(HandshakeTypeCertificate, certificate[4:])

	// --- CertificateVerify (sign over transcript = CH+SH+EE+Cert) ---
	sig, err := SignCertificateVerify(s.serverKey, ServerCertificateVerifyContext, s.transcript.Sum())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if certVerify, err = MarshalHandshakeMessage(&CertificateVerifyMsg{SignatureScheme: SM2SigSM3, Signature: sig}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	s.transcript.AddMessage(HandshakeTypeCertificateVerify, certVerify[4:])

	// --- Finished (verify_data over transcript = CH+SH+EE+Cert+CV) ---
	serverFinishedKey, err := DeriveFinishedKey(s.serverHSTraffic)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	verifyData, err := ComputeFinishedVerifyData(serverFinishedKey, s.transcript.Sum())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if finished, err = MarshalHandshakeMessage(&FinishedMsg{VerifyData: verifyData}); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	s.transcript.AddMessage(HandshakeTypeFinished, finished[4:])

	// --- Application keys (transcript = CH..server Finished) ---
	s.masterSecret, err = DeriveMasterSecret(s.handshakeSecret)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cAP, err := DeriveSecret(s.masterSecret, LabelClientAPTraffic, s.transcript.Sum())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sAP, err := DeriveSecret(s.masterSecret, LabelServerAPTraffic, s.transcript.Sum())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.secrets.ClientApplicationKeys, err = DeriveQUICPacketKeys(cAP); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if s.secrets.ServerApplicationKeys, err = DeriveQUICPacketKeys(sAP); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return serverHello, encExt, certificate, certVerify, finished, nil
}

// HandleClientFinished verifies the client's Finished message. The application
// keys are already derived in ServerFlight.
func (s *ServerHandshaker) HandleClientFinished(cf []byte) error {
	mt, body, _, err := ReadHandshakeMessage(cf)
	if err != nil {
		return fmt.Errorf("tls13gm: read client Finished: %w", err)
	}
	if mt != HandshakeTypeFinished {
		return fmt.Errorf("tls13gm: expected client Finished, got type %d", mt)
	}
	var fin FinishedMsg
	if err := fin.unmarshalBody(body); err != nil {
		return fmt.Errorf("tls13gm: client Finished: %w", err)
	}
	// Client Finished verify_data is over the transcript CH..server Finished
	// (the client Finished not yet added).
	finishedKey, err := DeriveFinishedKey(s.clientHSTraffic)
	if err != nil {
		return err
	}
	expected, err := ComputeFinishedVerifyData(finishedKey, s.transcript.Sum())
	if err != nil {
		return err
	}
	if !equalConstantTime(expected, fin.VerifyData) {
		return fmt.Errorf("tls13gm: client Finished verify_data mismatch")
	}
	s.transcript.AddMessage(mt, body)
	return nil
}

// containsCipherSuite reports whether list offers the cipher suite want.
func containsCipherSuite(list []uint16, want uint16) bool {
	for _, c := range list {
		if c == want {
			return true
		}
	}
	return false
}

// containsUint16List reports whether a TLS vector-of-uint16 extension body
// contains want. lenSize is the width (in bytes) of the vector length prefix:
// 1 for supported_versions in ClientHello, 2 for signature_algorithms and
// supported_groups. It is tolerant of a trailing/truncated vector (it scans no
// further than the bytes present), matching how the standard library tolerates
// malformed peer lists.
func containsUint16List(data []byte, lenSize int, want uint16) bool {
	if len(data) < lenSize {
		return false
	}
	var listLen int
	if lenSize == 1 {
		listLen = int(data[0])
	} else {
		listLen = int(data[0])<<8 | int(data[1])
	}
	body := data[lenSize:]
	if listLen > len(body) {
		listLen = len(body)
	}
	for i := 0; i+1 < listLen; i += 2 {
		if uint16(body[i])<<8|uint16(body[i+1]) == want {
			return true
		}
	}
	return false
}
