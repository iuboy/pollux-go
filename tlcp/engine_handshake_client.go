package tlcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// This file implements the client-side TLCP full handshake for ECC cipher
// suites (GB/T 38636-2020 §6.4.5). Phase 3 scope:
//   - ECC key exchange (SM2 public-key encryption of the PMS)
//   - Full handshake (no session resume, no client auth yet)
//   - Dual-certificate parsing and (optional) verification
//
// The handshake follows the standard TLS 1.2 full-handshake flow with TLCP's
// dual-certificate twist: the server sends two certificates ([sign, enc]) and
// the client encrypts the PMS with the encryption cert's SM2 public key.
//
// Reference: gotlcp/tlcp/handshake_client.go (structure consulted; rewritten for
// the pollux engine using the Phase 1/2 primitives).

// --- ClientHello construction ---

// tlcpMakeClientHello builds the ClientHello message. Phase 3 advertises the
// ECC SM4 suites, SM2 curve, and the SM2+SM3 signature algorithm.
func tlcpMakeClientHello(config *tlcpEngineConfig) (*tlcpClientHelloMsg, error) {
	suites := config.cipherSuites
	if len(suites) == 0 {
		suites = []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3}
	}
	random := make([]byte, 32)
	// Per TLCP (like TLS 1.2), the first 4 bytes carry gmt_unix_time.
	binary.BigEndian.PutUint32(random, uint32(time.Now().Unix()))
	if _, err := io.ReadFull(config.rand, random[4:]); err != nil {
		return nil, err
	}
	return &tlcpClientHelloMsg{
		version:                      tlcpVersionTLCP,
		random:                       random,
		sessionID:                    nil, // Phase 3: no session resume
		cipherSuites:                 suites,
		compressionMethods:           []uint8{0}, // null compression
		serverName:                   config.serverName,
		supportedCurves:              []tlcpCurveID{tlcpCurveSM2},
		supportedSignatureAlgorithms: []tlcpSignatureScheme{tlcpSigSM2WithSM3},
	}, nil
}

// --- Client handshake driver ---

// clientHandshake drives the full TLCP client handshake (Phase 3: ECC suites,
// no session resume, no client auth). On success the connection's in/out half
// conns hold the negotiated traffic keys and handshakeStatus is set by the
// caller (Handshake).
func (c *tlcpConn) clientHandshakeReal() error {
	config := c.config
	if config == nil {
		return errors.New("tlcp: nil config")
	}

	// 0. Load a cached session (by remote address) so we can offer to resume.
	if config.sessionCache != nil && c.isClient {
		if sess, ok := config.sessionCache.Get(c.conn.RemoteAddr().String()); ok && sess != nil {
			c.session = sess
		}
	}

	// 1. Build and send ClientHello (not yet in transcript — written after SH).
	hello, err := tlcpMakeClientHello(config)
	if err != nil {
		return err
	}
	// If we have a cached session, advertise its sessionId to offer resumption.
	if c.session != nil {
		hello.sessionID = c.session.sessionID
	}
	if err := c.writeRecord(tlcpRecordHandshake, mustMarshal(hello)); err != nil {
		return err
	}

	// 2. Read ServerHello.
	shData, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	var serverHello tlcpServerHelloMsg
	if !serverHello.unmarshal(shData) {
		return errors.New("tlcp: failed to parse ServerHello")
	}
	if serverHello.version != tlcpVersionTLCP {
		return fmt.Errorf("tlcp: server chose version %04x, want %04x", serverHello.version, tlcpVersionTLCP)
	}
	c.vers = serverHello.version
	c.haveVers = true
	c.cipherSuite = serverHello.cipherSuite

	suite := tlcpLookupCipherSuite(serverHello.cipherSuite)
	if suite == nil {
		return fmt.Errorf("tlcp: server selected unknown cipher suite %04x", serverHello.cipherSuite)
	}
	// Verify the server's choice is one we actually offered, preventing
	// downgrade attacks where a malicious server selects a suite the client
	// did not advertise.
	offers := hello.cipherSuites
	if len(offers) == 0 {
		offers = config.cipherSuites
	}
	suiteOffered := false
	for _, id := range offers {
		if id == serverHello.cipherSuite {
			suiteOffered = true
			break
		}
	}
	if !suiteOffered {
		return fmt.Errorf("tlcp: server selected cipher suite %04x that was not offered", serverHello.cipherSuite)
	}
	if serverHello.compressionMethod != 0 {
		return errors.New("tlcp: server selected non-null compression")
	}
	c.serverName = config.serverName
	c.clientProtocol = serverHello.alpnProtocol

	// 2b. Resume branch: server echoed our sessionId and we have a matching
	// cached session. Skip the full handshake and reuse the cached master secret.
	if c.serverResumedSession(&serverHello) {
		if err := c.clientResumeHandshake(suite, hello, &serverHello, shData); err != nil {
			c.discardSession()
			return err
		}
		c.didResume = true
		return nil
	}
	// If we offered a session but the server declined (different/empty sessionId),
	// drop the cached reference — a fresh full handshake follows.
	c.session = nil

	// 3. Initialize transcript and feed ClientHello + ServerHello.
	transcript := newTLCPFinishedHash()
	transcript.Write(mustMarshal(hello))
	transcript.Write(shData)

	// 4. Read Certificate (dual: [sign, enc, ...chain]).
	certData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var certMsg tlcpCertificateMsg
	if !certMsg.unmarshal(certData) || len(certMsg.certificates) < 2 {
		return errors.New("tlcp: server did not present a dual certificate pair")
	}
	signCertDER := certMsg.certificates[0]
	encCertDER := certMsg.certificates[1]
	c.peerCertificates = certMsg.certificates

	// 5. Parse the encryption certificate to extract its SM2 public key.
	encCert, err := polluxsmx509.ParseCertificate(encCertDER)
	if err != nil {
		return fmt.Errorf("tlcp: parse encryption certificate: %w", err)
	}
	encPub, ok := encCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: encryption cert public key is not ECDSA (SM2)")
	}
	signCert, err := polluxsmx509.ParseCertificate(signCertDER)
	if err != nil {
		return fmt.Errorf("tlcp: parse signing certificate: %w", err)
	}
	signPub, ok := signCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: signing cert public key is not ECDSA (SM2)")
	}
	sigType, err := tlcpSigTypeForSuite(suite.id)
	if err != nil {
		return err
	}
	isECDHE := suite.flags&tlcpFlagECDHE != 0

	// 6. Read ServerKeyExchange and verify its signature.
	skeData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var ske tlcpServerKeyExchangeMsg
	if !ske.unmarshal(skeData) || len(ske.key) < 2 {
		return errors.New("tlcp: failed to parse ServerKeyExchange")
	}
	var ecdheState *tlcpECDHEClientState
	if isECDHE {
		ecdheState, err = tlcpECDHEClientProcessSKE(sigType, signPub, hello.random, serverHello.random, ske.key)
		if err != nil {
			return fmt.Errorf("tlcp: ECDHE ServerKeyExchange: %w", err)
		}
	} else {
		if err := tlcpECCProcessServerKeyExchange(sigType, signPub, hello.random, serverHello.random, encCertDER, ske.key); err != nil {
			return fmt.Errorf("tlcp: ServerKeyExchange verification: %w", err)
		}
	}

	// 6b. Verify the server's dual-certificate chain against configured root CAs.
	if !config.insecureSkipVerify {
		roots := polluxsmx509.NewCertPool()
		for _, raw := range config.rootCAs {
			if rc, err := polluxsmx509.ParseCertificate(raw); err == nil {
				roots.AddCert(rc)
			}
		}
		// Verify the signing certificate chain (used for ServerKeyExchange/
		// CertificateVerify signatures) against the root pool.
		if err := polluxsmx509.Verify(signCert, polluxsmx509.VerifyOptions{
			Roots:     roots,
			DNSName:   config.serverName,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("tlcp: server certificate verification failed: %w", err)
		}
		// Verify the encryption certificate chain as well.
		if err := polluxsmx509.Verify(encCert, polluxsmx509.VerifyOptions{
			Roots:     roots,
			DNSName:   config.serverName,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("tlcp: server encryption certificate verification failed: %w", err)
		}
		// Verify dual-cert pairing constraints (same CA, correct key usages).
		if err := polluxsmx509.VerifyDualCerts(signCert, encCert); err != nil {
			return fmt.Errorf("tlcp: dual certificate pair validation failed: %w", err)
		}
	}

	// 7. Read optional CertificateRequest, then ServerHelloDone.
	nextData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	certRequested := false
	var crData []byte
	if nextData[0] == tlcpTypeCertificateRequest {
		certRequested = true
		crData = nextData
		var cr tlcpCertificateRequestMsg
		if !cr.unmarshal(crData) {
			return errors.New("tlcp: failed to parse CertificateRequest")
		}
		nextData, err = c.readHandshake(transcript)
		if err != nil {
			return err
		}
	}
	var shd tlcpServerHelloDoneMsg
	if !shd.unmarshal(nextData) {
		return errors.New("tlcp: failed to parse ServerHelloDone")
	}

	// 7b. If the server requested a certificate, send a Certificate message.
	// Per TLS/TLCP, after a CertificateRequest the client MUST send a
	// Certificate message (which may be empty) to avoid handshake desync.
	var pms []byte
	if certRequested {
		var certs [][]byte
		if config.clientCerts != nil {
			certs = [][]byte{config.clientCerts.signCertDER, config.clientCerts.encCertDER}
		}
		clientCertMsg := &tlcpCertificateMsg{certificates: certs}
		if err := c.writeHandshakeRecord(clientCertMsg, transcript); err != nil {
			return err
		}
	}

	// 8. Generate and send ClientKeyExchange (ECC: SM2-encrypted PMS; ECDHE:
	// ephemeral key + MQV-derived PMS).
	var ckePayload []byte
	if isECDHE {
		if config.clientCerts == nil || config.clientCerts.encDecrypter == nil {
			return errors.New("tlcp: ECDHE requires a client encryption certificate")
		}
		pms, ckePayload, err = tlcpECDHEClientGenerateCKE(ecdheState, config.clientCerts.encDecrypter, encPub)
	} else {
		pms, ckePayload, err = tlcpECCGenerateClientKeyExchange(c.vers, config.rand, encPub)
	}
	if err != nil {
		return err
	}
	cke := &tlcpClientKeyExchangeMsg{ciphertext: ckePayload}
	if err := c.writeHandshakeRecord(cke, transcript); err != nil {
		return err
	}

	// 8b. Send CertificateVerify (if we sent a client signing cert): SM2 sign
	// over the transcript hash up to this point.
	if certRequested && config.clientCerts != nil && config.clientCerts.signSigner != nil {
		signed := transcript.sum()
		sig, err := tlcpSignHandshake(config.rand, sigType, config.clientCerts.signSigner, signed)
		if err != nil {
			return err
		}
		cv := &tlcpCertificateVerifyMsg{signature: sig}
		if err := c.writeHandshakeRecord(cv, transcript); err != nil {
			return err
		}
	}

	// 9. Derive master secret and establish traffic keys.
	masterSecret := tlcpMasterFromPreMaster(pms, hello.random, serverHello.random)
	zeroBytes(pms)
	if err := c.establishKeys(suite, masterSecret, hello.random, serverHello.random); err != nil {
		return err
	}

	// 10. Send CCS + client Finished (buffered, then flushed).
	c.buffering = true
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.clientSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	// 11. Read server CCS + Finished.
	if err := c.readServerCCSAndFinished(transcript, masterSecret); err != nil {
		return err
	}

	// 12. Cache the session for future resumption (full handshake only).
	c.createNewClientSession(&serverHello, masterSecret)

	zeroBytes(masterSecret)
	return nil
}

// serverResumedSession reports whether the server agreed to resume the session
// the client offered. Requires a cached session, a non-empty echoed sessionId
// in ServerHello, and that the two sessionIds match (GB/T 38636-2020 §6.4.5.3).
func (c *tlcpConn) serverResumedSession(serverHello *tlcpServerHelloMsg) bool {
	return c.session != nil &&
		len(c.session.sessionID) > 0 &&
		len(serverHello.sessionID) > 0 &&
		bytes.Equal(serverHello.sessionID, c.session.sessionID) &&
		serverHello.version == c.session.version &&
		serverHello.cipherSuite == c.session.cipherSuite
}

// discardSession removes the offered session from the cache after a failed
// resume attempt (GB/T 38636-2020 §6.4.5.2.1: a session is invalidated on
// handshake error).
func (c *tlcpConn) discardSession() {
	if c.config == nil || c.config.sessionCache == nil || c.session == nil {
		return
	}
	key := tlcpSessionKeyHex(c.session.sessionID)
	c.config.sessionCache.Put(key, nil)
	c.config.sessionCache.Put(c.conn.RemoteAddr().String(), nil)
	c.session = nil
}

// createNewClientSession stores the freshly negotiated session so a subsequent
// connection to the same peer can resume. Only called after a successful full
// handshake (resume does not refresh the cache).
func (c *tlcpConn) createNewClientSession(serverHello *tlcpServerHelloMsg, masterSecret []byte) {
	if c.config == nil || c.config.sessionCache == nil {
		return
	}
	msCopy := make([]byte, len(masterSecret))
	copy(msCopy, masterSecret)
	peerCertsCopy := make([][]byte, len(c.peerCertificates))
	copy(peerCertsCopy, c.peerCertificates)
	sess := &tlcpSessionState{
		sessionID:        serverHello.sessionID,
		version:          c.vers,
		cipherSuite:      c.cipherSuite,
		masterSecret:     msCopy,
		peerCertificates: peerCertsCopy,
		createdAt:        time.Now(),
	}
	key := tlcpSessionKeyHex(sess.sessionID)
	c.config.sessionCache.Put(key, sess)
	c.config.sessionCache.Put(c.conn.RemoteAddr().String(), sess)
}

// clientResumeHandshake drives the client-side abbreviated (resume) handshake.
// Resume ordering (opposite of full): establishKeys → read server CCS+Finished
// → send client CCS+Finished. The transcript covers only ClientHello +
// ServerHello. masterSecret comes from the cached session (no re-derivation).
func (c *tlcpConn) clientResumeHandshake(suite *tlcpCipherSuite, hello *tlcpClientHelloMsg, serverHello *tlcpServerHelloMsg, shData []byte) error {
	transcript := newTLCPFinishedHash()
	transcript.Write(mustMarshal(hello))
	transcript.Write(shData)

	masterSecret := make([]byte, len(c.session.masterSecret))
	copy(masterSecret, c.session.masterSecret)
	c.peerCertificates = c.session.peerCertificates

	if err := c.establishKeys(suite, masterSecret, hello.random, serverHello.random); err != nil {
		return err
	}

	// Resume: server sends its Finished first, client reads then sends its own.
	if err := c.readServerCCSAndFinished(transcript, masterSecret); err != nil {
		return err
	}

	c.buffering = true
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.clientSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	zeroBytes(masterSecret)
	return nil
}

// establishKeys and hmacSM3Size are defined in engine_conn.go (shared by
// client + server handshake drivers).

// readServerCCSAndFinished reads the server's ChangeCipherSpec (switching the
// input cipher) and Finished message, verifying the server's verify_data.
func (c *tlcpConn) readServerCCSAndFinished(transcript *tlcpFinishedHash, masterSecret []byte) error {
	// The serverFinished is read WITHOUT feeding the transcript (nil), because
	// serverSum must cover the transcript state up to (but not including) the
	// serverFinished itself. Mirrors gotlcp readFinished (nil then transcriptMsg).
	finData, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	var fin tlcpFinishedMsg
	if !fin.unmarshal(finData) {
		return errors.New("tlcp: failed to parse server Finished")
	}
	want := transcript.serverSum(masterSecret)
	if constantTimeEq(fin.verifyData, want) != 1 {
		return fmt.Errorf("tlcp: server's Finished verify_data mismatch (got %x want %x)", fin.verifyData, want)
	}
	// Now feed the verified serverFinished into the transcript.
	transcript.Write(finData)
	return nil
}

// mustMarshal panics on marshal error (used for ClientHello which is freshly built).
func mustMarshal(m interface{ marshal() ([]byte, error) }) []byte {
	b, err := m.marshal()
	if err != nil {
		panic(err)
	}
	return b
}

// zeroBytes overwrites b with zeros (sensitive material).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Replace the conn.go clientHandshake stub with the real driver (build-tag
// guard ensures single definition).
func (c *tlcpConn) clientHandshake() error { return c.clientHandshakeReal() }

// ensure unused imports don't break the build when features are added later.
var (
	_ = bytes.Compare
	_ = big.NewInt
	_ = net.IPv4
)
