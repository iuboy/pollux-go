package tlcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// This file implements the server-side TLCP full handshake for ECC cipher
// suites (GB/T 38636-2020 §6.4.5). Phase 4 scope:
//   - ECC key exchange (server decrypts the SM2-encrypted PMS)
//   - Full handshake (no session resume, no client auth yet)
//   - Dual-certificate distribution: [sign leaf, enc leaf, ...CA chain]
//
// Server full-handshake order (differs from client): the server reads the
// client Finished BEFORE sending its own Finished. Transcript feed discipline
// mirrors gotlcp: clientFinished is read with nil transcript, verified, then fed.
//
// Reference: gotlcp/tlcp/handshake_server.go (structure consulted; rewritten for
// the pollux engine).

// tlcpServerCerts carries the server's dual certificate material.
type tlcpServerCerts struct {
	signCertDER []byte        // signing certificate leaf DER
	encCertDER  []byte        // encryption certificate leaf DER
	chainDER    [][]byte      // optional CA chain DERs (appended after the two leaves)
	signSigner  crypto.Signer // signing cert private key (for SKE signature)
	encDecrypter crypto.Decrypter // encryption cert private key (for PMS decryption)
}

// serverHandshake drives the full TLCP server handshake (Phase 4: ECC suites,
// no session resume, no client auth).
func (c *tlcpConn) serverHandshakeReal() error {
	config := c.config
	if config == nil {
		return errors.New("tlcp: nil config")
	}
	certs := config.serverCerts
	if certs == nil || certs.signSigner == nil || certs.encDecrypter == nil {
		return errors.New("tlcp: server requires signing + encryption certificates")
	}

	// 1. Read ClientHello (NOT fed to transcript yet — fed below).
	chData, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	var clientHello tlcpClientHelloMsg
	if !clientHello.unmarshal(chData) {
		return errors.New("tlcp: failed to parse ClientHello")
	}
	if clientHello.version != tlcpVersionTLCP {
		return fmt.Errorf("tlcp: client version %04x, want %04x", clientHello.version, tlcpVersionTLCP)
	}
	c.vers = tlcpVersionTLCP
	c.haveVers = true
	c.serverName = clientHello.serverName

	// 2. Select a cipher suite from the client's offer and our preference.
	suite := tlcpMutualCipherSuite(config.cipherSuites, clientHello.cipherSuites)
	if suite == nil {
		return errors.New("tlcp: no common cipher suite with client")
	}
	c.cipherSuite = suite.id
	isECDHE := suite.flags&tlcpFlagECDHE != 0

	// 2b. Resume check: if the client offered a sessionId that hits our cache,
	// perform an abbreviated handshake (no Certificate/SKE/SHD), reusing the
	// cached master secret. The server sends Finished first in a resume.
	if sess := c.lookupResumedSession(&clientHello, suite); sess != nil {
		if err := c.serverResumeHandshake(suite, &clientHello, chData, sess); err != nil {
			return err
		}
		c.didResume = true
		return nil
	}

	// 3. Build ServerHello.
	serverRandom := make([]byte, 32)
	binary.BigEndian.PutUint32(serverRandom, uint32(time.Now().Unix()))
	if _, err := io.ReadFull(config.rand, serverRandom[4:]); err != nil {
		return err
	}
	sessionID := make([]byte, 32)
	if _, err := io.ReadFull(config.rand, sessionID); err != nil {
		return err
	}
	serverHello := &tlcpServerHelloMsg{
		version:           tlcpVersionTLCP,
		random:            serverRandom,
		sessionID:         sessionID,
		cipherSuite:       suite.id,
		compressionMethod: 0,
	}

	// 4. Initialize transcript and feed ClientHello + ServerHello.
	transcript := newTLCPFinishedHash()
	transcript.Write(chData)

	c.buffering = true
	if err := c.writeHandshakeRecord(serverHello, transcript); err != nil {
		return err
	}

	// 5. Send Certificate [sign leaf, enc leaf, ...chain].
	certMsg := &tlcpCertificateMsg{
		certificates: [][]byte{certs.signCertDER, certs.encCertDER},
	}
	certMsg.certificates = append(certMsg.certificates, certs.chainDER...)
	if err := c.writeHandshakeRecord(certMsg, transcript); err != nil {
		return err
	}

	// 6. Send ServerKeyExchange (ECC: signature over cr||sr||encCert; ECDHE:
	// ephemeral key + signature over cr||sr||ECDHEParams).
	sigType, err := tlcpSigTypeForSuite(suite.id)
	if err != nil {
		return err
	}
	var ecdheState *tlcpECDHEServerKeyExchange
	var skePayload []byte
	if isECDHE {
		ecdheState, skePayload, err = tlcpECDHEServerGenerateSKE(sigType, certs.signSigner, certs.encDecrypter, clientHello.random, serverHello.random)
	} else {
		skePayload, err = tlcpECCGenerateServerKeyExchange(sigType, certs.signSigner, clientHello.random, serverHello.random, certs.encCertDER)
	}
	if err != nil {
		return err
	}
	ske := &tlcpServerKeyExchangeMsg{key: skePayload}
	if err := c.writeHandshakeRecord(ske, transcript); err != nil {
		return err
	}

	// 6b. Send CertificateRequest if the server requests client auth (ECDHE
	// mandates mutual auth; ECC optionally).
	wantClientCert := config.requestClientCert || isECDHE
	if wantClientCert {
		cr := &tlcpCertificateRequestMsg{
			certificateTypes: []byte{tlcpCertTypeECDSA},
		}
		if err := c.writeHandshakeRecord(cr, transcript); err != nil {
			return err
		}
	}

	// 7. Send ServerHelloDone.
	if err := c.writeHandshakeRecord(&tlcpServerHelloDoneMsg{}, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	// 7b. Read optional client Certificate (if we sent CertificateRequest).
	var clientSignPub *ecdsa.PublicKey
	var clientEncPub *ecdsa.PublicKey
	var clientSignCert *x509.Certificate
	if wantClientCert {
		ccData, err := c.readHandshake(transcript)
		if err != nil {
			return err
		}
		var cc tlcpCertificateMsg
		if !cc.unmarshal(ccData) {
			return errors.New("tlcp: failed to parse client Certificate")
		}
		if len(cc.certificates) > 0 {
			clientSignCert, err = polluxsmx509.ParseCertificate(cc.certificates[0])
			if err != nil {
				return fmt.Errorf("tlcp: parse client sign cert: %w", err)
			}
			pub, ok := clientSignCert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("tlcp: client sign cert not ECDSA")
			}
			clientSignPub = pub
		}
		if len(cc.certificates) >= 2 {
			clientEncCert, err := polluxsmx509.ParseCertificate(cc.certificates[1])
			if err != nil {
				return fmt.Errorf("tlcp: parse client enc cert: %w", err)
			}
			pub, ok := clientEncCert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("tlcp: client enc cert not ECDSA")
			}
			clientEncPub = pub
		}
		if isECDHE && clientEncPub == nil {
			return errors.New("tlcp: ECDHE requires a client encryption certificate")
		}
		// 客户端签名证书链校验：防 rogue（不受信 CA 签发的）客户端证书。
		// CertificateVerify 只证明私钥持有，不证明 CA 信任链；此处补链校验。
		// config.clientRoots 仅在 ClientAuth >= VerifyClientCertIfGiven 且配置了
		// ClientCACertificates 时非 nil。
		if config.clientRoots != nil {
			// RequireAndVerifyClientCert：客户端必须给证书且通过校验。
			if config.clientAuth >= RequireAndVerifyClientCert && clientSignCert == nil {
				return errors.New("tlcp: client did not provide a certificate")
			}
			// VerifyClientCertIfGiven / RequireAndVerifyClientCert：给了就验。
			if clientSignCert != nil {
				if err := polluxsmx509.Verify(clientSignCert, polluxsmx509.VerifyOptions{
					Roots: config.clientRoots,
				}); err != nil {
					return fmt.Errorf("tlcp: client certificate verification failed: %w", err)
				}
			}
		}
	}

	// 8. Read ClientKeyExchange and derive the PMS (ECC: decrypt SM2-encrypted
	// PMS; ECDHE: MQV from client ephemeral + long-term keys).
	ckeData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var cke tlcpClientKeyExchangeMsg
	if !cke.unmarshal(ckeData) {
		return errors.New("tlcp: failed to parse ClientKeyExchange")
	}
	var pms []byte
	if isECDHE {
		pms, err = tlcpECDHEServerProcessCKE(ecdheState, clientEncPub, cke.ciphertext)
	} else {
		pms, err = tlcpECCProcessClientKeyExchange(certs.encDecrypter, cke.ciphertext)
	}
	if err != nil {
		return fmt.Errorf("tlcp: ClientKeyExchange: %w", err)
	}

	// 8b. Read and verify CertificateVerify (if the client sent a certificate).
	if wantClientCert && clientSignPub != nil {
		cvData, err := c.readHandshake(nil)
		if err != nil {
			return err
		}
		var cv tlcpCertificateVerifyMsg
		if !cv.unmarshal(cvData) {
			return errors.New("tlcp: failed to parse CertificateVerify")
		}
		signed := transcript.sum()
		if err := tlcpVerifyHandshakeSignature(sigType, clientSignPub, signed, cv.signature); err != nil {
			return fmt.Errorf("tlcp: invalid CertificateVerify signature: %w", err)
		}
		transcript.Write(cvData)
	}

	masterSecret := tlcpMasterFromPreMaster(pms, clientHello.random, serverHello.random)
	zeroBytes(pms)

	// 9. Derive traffic keys (server: in=client keys, out=server keys).
	if err := c.establishKeys(suite, masterSecret, clientHello.random, serverHello.random); err != nil {
		return err
	}

	// 10. Read client CCS + Finished (verify clientSum), then feed.
	if err := c.readClientCCSAndFinished(transcript, masterSecret); err != nil {
		return err
	}

	// 11. Send server CCS + Finished (serverSum).
	c.buffering = true
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.serverSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	// 12. Cache the session for future resumption (full handshake only).
	c.createNewServerSession(serverHello, masterSecret)

	zeroBytes(masterSecret)
	return nil
}

// lookupResumedSession checks the session cache for the client's offered
// sessionId. Returns the cached session if it matches the negotiated version
// and cipher suite, else nil.
func (c *tlcpConn) lookupResumedSession(clientHello *tlcpClientHelloMsg, suite *tlcpCipherSuite) *tlcpSessionState {
	if c.config == nil || c.config.sessionCache == nil || len(clientHello.sessionID) == 0 {
		return nil
	}
	sess, ok := c.config.sessionCache.Get(tlcpSessionKeyHex(clientHello.sessionID))
	if !ok || sess == nil {
		return nil
	}
	if sess.version != c.vers || sess.cipherSuite != suite.id {
		return nil
	}
	return sess
}

// serverResumeHandshake drives the server-side abbreviated (resume) handshake.
// Resume ordering (opposite of full): send ServerHello (echoed sessionId) →
// establishKeys → send server CCS+Finished → read client CCS+Finished. The
// transcript covers only ClientHello + ServerHello. masterSecret comes from
// the cached session.
func (c *tlcpConn) serverResumeHandshake(suite *tlcpCipherSuite, clientHello *tlcpClientHelloMsg, chData []byte, sess *tlcpSessionState) error {
	serverRandom := make([]byte, 32)
	binary.BigEndian.PutUint32(serverRandom, uint32(time.Now().Unix()))
	if _, err := io.ReadFull(c.config.rand, serverRandom[4:]); err != nil {
		return err
	}
	serverHello := &tlcpServerHelloMsg{
		version:           tlcpVersionTLCP,
		random:            serverRandom,
		sessionID:         clientHello.sessionID, // echo the same sessionId
		cipherSuite:       suite.id,
		compressionMethod: 0,
	}

	transcript := newTLCPFinishedHash()
	transcript.Write(chData)

	c.buffering = true
	if err := c.writeHandshakeRecord(serverHello, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	c.peerCertificates = sess.peerCertificates
	masterSecret := make([]byte, len(sess.masterSecret))
	copy(masterSecret, sess.masterSecret)

	if err := c.establishKeys(suite, masterSecret, clientHello.random, serverHello.random); err != nil {
		return err
	}

	// Resume: server sends Finished first, then reads the client's.
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.serverSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	if err := c.readClientCCSAndFinished(transcript, masterSecret); err != nil {
		return err
	}

	zeroBytes(masterSecret)
	return nil
}

// createNewServerSession stores the freshly negotiated session so a later
// connection offering the same sessionId can resume. Only called after a
// successful full handshake.
func (c *tlcpConn) createNewServerSession(serverHello *tlcpServerHelloMsg, masterSecret []byte) {
	if c.config == nil || c.config.sessionCache == nil {
		return
	}
	msCopy := make([]byte, len(masterSecret))
	copy(msCopy, masterSecret)
	peerCertsCopy := make([][]byte, len(c.peerCertificates))
	copy(peerCertsCopy, c.peerCertificates)
	sess := &tlcpSessionState{
		sessionID:       serverHello.sessionID,
		version:         c.vers,
		cipherSuite:     c.cipherSuite,
		masterSecret:    msCopy,
		peerCertificates: peerCertsCopy,
		createdAt:       time.Now(),
	}
	c.config.sessionCache.Put(tlcpSessionKeyHex(sess.sessionID), sess)
}

// readClientCCSAndFinished reads the client's CCS (switching c.in to client
// keys) and Finished, verifying the client's verify_data. The Finished is read
// with nil transcript (verified before feeding).
func (c *tlcpConn) readClientCCSAndFinished(transcript *tlcpFinishedHash, masterSecret []byte) error {
	finData, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	var fin tlcpFinishedMsg
	if !fin.unmarshal(finData) {
		return errors.New("tlcp: failed to parse client Finished")
	}
	want := transcript.clientSum(masterSecret)
	if constantTimeEq(fin.verifyData, want) != 1 {
		return fmt.Errorf("tlcp: client's Finished verify_data mismatch (got %x want %x)", fin.verifyData, want)
	}
	transcript.Write(finData)
	return nil
}

// serverHandshake replaces the conn.go stub.
func (c *tlcpConn) serverHandshake() error { return c.serverHandshakeReal() }

// ensure imports referenced by the conditional paths don't go unused.
var _ = ecdsa.PublicKey{}
var _ = polluxsmx509.ParseCertificate
