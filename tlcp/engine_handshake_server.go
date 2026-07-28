//go:build tlcp_native

package tlcp

import (
	"crypto"
	"crypto/ecdsa"
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
	if suite.flags&tlcpFlagECDHE != 0 {
		return errors.New("tlcp: ECDHE suites not supported in Phase 4")
	}
	c.cipherSuite = suite.id

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

	// 6. Send ServerKeyExchange: signature over (client_random||server_random||encCert).
	sigType, err := tlcpSigTypeForSuite(suite.id)
	if err != nil {
		return err
	}
	skePayload, err := tlcpECCGenerateServerKeyExchange(sigType, certs.signSigner, clientHello.random, serverHello.random, certs.encCertDER)
	if err != nil {
		return err
	}
	ske := &tlcpServerKeyExchangeMsg{key: skePayload}
	if err := c.writeHandshakeRecord(ske, transcript); err != nil {
		return err
	}

	// 7. Send ServerHelloDone. Phase 4 does not send CertificateRequest (no
	// client auth).
	if err := c.writeHandshakeRecord(&tlcpServerHelloDoneMsg{}, transcript); err != nil {
		return err
	}
	if err := c.flush(); err != nil {
		return err
	}

	// 8. Read ClientKeyExchange and decrypt the PMS.
	ckeData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var cke tlcpClientKeyExchangeMsg
	if !cke.unmarshal(ckeData) {
		return errors.New("tlcp: failed to parse ClientKeyExchange")
	}
	pms, err := tlcpECCProcessClientKeyExchange(certs.encDecrypter, cke.ciphertext)
	if err != nil {
		return fmt.Errorf("tlcp: decrypt ClientKeyExchange: %w", err)
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

	zeroBytes(masterSecret)
	return nil
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
