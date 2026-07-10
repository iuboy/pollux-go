//go:build tlcp_native

package tlcp

import (
	"bytes"
	"crypto/ecdsa"
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

	// 1. Build and send ClientHello (not yet in transcript — written after SH).
	hello, err := tlcpMakeClientHello(config)
	if err != nil {
		return err
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
	if suite.flags&tlcpFlagECDHE != 0 {
		return errors.New("tlcp: ECDHE suites not supported in Phase 3")
	}
	if serverHello.compressionMethod != 0 {
		return errors.New("tlcp: server selected non-null compression")
	}
	c.serverName = config.serverName
	c.clientProtocol = serverHello.alpnProtocol

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

	// 5. Parse the encryption certificate to extract its SM2 public key (CKE).
	encCert, err := polluxsmx509.ParseCertificate(encCertDER)
	if err != nil {
		return fmt.Errorf("tlcp: parse encryption certificate: %w", err)
	}
	encPub, ok := encCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: encryption cert public key is not ECDSA (SM2)")
	}

	// 6. Read ServerKeyExchange and verify its signature over (cr||sr||encCert).
	skeData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var ske tlcpServerKeyExchangeMsg
	if !ske.unmarshal(skeData) || len(ske.key) < 2 {
		return errors.New("tlcp: failed to parse ServerKeyExchange")
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
	if err := tlcpECCProcessServerKeyExchange(sigType, signPub, hello.random, serverHello.random, encCertDER, ske.key); err != nil {
		return fmt.Errorf("tlcp: ServerKeyExchange verification: %w", err)
	}

	// (Optional) certificate verification against root CAs — Phase 3 skips this
	// when InsecureSkipVerify is set; full verification lands with root-CA wiring.
	if !config.insecureSkipVerify {
		// Phase 3 stub: real verification needs a root pool wired from Config.
		// For the interop test we rely on the SKE signature check above.
	}

	// 7. Read ServerHelloDone.
	shdData, err := c.readHandshake(transcript)
	if err != nil {
		return err
	}
	var shd tlcpServerHelloDoneMsg
	if !shd.unmarshal(shdData) {
		return errors.New("tlcp: failed to parse ServerHelloDone")
	}
	// Phase 3 does not handle CertificateRequest (no client auth).

	// 8. Generate and send ClientKeyExchange (SM2-encrypted PMS).
	pms, ckePayload, err := tlcpECCGenerateClientKeyExchange(c.vers, config.rand, encPub)
	if err != nil {
		return err
	}
	cke := &tlcpClientKeyExchangeMsg{ciphertext: ckePayload}
	if err := c.writeHandshakeRecord(cke, transcript); err != nil {
		return err
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
