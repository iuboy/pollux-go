package tlcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	polluxsmx509 "github.com/iuboy/pollux-go/smx509"
)

// establishKeys derives the traffic keys from the master secret and stages them
// on the in/out halfConns. Key-role assignment depends on the role:
//   - client: in decrypts server→client (server keys), out encrypts client→server (client keys)
//   - server: in decrypts client→server (client keys),  out encrypts server→client (server keys)
func (c *tlcpConn) establishKeys(suite *tlcpCipherSuite, masterSecret, clientRandom, serverRandom []byte) error {
	km := tlcpKeysFromMaster(masterSecret, clientRandom, serverRandom, suite.macLen, suite.keyLen, suite.ivLen)

	// readKeys/writeKeys are the key material for the in (read) and out (write)
	// directions respectively, from THIS endpoint's perspective.
	readMAC, readKey, readIV := km.serverMAC, km.serverKey, km.serverIV
	writeMAC, writeKey, writeIV := km.clientMAC, km.clientKey, km.clientIV
	if !c.isClient {
		readMAC, readKey, readIV = km.clientMAC, km.clientKey, km.clientIV
		writeMAC, writeKey, writeIV = km.serverMAC, km.serverKey, km.serverIV
	}

	if suite.isAEAD() {
		readAEAD, err := newTLCPAEADSM4GCM(readKey, readIV)
		if err != nil {
			return err
		}
		writeAEAD, err := newTLCPAEADSM4GCM(writeKey, writeIV)
		if err != nil {
			return err
		}
		c.in.prepareCipherSpec(c.vers, nil, readAEAD, nil, nil)
		c.out.prepareCipherSpec(c.vers, nil, writeAEAD, nil, nil)
	} else {
		c.in.prepareCipherSpec(c.vers, readKey, nil, hmacSM3Size{}, readMAC)
		c.out.prepareCipherSpec(c.vers, writeKey, nil, hmacSM3Size{}, writeMAC)
	}
	return nil
}

// hmacSM3Size satisfies the tlcpMAC interface (Size() int) for CBC suites.
type hmacSM3Size struct{}

func (hmacSM3Size) Size() int { return 32 }

// This file implements the TLCP connection and record layer (GB/T 38636-2020
// §6.3). The design follows the three-layer split: Conn (connection + record
// framing + handshake orchestration), halfConn (one-directional encryption
// state), and the handshake state machines (engine_handshake_{client,server}).
//
// Two record-protection paths are supported, selected by the negotiated suite:
//   - SM4-CBC + HMAC-SM3 (MAC-then-encrypt, TLS 1.0-style MAC)
//   - SM4-GCM prefix-nonce AEAD (RFC 5116 style)
//
// Reference: gotlcp/tlcp/conn.go (structure consulted; rewritten with a slimmer
// record layer focused on the SM4 suites).

// --- Record-layer constants (GB/T 38636-2020 §6.3.1) ---

const (
	tlcpRecordHeaderLen = 5
	tlcpMaxPlaintext    = 1 << 14 // 16384 bytes max record plaintext
)

// tlcpRecordType is the 1-byte content type in a record header.
type tlcpRecordType uint8

const (
	tlcpRecordChangeCipherSpec tlcpRecordType = 20
	tlcpRecordAlert            tlcpRecordType = 21
	tlcpRecordHandshake        tlcpRecordType = 22
	tlcpRecordApplicationData  tlcpRecordType = 23
)

// Alert level/description values (GB/T 38636-2020 §6.3.6, same numbering as
// TLS alert values).
const (
	tlcpAlertLevelWarning byte = 1
	tlcpAlertLevelError   byte = 2
	// tlcpAlertCloseNotify is the normal-close alert: Read maps it to io.EOF,
	// matching crypto/tls semantics.
	tlcpAlertCloseNotify byte = 0
	// tlcpAlertHandshakeFailure is the generic fatal alert sent on handshake
	// error paths (TLS alert value 40).
	tlcpAlertHandshakeFailure byte = 40
)

// alertError is a received alert, parsed from the DECRYPTED alert-record
// payload. readRecord returns it for any alert record; Read translates
// close_notify into io.EOF and everything else into this error.
type alertError struct {
	level byte
	desc  byte
}

func (e alertError) Error() string {
	return fmt.Sprintf("tlcp: received alert: level=%d description=%d", e.level, e.desc)
}

// errDecrypt is the single, undifferentiated record-decryption failure. All
// CBC padding/MAC failure modes surface as this error so an attacker cannot
// distinguish them (Lucky13/POODLE-style oracles need distinguishable
// failures). See decrypt's CBC branch.
var errDecrypt = errors.New("tlcp: bad record MAC")

// Handshake-message size caps, mirroring crypto/tls: a 3-byte length field
// would otherwise let a malicious peer buffer up to ~16MB per connection.
// Certificate messages legitimately carry multi-cert chains and get the
// larger cap; everything else is capped at 16KB.
const (
	maxHandshake               = 16 * 1024
	maxHandshakeCertificateMsg = 128 * 1024
)

// --- halfConn: one-directional encryption state ---

// tlcpHalfConn holds the encryption/MAC state for one direction of a TLCP
// connection. CCS uses a two-phase commit: prepareCipherSpec stages the next
// cipher/MAC, changeCipherSpec (triggered by a CCS record) activates it and
// resets the sequence number to zero.
type tlcpHalfConn struct {
	mu sync.Mutex

	version uint16

	// Current encryption state. Exactly one of cbcKey/aead is non-nil once keys
	// are established; both are nil during the initial plaintext phase. For CBC,
	// the key+IV are re-applied per record (TLCP carries a fresh IV each record).
	cbcKey      []byte // SM4 key for CBC suites
	aead        *tlcpPrefixNonceAEAD
	mac         tlcpMAC // HMAC-SM3 size interface (nil for AEAD)
	macKeyBytes []byte  // HMAC-SM3 key (CBC suites)

	seq [8]byte // 64-bit sequence number, big-endian; part of MAC/AAD, reset on CCS

	// Staged next cipher spec (activated by changeCipherSpec).
	nextCBCKey      []byte
	nextAEAD        *tlcpPrefixNonceAEAD
	nextMAC         tlcpMAC
	nextMACKeyBytes []byte
}

// tlcpMAC is the minimal interface for a CBC-suite MAC (a hash.Hash satisfies
// it). Kept as an interface so AEAD suites can use nil cleanly.
type tlcpMAC interface {
	Size() int
}

// destroy zeroes all key material held by this halfConn (connection teardown).
// The AEAD's expanded GCM subkeys live inside cipher.AEAD and cannot be
// zeroed — matching crypto/tls, which also only clears what it owns.
func (hc *tlcpHalfConn) destroy() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	zeroBytes(hc.cbcKey)
	zeroBytes(hc.macKeyBytes)
	zeroBytes(hc.nextCBCKey)
	zeroBytes(hc.nextMACKeyBytes)
}

// prepareCipherSpec stages a new cipher/MAC for activation on the next CCS.
// For CBC suites pass cbcKey + macKeyBytes; for AEAD pass aead (others nil).
func (hc *tlcpHalfConn) prepareCipherSpec(version uint16, cbcKey []byte, aead *tlcpPrefixNonceAEAD, mac tlcpMAC, macKeyBytes []byte) {
	hc.version = version
	hc.nextCBCKey = cbcKey
	hc.nextAEAD = aead
	hc.nextMAC = mac
	hc.nextMACKeyBytes = macKeyBytes
}

// changeCipherSpec activates the staged cipher/MAC and resets the sequence
// number. Called when a CCS record is sent (out) or received (in).
func (hc *tlcpHalfConn) changeCipherSpec() error {
	if hc.nextCBCKey == nil && hc.nextAEAD == nil {
		return errors.New("tlcp: changeCipherSpec without prepareCipherSpec")
	}
	hc.cbcKey = hc.nextCBCKey
	hc.aead = hc.nextAEAD
	hc.mac = hc.nextMAC
	hc.macKeyBytes = hc.nextMACKeyBytes
	hc.nextCBCKey = nil
	hc.nextAEAD = nil
	hc.nextMAC = nil
	hc.nextMACKeyBytes = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

// incSeq advances the 64-bit sequence number. Returns an error if the sequence
// number overflows (all bytes wrap to zero), which requires connection closure per
// TLS/TLCP spec (sequence numbers MUST NOT wrap).
func (hc *tlcpHalfConn) incSeq() error {
	for i := len(hc.seq) - 1; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return nil
		}
	}
	return errors.New("tlcp: sequence number overflow, connection must be terminated")
}

// encrypt seals a plaintext record payload into the on-wire ciphertext record.
// `record` is the 5-byte header (length field will be overwritten). Returns the
// full record (header + ciphertext).
func (hc *tlcpHalfConn) encrypt(record []byte, payload []byte) ([]byte, error) {
	if hc.cbcKey == nil && hc.aead == nil {
		// Plaintext phase: just append.
		return append(record, payload...), nil
	}

	switch {
	case hc.aead != nil:
		// AEAD: explicit nonce (8 bytes) = seq, AAD = seq(8) || header(5).
		explicitNonce := make([]byte, hc.aead.ExplicitNonceSize())
		copy(explicitNonce, hc.seq[:])
		aad := tlcpAEADAdditionalData(hc.seq[:], record, len(payload))
		ct := hc.aead.Seal(nil, explicitNonce, payload, aad)
		full := append(record[:tlcpRecordHeaderLen], explicitNonce...)
		full = append(full, ct...)
		binary.BigEndian.PutUint16(full[3:5], uint16(len(explicitNonce)+len(ct)))
		if err := hc.incSeq(); err != nil {
			return nil, err
		}
		return full, nil

	case hc.cbcKey != nil:
		// CBC + MAC: MAC = HMAC(seq || header || payload); then pad.
		macH := tlcpHMACSM3(hc.macKeyBytes)
		mac := tlcpRecordMAC(macH, hc.seq[:], record[:tlcpRecordHeaderLen], payload, nil)
		plaintextLen := len(payload) + len(mac)
		const blockSize = 16
		paddingLen := blockSize - plaintextLen%blockSize
		padded := make([]byte, plaintextLen+paddingLen)
		copy(padded, payload)
		copy(padded[len(payload):], mac)
		padVal := byte(paddingLen - 1)
		for i := plaintextLen; i < len(padded); i++ {
			padded[i] = padVal
		}
		// TLCP CBC carries a fresh random IV per record (first 16 bytes).
		iv := make([]byte, blockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		mode, err := newTLCPCBCEncrypter(hc.cbcKey, iv)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, len(padded))
		mode.CryptBlocks(ciphertext, padded)
		out := append(record[:tlcpRecordHeaderLen], iv...)
		out = append(out, ciphertext...)
		binary.BigEndian.PutUint16(out[3:5], uint16(len(iv)+len(ciphertext)))
		if err := hc.incSeq(); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("tlcp: no cipher configured")
}

// decrypt unwraps a received record into its plaintext payload + record type.
// `record` is the full 5-byte-header + ciphertext.
func (hc *tlcpHalfConn) decrypt(record []byte) ([]byte, tlcpRecordType, error) {
	if len(record) < tlcpRecordHeaderLen {
		return nil, 0, errors.New("tlcp: record too short")
	}
	typ := tlcpRecordType(record[0])
	payload := record[tlcpRecordHeaderLen:]

	if hc.cbcKey == nil && hc.aead == nil {
		return payload, typ, nil // plaintext phase
	}

	switch {
	case hc.aead != nil:
		enl := hc.aead.ExplicitNonceSize()
		if len(payload) < enl+1 {
			return nil, 0, errors.New("tlcp: AEAD record too short")
		}
		explicitNonce := payload[:enl]
		ct := payload[enl:]
		plaintextLen := len(ct) - hc.aead.Overhead()
		if plaintextLen < 0 {
			return nil, 0, errors.New("tlcp: AEAD record shorter than tag")
		}
		aad := tlcpAEADAdditionalData(hc.seq[:], record, plaintextLen)
		plaintext, err := hc.aead.Open(nil, explicitNonce, ct, aad)
		if err != nil {
			return nil, 0, errors.New("tlcp: bad record MAC (AEAD authentication failed)")
		}
		if err := hc.incSeq(); err != nil {
			return nil, 0, err
		}
		return plaintext, typ, nil

	case hc.cbcKey != nil:
		const blockSize = 16
		macSize := 0
		if hc.mac != nil {
			macSize = hc.mac.Size()
		}
		// A well-formed CBC record is at least one IV block plus the MAC and
		// one padding byte rounded up to a block. Shorter records fail with
		// the SAME undifferentiated error as every other decryption failure —
		// a distinguishable early exit is itself a padding-oracle signal.
		minPayload := blockSize + roundUpToBlock(macSize+1, blockSize)
		if len(payload)%blockSize != 0 || len(payload) < minPayload {
			return nil, 0, errDecrypt
		}
		iv := payload[:blockSize]
		ct := payload[blockSize:]
		mode, err := newTLCPCBCDecrypter(hc.cbcKey, iv)
		if err != nil {
			// Key-length programming error; key length is validated at
			// establishKeys, so this is not attacker-influenced. Still report
			// it as a decryption failure to keep one failure surface.
			return nil, 0, errDecrypt
		}
		plain := make([]byte, len(ct))
		mode.CryptBlocks(plain, ct)

		// Constant-time padding extraction (port of crypto/tls extractPadding):
		// a fixed 256-iteration scan, no early exit, and the padding length is
		// zeroed on error so unchecked bytes are included in the MAC below.
		paddingLen, paddingGood := tlcpExtractPadding(plain)
		n := len(plain) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		macHeader := make([]byte, tlcpRecordHeaderLen)
		copy(macHeader, record[:tlcpRecordHeaderLen])
		binary.BigEndian.PutUint16(macHeader[3:5], uint16(n))
		remoteMAC := plain[n : n+macSize]
		// The bytes past the MAC (the padding, whose length is secret) are fed
		// to the HMAC as extra data so the MAC time depends only on the public
		// record length (Lucky13 mitigation, as in crypto/tls).
		localMAC := tlcpRecordMAC(tlcpHMACSM3(hc.macKeyBytes), hc.seq[:], macHeader, plain[:n], plain[n+macSize:])
		// MAC and padding validity combine in constant time so the two failure
		// modes cannot be distinguished.
		if subtle.ConstantTimeCompare(localMAC, remoteMAC)&int(paddingGood) != 1 {
			return nil, 0, errDecrypt
		}
		if err := hc.incSeq(); err != nil {
			return nil, 0, err
		}
		return plain[:n], typ, nil
	}
	return nil, 0, errors.New("tlcp: no cipher configured")
}

// --- Conn: the TLCP connection ---

// tlcpConn is a TLCP secure connection implementing net.Conn. It owns the
// underlying transport, the two halfConns (in/out), and handshake state.
type tlcpConn struct {
	conn     net.Conn
	isClient bool
	config   *tlcpEngineConfig

	handshakeStatus uint32 // atomic; 1 after handshake complete
	handshakeMutex  sync.Mutex
	handshakeErr    error

	vers     uint16
	haveVers bool

	in, out tlcpHalfConn

	// readMu serializes Read: the input buffer and the record stream are not
	// safe for concurrent use, and net.Conn's contract permits multiple
	// goroutines to call Read simultaneously (crypto/tls serializes with an
	// in.Lock around the same surface).
	readMu sync.Mutex

	// Decrypted handshake bytes awaiting parse, and decrypted app data awaiting Read.
	hand      bytes.Buffer
	input     bytes.Buffer
	buffering atomic.Bool // coalesce handshake writes; atomic for race-safety with Close()'s alert path
	sendBuf   bytes.Buffer
	rawConn   net.Conn // net.Conn accessor

	// Result of the handshake, exposed via ConnectionState().
	cipherSuite      uint16
	peerCertificates [][]byte // DER list: [sign, enc, ...chain]
	serverName       string
	clientProtocol   string

	// Session resumption (Phase 5): a session offered by the client (loaded from
	// cache before the handshake) and, on a successful full handshake, the
	// negotiated session to store. didResume records whether this handshake
	// resumed an existing session.
	session   *SessionState
	didResume bool
}

// tlcpEngineConfig is the minimal config the native engine needs. It is
// populated by the public Config adapter in a later step; for now it carries
// the random source and cipher-suite preference.
type tlcpEngineConfig struct {
	rand               io.Reader
	cipherSuites       []uint16
	serverName         string
	insecureSkipVerify bool
	rootCAs            [][]byte               // DER certs for verification (Phase 4)
	serverCerts        *tlcpServerCerts       // server dual certificates (server mode only)
	sessionCache       SessionCache           // optional session-resumption store (Phase 5)
	clientCerts        *tlcpServerCerts       // client dual certificates (mutual auth / ECDHE)
	requestClientCert  bool                   // server: send CertificateRequest
	clientRoots        *polluxsmx509.CertPool // 客户端证书验证根池（服务端 mTLS，nil=不验）
	clientAuth         ClientAuthType         // 客户端证书校验级别（精确区分 Require/VerifyIfGiven）
}

// newTLCPConn wraps a transport connection.
func newTLCPConn(c net.Conn, config *tlcpEngineConfig, isClient bool) *tlcpConn {
	tc := &tlcpConn{
		conn:     c,
		rawConn:  c,
		isClient: isClient,
		config:   config,
	}
	return tc
}

// clientHandshake is implemented in engine_handshake_client.go (Phase 3).
// serverHandshake is implemented in engine_handshake_server.go (Phase 4).

// Handshake drives the handshake (client or server) and stores any error.
func (c *tlcpConn) Handshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if atomic.LoadUint32(&c.handshakeStatus) == 1 {
		return nil
	}
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	if c.handshakeErr == nil {
		// Flush any buffered handshake records and disable buffering so post-
		// handshake application-data writes go straight to the wire.
		_ = c.flush()
		c.buffering.Store(false)
		atomic.StoreUint32(&c.handshakeStatus, 1)
		return nil
	}
	// Best-effort fatal alert so the peer sees a protocol-level failure
	// instead of a bare TCP close (crypto/tls alerts on every handshake error
	// path). The write is bounded by a deadline; errors are ignored — the
	// handshake has already failed and Close will tear the transport down.
	_ = c.conn.SetWriteDeadline(time.Now().Add(tlcpCloseNotifyTimeout))
	_ = c.writeRecord(tlcpRecordAlert, []byte{tlcpAlertLevelError, tlcpAlertHandshakeFailure})
	_ = c.flush()
	return c.handshakeErr
}

// HandshakeContext drives the handshake, honoring context cancellation. The
// native engine does not yet support mid-handshake cancellation; the context is
// best-effort (the underlying conn deadline should be set for hard timeouts).
func (c *tlcpConn) HandshakeContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Handshake()
}

// NetConn returns the underlying transport connection.
func (c *tlcpConn) NetConn() net.Conn { return c.rawConn }

// ConnectionState returns the negotiated security parameters. Peer certificates
// are parsed from their DER via polluxsmx509 (SM2-aware).
//
// It acquires handshakeMutex so the reads of vers/cipherSuite/serverName/
// peerCertificates establish a happens-before relationship with the handshake
// that writes them (Handshake holds handshakeMutex throughout). This matches
// crypto/tls.Conn.ConnectionState, which also locks. A concurrent in-flight
// handshake will block this call until the handshake finishes — the intended
// behavior, since ConnectionState is only meaningful post-handshake.
func (c *tlcpConn) ConnectionState() tlcpEngineConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	st := tlcpEngineConnectionState{
		Version:            c.vers,
		HandshakeComplete:  atomic.LoadUint32(&c.handshakeStatus) == 1,
		CipherSuite:        c.cipherSuite,
		ServerName:         c.serverName,
		DidResume:          c.didResume,
		NegotiatedProtocol: c.clientProtocol,
	}
	for _, der := range c.peerCertificates {
		if cert, err := polluxsmx509.ParseCertificate(der); err == nil {
			st.PeerCertificates = append(st.PeerCertificates, cert)
		}
	}
	return st
}

// tlcpEngineConnectionState is the engine-level connection state, carrying
// stdlib *x509.Certificate peer certs. The public ConnectionState type (in
// tlcp.go) mirrors these fields.
type tlcpEngineConnectionState struct {
	Version            uint16
	HandshakeComplete  bool
	CipherSuite        uint16
	ServerName         string
	PeerCertificates   []*x509.Certificate
	DidResume          bool
	NegotiatedProtocol string
}

// Read reads decrypted application data. A peer close_notify maps to io.EOF
// (crypto/tls semantics); any other alert surfaces as an error.
func (c *tlcpConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if atomic.LoadUint32(&c.handshakeStatus) == 0 {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	for {
		if c.input.Len() > 0 {
			return c.input.Read(b)
		}
		payload, typ, err := c.readRecord()
		if err != nil {
			var alert alertError
			if errors.As(err, &alert) && alert.desc == tlcpAlertCloseNotify {
				return 0, io.EOF
			}
			return 0, err
		}
		switch typ {
		case tlcpRecordApplicationData:
			// bytes.Buffer.Write never returns a non-nil error.
			c.input.Write(payload)
			return c.input.Read(b)
		default:
			return 0, fmt.Errorf("tlcp: unexpected record type %d after handshake", typ)
		}
	}
}

// Write encrypts and sends application data.
func (c *tlcpConn) Write(b []byte) (int, error) {
	if atomic.LoadUint32(&c.handshakeStatus) == 0 {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	// Fragment into max-plaintext records.
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > tlcpMaxPlaintext {
			n = tlcpMaxPlaintext
		}
		if err := c.writeRecord(tlcpRecordApplicationData, b[:n]); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// tlcpCloseNotifyTimeout bounds the best-effort close_notify write. Close
// relies on conn.Close() interrupting a blocked write on TCP/net.Pipe, but
// wrapped or buffered net.Conn implementations may not interrupt it — the
// write deadline guarantees Close (and the alert goroutine) still terminate.
const tlcpCloseNotifyTimeout = 5 * time.Second

// Close sends a best-effort close_notify alert and closes the underlying
// connection, then zeroes the traffic keys held by both half-conns. Both the
// alert write and Close itself are bounded by tlcpCloseNotifyTimeout even on
// transports whose Close does not unblock a pending Write.
func (c *tlcpConn) Close() error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(tlcpCloseNotifyTimeout))
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Errors are ignored: the connection is being torn down and the peer
		// may already have closed its side.
		_ = c.writeRecord(tlcpRecordAlert, []byte{tlcpAlertLevelWarning, tlcpAlertCloseNotify})
		// If the alert landed in the handshake send buffer (close during
		// handshake), flush it so the peer actually sees the close_notify.
		_ = c.flush()
	}()
	err := c.conn.Close()
	select {
	case <-done:
	case <-time.After(tlcpCloseNotifyTimeout):
		// Pathological transport: the write deadline above still forces the
		// goroutine to exit; do not wait for it here.
	}
	c.in.destroy()
	c.out.destroy()
	return err
}

func (c *tlcpConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *tlcpConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *tlcpConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *tlcpConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *tlcpConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// --- record I/O ---

// readRecord reads one record from the wire and decrypts it. Returns the
// plaintext payload and record type. CCS records trigger in.changeCipherSpec
// transparently.
func (c *tlcpConn) readRecord() ([]byte, tlcpRecordType, error) {
	for {
		typ, header, body, err := c.readRawRecord()
		if err != nil {
			return nil, 0, err
		}
		if typ == tlcpRecordChangeCipherSpec {
			if len(body) != 1 || body[0] != 1 {
				return nil, 0, errors.New("tlcp: malformed ChangeCipherSpec")
			}
			c.in.mu.Lock()
			err := c.in.changeCipherSpec()
			c.in.mu.Unlock()
			if err != nil {
				return nil, 0, err
			}
			continue // CCS produces no application data
		}
		// Decrypt FIRST, before any per-type parsing: alerts after the CCS are
		// encrypted on the wire, and reading level/description out of the raw
		// ciphertext would both misreport the alert and leak two ciphertext
		// bytes (see readRecord's alert branch below for the parsed form).
		fullRecord := append(header, body...)
		c.in.mu.Lock()
		plaintext, _, err := c.in.decrypt(fullRecord)
		c.in.mu.Unlock()
		if err != nil {
			return nil, 0, err
		}
		if typ == tlcpRecordAlert {
			if len(plaintext) != 2 {
				return nil, 0, errors.New("tlcp: malformed alert record")
			}
			return nil, 0, alertError{level: plaintext[0], desc: plaintext[1]}
		}
		return plaintext, typ, nil
	}
}

// readRawRecord reads one complete record (header + body) from the wire. Returns
// the record type, the 5-byte header, and the body bytes.
func (c *tlcpConn) readRawRecord() (tlcpRecordType, []byte, []byte, error) {
	header := make([]byte, tlcpRecordHeaderLen)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, nil, nil, err
	}
	typ := tlcpRecordType(header[0])
	switch typ {
	case tlcpRecordChangeCipherSpec, tlcpRecordAlert, tlcpRecordHandshake, tlcpRecordApplicationData:
	default:
		// Unknown content types (heartbeat, renegotiation probes, garbage)
		// are a protocol violation — drop the connection instead of
		// silently skipping the record (crypto/tls sends unexpected_message).
		return 0, nil, nil, fmt.Errorf("tlcp: unexpected record type %d", typ)
	}
	// Version sanity on every record: TLCP uses 0x0101; some stacks send
	// TLS-style 0x03xx legacy versions. Anything else (0x0000, SSLv2 0x0002,
	// 0x02xx, …) is not a TLCP-family peer — treat as a protocol violation
	// (crypto/tls rejects bad versions with a RecordHeaderError).
	version := binary.BigEndian.Uint16(header[1:3])
	if version != tlcpVersionTLCP && (version < 0x0301 || version > 0x0303) {
		return 0, nil, nil, fmt.Errorf("tlcp: unexpected record version 0x%04x", version)
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > tlcpMaxPlaintext+2048 {
		return 0, nil, nil, errors.New("tlcp: record too large")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return 0, nil, nil, err
	}
	return typ, header, body, nil
}

// writeRecord encrypts (if keys established) and writes one record. For CCS it
// triggers out.changeCipherSpec after writing.
func (c *tlcpConn) writeRecord(typ tlcpRecordType, payload []byte) error {
	header := make([]byte, tlcpRecordHeaderLen)
	header[0] = byte(typ)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))

	c.out.mu.Lock()
	// Record-layer version: read vers/haveVers under out.mu so they stay in
	// sync with the handshake (which writes them under out.mu — see
	// engine_handshake_{client,server}.go). Close()'s alert goroutine reaches
	// here without handshakeMutex, so without this lock the reads would race
	// with a concurrent Handshake().
	recordVersion := c.vers
	if !c.haveVers {
		recordVersion = tlcpVersionTLCP
	}
	header[1] = byte(recordVersion >> 8)
	header[2] = byte(recordVersion)

	record, err := c.out.encrypt(header, payload)
	if err != nil {
		c.out.mu.Unlock()
		return err
	}

	// ChangeCipherSpec flips the output cipher immediately after the CCS record
	// is produced (it is itself sent plaintext, under the OLD/nil cipher). The
	// following record (Finished) is then encrypted with the new keys. This must
	// happen whether or not writes are buffered.
	if typ == tlcpRecordChangeCipherSpec {
		if err = c.out.changeCipherSpec(); err != nil {
			c.out.mu.Unlock()
			return err
		}
	}

	// The encrypt + write must be one atomic unit so concurrent Write calls
	// do not interleave encrypted records on the wire.
	if c.buffering.Load() {
		c.sendBuf.Write(record)
		c.out.mu.Unlock()
		return nil
	}
	_, err = c.conn.Write(record)
	c.out.mu.Unlock()
	return err
}

// writeHandshakeRecord marshals a handshake message, feeds it to the transcript
// hash (if non-nil), and writes it as a handshake record.
func (c *tlcpConn) writeHandshakeRecord(msg tlcpHandshakeMessage, transcript *tlcpFinishedHash) error {
	type marshalable interface {
		marshal() ([]byte, error)
	}
	mm, ok := msg.(marshalable)
	if !ok {
		return errors.New("tlcp: handshake message does not implement marshalable")
	}
	data, err := mm.marshal()
	if err != nil {
		return err
	}
	if transcript != nil {
		transcript.Write(data)
	}
	return c.writeRecord(tlcpRecordHandshake, data)
}

// readHandshake reads and parses one handshake message, feeding it to the
// transcript hash.
func (c *tlcpConn) readHandshake(transcript *tlcpFinishedHash) ([]byte, error) {
	for c.hand.Len() < 4 {
		payload, typ, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if typ != tlcpRecordHandshake {
			return nil, fmt.Errorf("tlcp: expected handshake record, got type %d", typ)
		}
		// bytes.Buffer.Write never returns a non-nil error.
		c.hand.Write(payload)
	}
	// Peek the length to know how many bytes the full message occupies.
	head := c.hand.Bytes()
	msgLen := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	// Cap the message size (mirrors crypto/tls): without a cap a malicious
	// peer can claim a ~16MB message and pin that much memory per connection.
	limit := maxHandshake
	if head[0] == tlcpTypeCertificate {
		limit = maxHandshakeCertificateMsg
	}
	if msgLen > limit {
		return nil, fmt.Errorf("tlcp: handshake message of length %d bytes exceeds maximum of %d bytes", msgLen, limit)
	}
	total := 4 + msgLen
	for c.hand.Len() < total {
		payload, typ, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if typ != tlcpRecordHandshake {
			return nil, fmt.Errorf("tlcp: expected handshake record, got type %d", typ)
		}
		c.hand.Write(payload)
	}
	data := make([]byte, total)
	// bytes.Buffer.Read is guaranteed to fill data: the loop above ensured
	// c.hand holds at least total bytes, and Read drains at most that many.
	_, _ = c.hand.Read(data)
	if transcript != nil {
		transcript.Write(data)
	}
	return data, nil
}

// flush sends all buffered records.
//
// It holds c.out.mu while touching c.sendBuf: writeRecord's buffering branch
// (engine_conn.go) appends to c.sendBuf under c.out.mu, and Close()'s alert
// goroutine can run concurrently with a handshake flush. Without this lock the
// two would race on the bytes.Buffer. flush is never invoked from a path that
// already holds out.mu (writeRecord's buffering branch returns without calling
// flush), so acquiring it here cannot deadlock.
func (c *tlcpConn) flush() error {
	c.out.mu.Lock()
	defer c.out.mu.Unlock()
	if c.sendBuf.Len() == 0 {
		return nil
	}
	_, err := c.conn.Write(c.sendBuf.Bytes())
	c.sendBuf.Reset()
	return err
}

// --- helpers ---

// tlcpAEADAdditionalData builds the AEAD AAD = seq(8) || header(5) with the
// header's length field rewritten to plaintextLen.
func tlcpAEADAdditionalData(seq, header []byte, plaintextLen int) []byte {
	aad := make([]byte, 0, 8+5)
	aad = append(aad, seq...)
	h := make([]byte, 5)
	copy(h, header[:5])
	binary.BigEndian.PutUint16(h[3:5], uint16(plaintextLen))
	aad = append(aad, h...)
	return aad
}

// roundUpToBlock rounds a up to the next multiple of b (a must be > 0).
// Mirrors crypto/tls roundUp.
func roundUpToBlock(a, b int) int {
	return a + (b-a%b)%b
}

// tlcpExtractPadding returns, in constant time, the number of padding bytes
// to remove (including the final padding-length byte) and a good flag that is
// 1 if the padding is valid. Port of crypto/tls extractPadding (Lucky13 /
// POODLE hardening):
//   - the scan is a fixed 256 iterations (bounded only by the public record
//     length), so the loop count does not leak the padding value;
//   - no early exit distinguishes "padding too long" from "padding byte
//     mismatch" — both collapse good to 0;
//   - the padding length is masked with good so that on invalid padding the
//     unchecked bytes are still fed into the MAC (see decrypt).
func tlcpExtractPadding(plaintext []byte) (toRemove int, paddingGood byte) {
	if len(plaintext) < 1 {
		return 0, 0
	}
	paddingLen := plaintext[len(plaintext)-1]
	t := uint(len(plaintext)-1) - uint(paddingLen)
	// if len(plaintext) >= (paddingLen+1) then the MSB of t is zero
	good := byte(int32(^t) >> 31)

	toCheck := 256
	if toCheck > len(plaintext) {
		toCheck = len(plaintext)
	}
	for i := range toCheck {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := plaintext[len(plaintext)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// AND the bits of good together and replicate the result across all bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error so unchecked bytes are included in
	// the MAC (POODLE-style guard, as in crypto/tls).
	paddingLen &= good

	return int(paddingLen) + 1, good
}

// constantTimeEq returns 1 if a and b are equal, 0 otherwise (constant-time).
func constantTimeEq(a, b []byte) int {
	return subtle.ConstantTimeCompare(a, b)
}
