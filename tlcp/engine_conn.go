//go:build tlcp_native

package tlcp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// cryptoRandReader is the default RNG (crypto/rand) for record IVs.
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) { return rand.Read(p) }

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

// --- halfConn: one-directional encryption state ---

// tlcpHalfConn holds the encryption/MAC state for one direction of a TLCP
// connection. CCS uses a two-phase commit: prepareCipherSpec stages the next
// cipher/MAC, changeCipherSpec (triggered by a CCS record) activates it and
// resets the sequence number to zero.
type tlcpHalfConn struct {
	mu  sync.Mutex
	err error // first permanent error on this direction

	version uint16

	// Current encryption state. Exactly one of cbcKey/aead is non-nil once keys
	// are established; both are nil during the initial plaintext phase. For CBC,
	// the key+IV are re-applied per record (TLCP carries a fresh IV each record).
	cbcKey     []byte          // SM4 key for CBC suites
	aead       *tlcpPrefixNonceAEAD
	mac        tlcpMAC         // HMAC-SM3 size interface (nil for AEAD)
	macKeyBytes []byte         // HMAC-SM3 key (CBC suites)

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

// isAEAD reports whether this halfConn uses an AEAD cipher.
func (hc *tlcpHalfConn) isAEAD() bool { return hc.aead != nil }

// explicitNonceLen returns the per-record explicit-nonce byte count: 8 for AEAD
// (the prefix-nonce explicit part), the block size (16) for CBC (carries the
// IV), 0 otherwise.
func (hc *tlcpHalfConn) explicitNonceLen() int {
	switch {
	case hc.aead != nil:
		return hc.aead.ExplicitNonceSize()
	case hc.cbcKey != nil:
		return 16 // SM4 block size
	}
	return 0
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

// incSeq advances the 64-bit sequence number. It does NOT wrap (matching TLS
// behavior: a connection must be renegotiated before seq overflows).
func (hc *tlcpHalfConn) incSeq() {
	for i := len(hc.seq) - 1; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}
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
		hc.incSeq()
		return full, nil

	case hc.cbcKey != nil:
		// CBC + MAC: MAC = HMAC(seq || header || payload); then pad.
		macH := tlcpHMACSM3(hc.macKeyBytes)
		mac := tlcpRecordMAC(macH, nil, hc.seq[:], record[:tlcpRecordHeaderLen], payload)
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
		if _, err := io.ReadFull(randReader, iv); err != nil {
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
		hc.incSeq()
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
		hc.incSeq()
		return plaintext, typ, nil

	case hc.cbcKey != nil:
		const blockSize = 16
		if len(payload) < blockSize {
			return nil, 0, errors.New("tlcp: CBC record too short")
		}
		iv := payload[:blockSize]
		ct := payload[blockSize:]
		if len(ct)%blockSize != 0 {
			return nil, 0, errors.New("tlcp: CBC ciphertext not block-aligned")
		}
		mode, err := newTLCPCBCDecrypter(hc.cbcKey, iv)
		if err != nil {
			return nil, 0, err
		}
		plain := make([]byte, len(ct))
		mode.CryptBlocks(plain, ct)

		paddingLen, paddingGood := tlcpExtractPadding(plain, blockSize)
		macSize := 0
		if hc.mac != nil {
			macSize = hc.mac.Size()
		}
		if len(plain) < macSize+paddingLen {
			return nil, 0, errors.New("tlcp: CBC record shorter than MAC+padding")
		}
		dataLen := len(plain) - macSize - paddingLen
		if dataLen < 0 {
			dataLen = 0
		}
		macHeader := make([]byte, tlcpRecordHeaderLen)
		copy(macHeader, record[:tlcpRecordHeaderLen])
		binary.BigEndian.PutUint16(macHeader[3:5], uint16(dataLen))
		remoteMAC := plain[dataLen : dataLen+macSize]
		localMAC := tlcpRecordMAC(tlcpHMACSM3(hc.macKeyBytes), nil, hc.seq[:], macHeader, plain[:dataLen])
		macGood := constantTimeEq(localMAC, remoteMAC)
		if macGood == 0 || paddingGood == 0 {
			return nil, 0, errors.New("tlcp: bad record MAC")
		}
		hc.incSeq()
		return plain[:dataLen], typ, nil
	}
	return nil, 0, errors.New("tlcp: no cipher configured")
}

// macKeyBytes holds the HMAC-SM3 key (CBC suites); nil for AEAD. Set during
// establishKeys alongside prepareCipherSpec.
type tlcpHalfConnMACKeyOwner = *tlcpHalfConn

// extend tlcpHalfConn with macKeyBytes via a method-less field below.

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

	// Decrypted handshake bytes awaiting parse, and decrypted app data awaiting Read.
	hand       bytes.Buffer
	input      bytes.Buffer
	rawInput   bytes.Buffer // pending raw record bytes (incomplete reads)
	buffering  bool         // coalesce handshake writes
	sendBuf    bytes.Buffer
	rawConn    net.Conn // net.Conn accessor

	// Result of the handshake, exposed via ConnectionState().
	cipherSuite      uint16
	peerCertificates [][]byte // DER list: [sign, enc, ...chain]
	serverName       string
	clientProtocol   string

	// Session resumption (Phase 5): a session offered by the client (loaded from
	// cache before the handshake) and, on a successful full handshake, the
	// negotiated session to store. didResume records whether this handshake
	// resumed an existing session.
	session   *tlcpSessionState
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
	rootCAs            [][]byte          // DER certs for verification (Phase 4)
	serverCerts        *tlcpServerCerts  // server dual certificates (server mode only)
	sessionCache       tlcpSessionCache  // optional session-resumption store (Phase 5)
	clientCerts        *tlcpServerCerts  // client dual certificates (mutual auth / ECDHE)
	requestClientCert  bool              // server: send CertificateRequest
}

// newTLCPConn wraps a transport connection.
func newTLCPConn(c net.Conn, config *tlcpEngineConfig, isClient bool) *tlcpConn {
	tc := &tlcpConn{
		conn:     c,
		rawConn:  c,
		isClient: isClient,
		config:   config,
	}
	if config != nil && config.rand != nil {
		randReader = config.rand
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
		c.buffering = false
		atomic.StoreUint32(&c.handshakeStatus, 1)
	}
	return c.handshakeErr
}

// Read reads decrypted application data.
func (c *tlcpConn) Read(b []byte) (int, error) {
	if atomic.LoadUint32(&c.handshakeStatus) == 0 {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	if c.input.Len() > 0 {
		return c.input.Read(b)
	}
	// Read and decrypt the next application-data record.
	for {
		payload, typ, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch typ {
		case tlcpRecordApplicationData:
			c.input.Write(payload)
			return c.input.Read(b)
		case tlcpRecordAlert:
			if len(payload) >= 2 {
				return 0, fmt.Errorf("tlcp: received alert: level=%d description=%d", payload[0], payload[1])
			}
			return 0, io.EOF
		default:
			// Unexpected post-handshake record type; ignore and continue.
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

// Close sends close_notify and closes the underlying connection.
func (c *tlcpConn) Close() error {
	// Best-effort close_notify alert.
	_ = c.writeRecord(tlcpRecordAlert, []byte{1, 0}) // warning level, close_notify
	return c.conn.Close()
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
		if typ == tlcpRecordAlert && len(body) >= 2 {
			return nil, 0, fmt.Errorf("tlcp: received alert during handshake: level=%d description=%d", body[0], body[1])
		}
		// Decrypt via the input halfConn, passing the REAL record header (its
		// type+version bytes feed the AEAD/CBC additional data).
		fullRecord := append(header, body...)
		c.in.mu.Lock()
		plaintext, _, err := c.in.decrypt(fullRecord)
		c.in.mu.Unlock()
		if err != nil {
			return nil, 0, err
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
	// Record-layer version: use the negotiated version once known, else the
	// initial TLCP version (the ClientHello is sent before version negotiation).
	recordVersion := c.vers
	if !c.haveVers {
		recordVersion = tlcpVersionTLCP
	}
	header[1] = byte(recordVersion >> 8)
	header[2] = byte(recordVersion)

	c.out.mu.Lock()
	record, err := c.out.encrypt(header, payload)
	c.out.mu.Unlock()
	if err != nil {
		return err
	}

	// ChangeCipherSpec flips the output cipher immediately after the CCS record
	// is produced (it is itself sent plaintext, under the OLD/nil cipher). The
	// following record (Finished) is then encrypted with the new keys. This must
	// happen whether or not writes are buffered.
	if typ == tlcpRecordChangeCipherSpec {
		c.out.mu.Lock()
		err = c.out.changeCipherSpec()
		c.out.mu.Unlock()
		if err != nil {
			return err
		}
	}

	if c.buffering {
		c.sendBuf.Write(record)
		return nil
	}
	_, err = c.conn.Write(record)
	return err
}

// writeHandshakeRecord marshals a handshake message, feeds it to the transcript
// hash (if non-nil), and writes it as a handshake record.
func (c *tlcpConn) writeHandshakeRecord(msg tlcpHandshakeMessage, transcript *tlcpFinishedHash) error {
	type marshalable interface {
		marshal() ([]byte, error)
	}
	mm := msg.(marshalable)
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
		c.hand.Write(payload)
	}
	// Peek the length to know how many bytes the full message occupies.
	head := c.hand.Bytes()
	msgLen := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
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
	c.hand.Read(data)
	if transcript != nil {
		transcript.Write(data)
	}
	return data, nil
}

// flushLocked sends all buffered records. Caller does not need the out lock.
func (c *tlcpConn) flushLocked() error {
	if c.sendBuf.Len() == 0 {
		return nil
	}
	_, err := c.conn.Write(c.sendBuf.Bytes())
	c.sendBuf.Reset()
	return err
}

// flush sends all buffered records.
func (c *tlcpConn) flush() error {
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

// tlcpExtractPadding extracts the CBC padding length in constant time. Returns
// (paddingLen, paddingGood) where paddingGood is 1 if valid, 0 otherwise.
func tlcpExtractPadding(plaintext []byte, blockSize int) (paddingLen, paddingGood int) {
	if len(plaintext) == 0 {
		return 0, 0
	}
	last := int(plaintext[len(plaintext)-1])
	// paddingLen candidate = last+1 (TLS padding: each byte equals the count-1).
	toCheck := last + 1
	if toCheck > len(plaintext) || toCheck > 256 {
		return 0, 0
	}
	good := 1
	for i := 0; i < toCheck; i++ {
		if int(plaintext[len(plaintext)-1-i]) != last {
			good = 0
		}
	}
	return toCheck, good
}

// constantTimeEq returns 1 if a and b are equal, 0 otherwise (constant-time).
func constantTimeEq(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

// randReader is the package-level RNG source used by encrypt for CBC IVs. It
// defaults to crypto/rand and can be overridden by tests via the engine config.
var randReader io.Reader = cryptoRandReader{}
