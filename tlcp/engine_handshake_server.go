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
	signCertDER  []byte           // signing certificate leaf DER
	encCertDER   []byte           // encryption certificate leaf DER
	chainDER     [][]byte         // optional CA chain DERs (appended after the two leaves)
	signSigner   crypto.Signer    // signing cert private key (for SKE signature)
	encDecrypter crypto.Decrypter // encryption cert private key (for PMS decryption)
}

// tlcpNegotiateServerALPN 服务端 ALPN 裁决（RFC 7301）：在「客户端提议 ∩
// 本地 NextProtos」中按客户端优先序取第一个两侧都支持的协议——对齐
// tls13gm 的 client-preference 选择（RFC 7301 不强制顺序）。
//
// 语义裁决（依据 stdlib crypto/tls negotiateALPN，Go 1.27 核实）：
//   - 任一侧未配置（服务端无 NextProtos 或客户端未提议）：返回空串、
//     不报错——stdlib 对空 serverProtos/clientProtos 返回 ("", nil)。服务端
//     未配置时若采纳客户端首个提议，会把操作者从未配置的协议"协商"成真
//     （客户端可借此让服务端报告任意 ALPN 标签），故不采纳。
//   - 两侧都配置但无交集：返回错误，握手中止。stdlib 发
//     no_application_protocol(120) alert；本引擎 alert 词表只有
//     close_notify/handshake_failure，故统一走 Handshake() 的通用握手失败
//     路径发 handshake_failure(40)，错误文本保留 no_application_protocol
//     字样供定位（改动需先扩引擎 alert 词表，属破坏性协议面变更）。
func tlcpNegotiateServerALPN(clientProtocols, serverProtocols []string) (string, error) {
	if len(clientProtocols) == 0 || len(serverProtocols) == 0 {
		return "", nil
	}
	for _, cp := range clientProtocols {
		for _, sp := range serverProtocols {
			if cp == sp {
				return cp, nil
			}
		}
	}
	return "", errors.New("tlcp: no overlapping ALPN protocol (no_application_protocol)")
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
	// vers/haveVers are read by writeRecord under out.mu (see engine_conn.go);
	// write them under the same lock for race-safety with Close()'s alert path.
	c.out.mu.Lock()
	c.vers = tlcpVersionTLCP
	c.haveVers = true
	c.out.mu.Unlock()
	c.serverName = clientHello.serverName

	// 2. Select a cipher suite from the client's offer and our preference.
	suite := tlcpMutualCipherSuite(config.cipherSuites, clientHello.cipherSuites)
	if suite == nil {
		return errors.New("tlcp: no common cipher suite with client")
	}
	c.cipherSuite = suite.id
	isECDHE := suite.flags&tlcpFlagECDHE != 0

	// 2a. ALPN 裁决（全握手与 resume 共用同一决定点；无 overlap 中止握手）。
	// 选中协议写入 c.clientProtocol（ConnectionState 暴露）并经 ServerHello
	// ALPN 扩展回传；未选中则不回扩展。
	alpnSelected, err := tlcpNegotiateServerALPN(clientHello.alpnProtocols, config.nextProtos)
	if err != nil {
		return err
	}
	c.clientProtocol = alpnSelected

	// 2b. Resume check: if the client offered a sessionId that hits our cache,
	// perform an abbreviated handshake (no Certificate/SKE/SHD), reusing the
	// cached master secret. The server sends Finished first in a resume.
	if sess := c.lookupResumedSession(&clientHello, suite); sess != nil {
		if err := c.serverResumeHandshake(suite, &clientHello, chData, sess, alpnSelected); err != nil {
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
		alpnProtocol:      alpnSelected,
	}

	// 4. Initialize transcript and feed ClientHello + ServerHello.
	transcript := newTLCPFinishedHash()
	transcript.Write(chData)

	c.buffering.Store(true)
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
	var clientEncCert *x509.Certificate
	if wantClientCert {
		ccData, err := c.readHandshake(transcript)
		if err != nil {
			return err
		}
		var cc tlcpCertificateMsg
		if !cc.unmarshal(ccData) {
			return errors.New("tlcp: failed to parse client Certificate")
		}
		// Store for ConnectionState.PeerCertificates + session cache.
		c.peerCertificates = cc.certificates
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
			clientEncCert, err = polluxsmx509.ParseCertificate(cc.certificates[1])
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
		// RequireAnyClientCert / RequireAndVerifyClientCert: a cert MUST be
		// presented regardless of whether clientRoots is configured.
		// NOTE: pollux-go's ClientAuthType iota ordering differs from stdlib
		// crypto/tls — here VerifyClientCertIfGiven (3) > RequireAnyClientCert (2),
		// so a range check (>= RequireAnyClientCert) would wrongly treat the
		// optional "verify if given" mode as mandatory. Match only the two modes
		// that unconditionally require a certificate.
		if (config.clientAuth == RequireAnyClientCert || config.clientAuth == RequireAndVerifyClientCert) && clientSignCert == nil {
			return errors.New("tlcp: client did not provide a certificate")
		}
		// 客户端证书链校验：防 rogue（不受信 CA 签发的）客户端证书。
		// CertificateVerify 只证明私钥持有，不证明 CA 信任链；此处补链校验。
		// config.clientRoots 仅在 ClientAuth >= VerifyClientCertIfGiven 且配置了
		// ClientCACertificates 时非 nil。
		if config.clientRoots != nil {
			// RequireAndVerifyClientCert：客户端必须给证书且通过校验。
			// NOTE: use an explicit == comparison (not >=) so the check does not
			// depend on the iota ordering of ClientAuthType. The iota sequence
			// here differs from crypto/tls (VerifyClientCertIfGiven (3) sorts
			// above RequireAnyClientCert (2)); a range check would silently bind
			// this to that ordering and could accept an unverified client cert if
			// the constants are ever reordered.
			if config.clientAuth == RequireAndVerifyClientCert && clientSignCert == nil {
				return errors.New("tlcp: client did not provide a certificate")
			}
			// VerifyClientCertIfGiven / RequireAndVerifyClientCert：给了就验。
			// 双证时验双链（VerifyDualCertSignatures 含 enc 证书链 + 配对约束），
			// 见 verifyClientCertChain——仅验 sign 链会放行 enc 证书由攻击者
			// CA 签发的客户端（PMS 用 enc 公钥加密，enc 证书不受信即 PMS 泄露面）。
			if clientSignCert != nil {
				if err := verifyClientCertChain(clientSignCert, clientEncCert, config.clientRoots); err != nil {
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
		zeroBytes(masterSecret)
		return err
	}

	// 10. Read client CCS + Finished (verify clientSum), then feed.
	if err := c.readClientCCSAndFinished(transcript, masterSecret); err != nil {
		zeroBytes(masterSecret)
		return err
	}

	// 11. Send server CCS + Finished (serverSum).
	c.buffering.Store(true)
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		zeroBytes(masterSecret)
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.serverSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		zeroBytes(masterSecret)
		return err
	}
	if err := c.flush(); err != nil {
		zeroBytes(masterSecret)
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
//
// mTLS 策略绑定（clientRoots 非 nil 的两种验链模式）：resume 命中的会话必须
// 携带缓存 peerCertificates 且对其重跑链验证（abbreviated handshake 无
// Certificate/CertificateVerify 消息，客户端身份完全由缓存会话承载）。强制
// （RequireAndVerifyClientCert）与可选（VerifyClientCertIfGiven）模式统一覆
// 盖——可选模式全握手语义是「给了就验」，缓存身份存在时同样必须重验，否则
// rogue 缓存条目可借 resume 绕过验链。验证失败（证书过期/被吊销换链/缓存条
// 目被伪造）→ 放弃 resume 返回 nil，走全握手重新认证——不报错中断，与
// stdlib TLS 1.2 的 resume 语义一致。无 mTLS 要求时维持原语义（仅
// version+suite 匹配）。
func (c *tlcpConn) lookupResumedSession(clientHello *tlcpClientHelloMsg, suite *tlcpCipherSuite) *SessionState {
	if c.config == nil || c.config.sessionCache == nil || len(clientHello.sessionID) == 0 {
		return nil
	}
	sess, ok := c.config.sessionCache.Get(serverSessionKey(clientHello.sessionID))
	if !ok || sess == nil {
		return nil
	}
	if !sessionFresh(sess) {
		return nil
	}
	if sess.version != c.vers || sess.cipherSuite != suite.id {
		return nil
	}
	// clientRoots 仅在 ClientAuth >= VerifyClientCertIfGiven 且配置了
	// ClientCACertificates 时非 nil；此处覆盖两种验链模式——强制
	// （RequireAndVerifyClientCert）与可选（VerifyClientCertIfGiven）。显式
	// == 枚举（不用 >=，模式排序语义见全握手路径的 NOTE）。可选模式的语义是
	// 「给了就验」：缓存会话绑定过客户端证书（全握手时给了）就必须重验，
	// 否则 rogue 缓存条目借 resume 绕过验链——与全握手路径的 verifyClientCert
	// Chain 门（clientSignCert != nil 即验）对齐。
	if (c.config.clientAuth == RequireAndVerifyClientCert || c.config.clientAuth == VerifyClientCertIfGiven) && c.config.clientRoots != nil {
		if len(sess.peerCertificates) == 0 {
			// 缓存会话未绑定客户端身份。强制模式：不可 resume（身份 MUST 存在）；
			// 可选模式：全握手时客户端未给证书，缓存与该语义一致，无可验对象，
			// 按原样 resume（不因缺证书否定一个本就不要求证书的会话）。
			if c.config.clientAuth == RequireAndVerifyClientCert {
				return nil
			}
			return sess
		}
		signCert, err := polluxsmx509.ParseCertificate(sess.peerCertificates[0])
		if err != nil {
			return nil
		}
		var encCert *x509.Certificate
		if len(sess.peerCertificates) >= 2 {
			encCert, err = polluxsmx509.ParseCertificate(sess.peerCertificates[1])
			if err != nil {
				return nil
			}
		}
		if verifyClientCertChain(signCert, encCert, c.config.clientRoots) != nil {
			return nil // 链验证失败：放弃 resume，走全握手
		}
	}
	return sess
}

// verifyClientCertChain 校验客户端证书链（服务端 mTLS，全握手与 resume 共用）。
// signCert 必须非 nil；encCert 为 nil（客户端只发单证）时退化为仅验 sign 链，
// 双证时走 VerifyDualCertSignatures——除两条链各自到根的验证外，还强制配对
// 约束（同 CA、同 subject、正确的 sign/enc KeyUsage）。KeyUsages 恒为
// ExtKeyUsageClientAuth：客户端证书应含 ClientAuth EKU（默认 ServerAuth 会
// 误拒）。roots 为服务端配置的客户端 CA 池（config.clientRoots）。
func verifyClientCertChain(signCert, encCert *x509.Certificate, roots *polluxsmx509.CertPool) error {
	opts := polluxsmx509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if encCert != nil {
		return polluxsmx509.VerifyDualCertSignatures(signCert, encCert, opts)
	}
	return polluxsmx509.Verify(signCert, opts)
}

// serverResumeHandshake drives the server-side abbreviated (resume) handshake.
// Resume ordering (opposite of full): send ServerHello (echoed sessionId) →
// establishKeys → send server CCS+Finished → read client CCS+Finished. The
// transcript covers only ClientHello + ServerHello. masterSecret comes from
// the cached session. alpnProtocol is the ALPN selection already negotiated
// for this ClientHello（stdlib TLS 1.2 亦在 resume 的 ServerHello 中回传
// ALPN 选择，客户端信任门同样覆盖 resume 路径）。
func (c *tlcpConn) serverResumeHandshake(suite *tlcpCipherSuite, clientHello *tlcpClientHelloMsg, chData []byte, sess *SessionState, alpnProtocol string) error {
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
		alpnProtocol:      alpnProtocol,
	}

	transcript := newTLCPFinishedHash()
	transcript.Write(chData)

	c.buffering.Store(true)
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
		zeroBytes(masterSecret)
		return err
	}

	// Resume: server sends Finished first, then reads the client's.
	if err := c.writeRecord(tlcpRecordChangeCipherSpec, []byte{1}); err != nil {
		zeroBytes(masterSecret)
		return err
	}
	finished := &tlcpFinishedMsg{verifyData: transcript.serverSum(masterSecret)}
	if err := c.writeHandshakeRecord(finished, transcript); err != nil {
		zeroBytes(masterSecret)
		return err
	}
	if err := c.flush(); err != nil {
		zeroBytes(masterSecret)
		return err
	}

	if err := c.readClientCCSAndFinished(transcript, masterSecret); err != nil {
		zeroBytes(masterSecret)
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
	sess := &SessionState{
		sessionID:        serverHello.sessionID,
		version:          c.vers,
		cipherSuite:      c.cipherSuite,
		masterSecret:     msCopy,
		peerCertificates: peerCertsCopy,
		createdAt:        time.Now(),
	}
	c.config.sessionCache.Put(serverSessionKey(sess.sessionID), sess)
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
		// Do not leak the expected verify_data — it is derived from the
		// master secret and transcript hash; exposing it could enable
		// Finished-message oracle attacks or session compromise.
		return errors.New("tlcp: client's Finished verify_data mismatch")
	}
	transcript.Write(finData)
	return nil
}

// serverHandshake replaces the conn.go stub.
func (c *tlcpConn) serverHandshake() error { return c.serverHandshakeReal() }
