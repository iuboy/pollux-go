package tlcp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// roundTripMsg marshals m, unmarshals into a fresh zero value via the provided
// closure, and reports whether the fields match the original. The comparison
// closure returns true if equal.
type tlcpMsgRoundTrip[T any] struct {
	name      string
	marshal   func(m *T) ([]byte, error)
	unmarshal func(out *T, data []byte) bool
}

// --- ClientHello ---

func TestTLCPMsg_ClientHello_RoundTrip(t *testing.T) {
	orig := &tlcpClientHelloMsg{
		version:                      tlcpVersionTLCP,
		random:                       bytes.Repeat([]byte{0x11}, 32),
		sessionID:                    []byte{0x01, 0x02, 0x03},
		cipherSuites:                 []uint16{SuiteECC_SM2_SM4_GCM_SM3, SuiteECC_SM2_SM4_CBC_SM3},
		compressionMethods:           []uint8{0}, // null compression only
		serverName:                   "example.com",
		supportedCurves:              []tlcpCurveID{tlcpCurveSM2},
		supportedSignatureAlgorithms: []tlcpSignatureScheme{tlcpSigSM2WithSM3},
		alpnProtocols:                []string{"h2", "http/1.1"},
		ocspStapling:                 true,
	}
	data, err := orig.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got tlcpClientHelloMsg
	if !got.unmarshal(data) {
		t.Fatalf("unmarshal failed on:\n%s", hex.Dump(data))
	}
	// Verify the first byte is the ClientHello type.
	if data[0] != tlcpTypeClientHello {
		t.Errorf("message type byte = %d, want %d", data[0], tlcpTypeClientHello)
	}
	if got.version != orig.version || !bytes.Equal(got.random, orig.random) {
		t.Error("version/random mismatch")
	}
	if !bytes.Equal(got.sessionID, orig.sessionID) {
		t.Error("sessionID mismatch")
	}
	if len(got.cipherSuites) != 2 || got.cipherSuites[0] != SuiteECC_SM2_SM4_GCM_SM3 {
		t.Errorf("cipherSuites mismatch: %v", got.cipherSuites)
	}
	if len(got.compressionMethods) != 1 || got.compressionMethods[0] != 0 {
		t.Error("compressionMethods mismatch")
	}
	if got.serverName != orig.serverName {
		t.Errorf("serverName = %q, want %q", got.serverName, orig.serverName)
	}
	if len(got.supportedCurves) != 1 || got.supportedCurves[0] != tlcpCurveSM2 {
		t.Error("supportedCurves mismatch")
	}
	if len(got.supportedSignatureAlgorithms) != 1 || got.supportedSignatureAlgorithms[0] != tlcpSigSM2WithSM3 {
		t.Error("supportedSignatureAlgorithms mismatch")
	}
	if len(got.alpnProtocols) != 2 || got.alpnProtocols[0] != "h2" {
		t.Errorf("alpnProtocols mismatch: %v", got.alpnProtocols)
	}
	if !got.ocspStapling {
		t.Error("ocspStapling not preserved")
	}
	// marshal of the unmarshaled msg must be byte-identical (idempotency).
	reData, err := got.marshal()
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(data, reData) {
		t.Errorf("re-marshal not byte-identical:\n orig %x\n re   %x", data, reData)
	}
}

func TestTLCPMsg_ClientHello_RejectsShort(t *testing.T) {
	var m tlcpClientHelloMsg
	if m.unmarshal([]byte{tlcpTypeClientHello, 0, 0, 1, 0}) {
		t.Error("unmarshal should reject truncated ClientHello")
	}
}

func TestTLCPMsg_ClientHello_RejectsBadType(t *testing.T) {
	orig := &tlcpClientHelloMsg{version: tlcpVersionTLCP, random: bytes.Repeat([]byte{0x11}, 32), cipherSuites: []uint16{SuiteECC_SM2_SM4_GCM_SM3}, compressionMethods: []uint8{0}}
	data, _ := orig.marshal()
	data[0] = tlcpTypeServerHello // wrong type
	var m tlcpClientHelloMsg
	if m.unmarshal(data) {
		t.Error("unmarshal should reject wrong message type")
	}
}

// --- ServerHello ---

func TestTLCPMsg_ServerHello_RoundTrip(t *testing.T) {
	orig := &tlcpServerHelloMsg{
		version:           tlcpVersionTLCP,
		random:            bytes.Repeat([]byte{0x22}, 32),
		sessionID:         []byte{0xAA, 0xBB},
		cipherSuite:       SuiteECC_SM2_SM4_GCM_SM3,
		compressionMethod: 0,
		alpnProtocol:      "h2",
		serverNameAck:     true,
	}
	data, err := orig.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got tlcpServerHelloMsg
	if !got.unmarshal(data) {
		t.Fatalf("unmarshal failed")
	}
	if got.version != orig.version || !bytes.Equal(got.random, orig.random) {
		t.Error("version/random mismatch")
	}
	if got.cipherSuite != orig.cipherSuite {
		t.Error("cipherSuite mismatch")
	}
	if got.alpnProtocol != "h2" {
		t.Errorf("alpnProtocol = %q", got.alpnProtocol)
	}
	if !got.serverNameAck {
		t.Error("serverNameAck not preserved")
	}
	reData, _ := got.marshal()
	if !bytes.Equal(data, reData) {
		t.Errorf("re-marshal not byte-identical")
	}
}

// --- Certificate ---

func TestTLCPMsg_Certificate_RoundTrip(t *testing.T) {
	orig := &tlcpCertificateMsg{
		certificates: [][]byte{
			bytes.Repeat([]byte{0xC1}, 100), // signing cert
			bytes.Repeat([]byte{0xC2}, 120), // encryption cert
		},
	}
	data, err := orig.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got tlcpCertificateMsg
	if !got.unmarshal(data) {
		t.Fatalf("unmarshal failed")
	}
	if len(got.certificates) != 2 {
		t.Fatalf("cert count = %d, want 2", len(got.certificates))
	}
	if !bytes.Equal(got.certificates[0], orig.certificates[0]) || !bytes.Equal(got.certificates[1], orig.certificates[1]) {
		t.Error("certificate bytes mismatch")
	}
	reData, _ := got.marshal()
	if !bytes.Equal(data, reData) {
		t.Errorf("re-marshal not byte-identical")
	}
}

// --- ServerKeyExchange / ClientKeyExchange (opaque payloads) ---

func TestTLCPMsg_KeyExchange_RoundTrip(t *testing.T) {
	// ServerKeyExchange
	ske := &tlcpServerKeyExchangeMsg{key: []byte("opaque-key-exchange-params")}
	d, err := ske.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var ske2 tlcpServerKeyExchangeMsg
	if !ske2.unmarshal(d) || !bytes.Equal(ske2.key, ske.key) {
		t.Error("ServerKeyExchange round-trip failed")
	}
	// ClientKeyExchange
	cke := &tlcpClientKeyExchangeMsg{ciphertext: []byte("sm2-encrypted-pms")}
	d2, err := cke.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var cke2 tlcpClientKeyExchangeMsg
	if !cke2.unmarshal(d2) || !bytes.Equal(cke2.ciphertext, cke.ciphertext) {
		t.Error("ClientKeyExchange round-trip failed")
	}
}

// --- CertificateRequest ---

func TestTLCPMsg_CertificateRequest_RoundTrip(t *testing.T) {
	orig := &tlcpCertificateRequestMsg{
		certificateTypes:       []byte{tlcpCertTypeECDSA, tlcpCertTypeIBC},
		certificateAuthorities: [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}},
	}
	data, err := orig.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got tlcpCertificateRequestMsg
	if !got.unmarshal(data) {
		t.Fatalf("unmarshal failed")
	}
	if !bytes.Equal(got.certificateTypes, orig.certificateTypes) {
		t.Error("certificateTypes mismatch")
	}
	if len(got.certificateAuthorities) != 2 {
		t.Fatalf("CA count = %d, want 2", len(got.certificateAuthorities))
	}
	for i, ca := range orig.certificateAuthorities {
		if !bytes.Equal(got.certificateAuthorities[i], ca) {
			t.Errorf("CA[%d] mismatch", i)
		}
	}
	reData, _ := got.marshal()
	if !bytes.Equal(data, reData) {
		t.Errorf("re-marshal not byte-identical")
	}
}

// --- ServerHelloDone (empty body) ---

func TestTLCPMsg_ServerHelloDone_RoundTrip(t *testing.T) {
	orig := &tlcpServerHelloDoneMsg{}
	data, err := orig.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 4 { // type + uint24 length(0)
		t.Errorf("ServerHelloDone length = %d, want 4", len(data))
	}
	var got tlcpServerHelloDoneMsg
	if !got.unmarshal(data) {
		t.Error("unmarshal failed")
	}
	// Extra trailing byte must be rejected.
	if got.unmarshal(append(data, 0xFF)) {
		t.Error("unmarshal should reject trailing bytes")
	}
}

// --- CertificateVerify ---

func TestTLCPMsg_CertificateVerify_RoundTrip(t *testing.T) {
	orig := &tlcpCertificateVerifyMsg{signature: bytes.Repeat([]byte{0x5A}, 64)}
	data, err := orig.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got tlcpCertificateVerifyMsg
	if !got.unmarshal(data) || !bytes.Equal(got.signature, orig.signature) {
		t.Error("CertificateVerify round-trip failed")
	}
}

// --- Finished ---

func TestTLCPMsg_Finished_RoundTrip(t *testing.T) {
	orig := &tlcpFinishedMsg{verifyData: bytes.Repeat([]byte{0x77}, tlcpFinishedVerifyLength)}
	data, err := orig.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got tlcpFinishedMsg
	if !got.unmarshal(data) || !bytes.Equal(got.verifyData, orig.verifyData) {
		t.Error("Finished round-trip failed")
	}
}

// --- TrustedAuthorities extension round-trip (all identifier types) ---

func TestTLCPMsg_ClientHello_TrustedAuthorities(t *testing.T) {
	orig := &tlcpClientHelloMsg{
		version:            tlcpVersionTLCP,
		random:             bytes.Repeat([]byte{0x11}, 32),
		cipherSuites:       []uint16{SuiteECC_SM2_SM4_GCM_SM3},
		compressionMethods: []uint8{0},
		trustedAuthorities: []tlcpTrustedAuthority{
			{IdentifierType: tlcpIDTypePreAgreed},
			{IdentifierType: tlcpIDTypeKeySM3Hash, Identifier: bytes.Repeat([]byte{0x33}, 32)},
			{IdentifierType: tlcpIDTypeCertSM3Hash, Identifier: bytes.Repeat([]byte{0x44}, 32)},
			{IdentifierType: tlcpIDTypeX509Name, Identifier: []byte("CN=Test CA")},
		},
	}
	data, err := orig.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got tlcpClientHelloMsg
	if !got.unmarshal(data) {
		t.Fatalf("unmarshal failed")
	}
	if len(got.trustedAuthorities) != 4 {
		t.Fatalf("trustedAuthorities count = %d, want 4", len(got.trustedAuthorities))
	}
	for i, ta := range orig.trustedAuthorities {
		g := got.trustedAuthorities[i]
		if g.IdentifierType != ta.IdentifierType || !bytes.Equal(g.Identifier, ta.Identifier) {
			t.Errorf("trustedAuthority[%d] mismatch: got %+v want %+v", i, g, ta)
		}
	}
}
