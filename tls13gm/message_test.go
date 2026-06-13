package tls13gm

import (
	"bytes"
	"testing"
)

func TestExtensionVectorRoundTrip(t *testing.T) {
	exts := []Extension{
		{Type: ExtensionTypeSupportedVersions, Data: []byte{0x02, 0x03, 0x03}},
		{Type: ExtensionTypeKeyShare, Data: bytes.Repeat([]byte{0x11}, 69)},
	}
	enc, err := marshalExtensions(exts)
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := parseExtensions(enc)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(enc) {
		t.Errorf("consumed %d, want %d", n, len(enc))
	}
	if len(got) != len(exts) {
		t.Fatalf("got %d extensions, want %d", len(got), len(exts))
	}
	for i := range exts {
		if got[i].Type != exts[i].Type || !bytes.Equal(got[i].Data, exts[i].Data) {
			t.Errorf("extension %d mismatch", i)
		}
	}
}

// supportedVersionsClient builds the ClientHello supported_versions data:
// a 1-byte-prefixed list of versions.
func supportedVersionsClient() []byte { return []byte{0x02, 0x03, 0x03} }

// keyShareEntry builds a key_share entry vector (ClientHello form): a
// 2-byte-prefixed list of (group | len | key).
func keyShareEntry(group uint16, key []byte) []byte {
	v := make([]byte, 2+4+len(key))
	total := 4 + len(key)
	v[0] = byte(total >> 8)
	v[1] = byte(total)
	v[2] = byte(group >> 8)
	v[3] = byte(group)
	v[4] = byte(len(key) >> 8)
	v[5] = byte(len(key))
	copy(v[6:], key)
	return v
}

func TestClientHello_RoundTrip(t *testing.T) {
	sid := []byte{0xA0, 0xB1, 0xC2, 0xD3}
	key := bytes.Repeat([]byte{0x42}, CurveSM2KeySize) // 65 bytes
	orig := &ClientHelloMsg{
		LegacyVersion:   uint16(VersionTLS13),
		Random:          [32]byte{0x01, 0x02, 0x03},
		LegacySessionID: sid,
		CipherSuites:    []uint16{TLS_SM4_GCM_SM3},
		Extensions: []Extension{
			{Type: ExtensionTypeSupportedVersions, Data: supportedVersionsClient()},
			{Type: ExtensionTypeSignatureAlgorithms, Data: []byte{0x00, 0x02, byte(SM2SigSM3 >> 8), byte(SM2SigSM3 & 0xff)}},
			{Type: ExtensionTypeSupportedGroups, Data: []byte{0x00, 0x02, byte(CurveSM2 >> 8), byte(CurveSM2 & 0xff)}},
			{Type: ExtensionTypeKeyShare, Data: keyShareEntry(CurveSM2, key)},
		},
	}

	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if full[0] != HandshakeTypeClientHello {
		t.Errorf("header type %d, want %d", full[0], HandshakeTypeClientHello)
	}

	msgType, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if msgType != HandshakeTypeClientHello {
		t.Fatalf("type %d", msgType)
	}

	var got ClientHelloMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LegacyVersion != orig.LegacyVersion {
		t.Errorf("version %x", got.LegacyVersion)
	}
	if !bytes.Equal(got.Random[:], orig.Random[:]) {
		t.Error("random mismatch")
	}
	if !bytes.Equal(got.LegacySessionID, orig.LegacySessionID) {
		t.Error("session id mismatch")
	}
	if len(got.CipherSuites) != 1 || got.CipherSuites[0] != TLS_SM4_GCM_SM3 {
		t.Errorf("cipher suites %v", got.CipherSuites)
	}
	if len(got.Extensions) != len(orig.Extensions) {
		t.Fatalf("extensions %d", len(got.Extensions))
	}
	ks := findExtension(got.Extensions, ExtensionTypeKeyShare)
	if ks == nil || !bytes.Contains(ks, key) {
		t.Error("key_share not recovered")
	}
}

func TestServerHello_RoundTrip(t *testing.T) {
	sid := []byte{0x11, 0x22}
	key := bytes.Repeat([]byte{0x55}, CurveSM2KeySize)
	orig := &ServerHelloMsg{
		LegacyVersion:   uint16(VersionTLS13),
		Random:          [32]byte{0xDE, 0xAD},
		LegacySessionID: sid,
		CipherSuite:     TLS_SM4_GCM_SM3,
		Extensions: []Extension{
			{Type: ExtensionTypeSupportedVersions, Data: []byte{0x03, 0x03}},
			{Type: ExtensionTypeKeyShare, Data: keyShareEntry(CurveSM2, key)},
		},
	}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	var got ServerHelloMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.CipherSuite != TLS_SM4_GCM_SM3 {
		t.Errorf("cipher %x", got.CipherSuite)
	}
	if !bytes.Equal(got.LegacySessionID, sid) {
		t.Error("session id mismatch")
	}
	ks := findExtension(got.Extensions, ExtensionTypeKeyShare)
	if ks == nil || !bytes.Contains(ks, key) {
		t.Error("key_share not recovered")
	}
}

func TestEncryptedExtensions_RoundTrip(t *testing.T) {
	for _, exts := range [][]Extension{
		nil, // empty (common minimal case)
		{{Type: ExtensionTypeALPN, Data: []byte{0x00, 0x03, 0x02, 'h', '2'}}},
	} {
		orig := &EncryptedExtensionsMsg{Extensions: exts}
		full, err := MarshalHandshakeMessage(orig)
		if err != nil {
			t.Fatal(err)
		}
		_, body, _, err := ReadHandshakeMessage(full)
		if err != nil {
			t.Fatal(err)
		}
		var got EncryptedExtensionsMsg
		if err := got.unmarshalBody(body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Extensions) != len(exts) {
			t.Errorf("extensions %d, want %d", len(got.Extensions), len(exts))
		}
	}
}

func TestFinished_RoundTrip(t *testing.T) {
	verify := bytes.Repeat([]byte{0x7A}, 32) // HMAC-SM3 output size
	orig := &FinishedMsg{VerifyData: verify}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	var got FinishedMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.VerifyData, verify) {
		t.Error("verify_data mismatch")
	}
}

func TestClientHello_RejectsTrailing(t *testing.T) {
	orig := &ClientHelloMsg{
		LegacyVersion: uint16(VersionTLS13),
		CipherSuites:  []uint16{TLS_SM4_GCM_SM3},
	}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	// Append a stray byte: unmarshalling must fail rather than silently accept.
	body = append(body, 0xFF)
	var got ClientHelloMsg
	if err := got.unmarshalBody(body); err == nil {
		t.Error("expected error for trailing bytes")
	}
}
