package tls13gm

import (
	"bytes"
	"testing"
)

func TestCertificate_RoundTrip(t *testing.T) {
	certDER := bytes.Repeat([]byte{0xCA}, 100) // arbitrary DER; message layer does not parse it
	orig := &CertificateMsg{
		CertificateRequestContext: nil,
		CertificateList: []CertificateEntry{
			{
				Certificate: certDER,
				Extensions:  []Extension{{Type: ExtensionTypeSignatureAlgorithms, Data: []byte{0x00, 0x02, 0x07, 0x08}}},
			},
		},
	}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	msgType, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != HandshakeTypeCertificate {
		t.Fatalf("type %d", msgType)
	}
	var got CertificateMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.CertificateList) != 1 {
		t.Fatalf("entries %d", len(got.CertificateList))
	}
	if !bytes.Equal(got.CertificateList[0].Certificate, certDER) {
		t.Error("certificate DER mismatch")
	}
	if len(got.CertificateList[0].Extensions) != 1 {
		t.Errorf("entry extensions %d", len(got.CertificateList[0].Extensions))
	}
}

func TestCertificate_ChainRoundTrip(t *testing.T) {
	orig := &CertificateMsg{
		CertificateRequestContext: []byte{0x01},
		CertificateList: []CertificateEntry{
			{Certificate: bytes.Repeat([]byte{0xAA}, 50)},
			{Certificate: bytes.Repeat([]byte{0xBB}, 30)},
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
	var got CertificateMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.CertificateList) != 2 {
		t.Fatalf("entries %d", len(got.CertificateList))
	}
	if !bytes.Equal(got.CertificateList[1].Certificate, orig.CertificateList[1].Certificate) {
		t.Error("second cert mismatch")
	}
}

func TestCertificateVerify_RoundTrip(t *testing.T) {
	sig := bytes.Repeat([]byte{0x5E}, 71) // DER-encoded SM2 signature, arbitrary here
	orig := &CertificateVerifyMsg{
		SignatureScheme: SM2SigSM3,
		Signature:       sig,
	}
	full, err := MarshalHandshakeMessage(orig)
	if err != nil {
		t.Fatal(err)
	}
	msgType, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != HandshakeTypeCertificateVerify {
		t.Fatalf("type %d", msgType)
	}
	var got CertificateVerifyMsg
	if err := got.unmarshalBody(body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SignatureScheme != SM2SigSM3 {
		t.Errorf("scheme %x", got.SignatureScheme)
	}
	if !bytes.Equal(got.Signature, sig) {
		t.Error("signature mismatch")
	}
}

func TestCertificateVerify_RejectsTrailing(t *testing.T) {
	full, err := MarshalHandshakeMessage(&CertificateVerifyMsg{SignatureScheme: SM2SigSM3, Signature: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := ReadHandshakeMessage(full)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, 0xFF) // trailing byte
	var got CertificateVerifyMsg
	if err := got.unmarshalBody(body); err == nil {
		t.Error("expected error for trailing bytes")
	}
}
