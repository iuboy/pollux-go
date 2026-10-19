package crl_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/iuboy/pollux-go/crl"
)

// TestParseCRLRecords_ReasonRoundTrip 锁定撤销原因经 ReasonCode 字段的
// 序列化/解析往返：Go 1.26 起 CRL entry 的 reasonCode 只认 ReasonCode
// 字段，手工扩展进 Extensions 会被序列化静默忽略。
func TestParseCRLRecords_ReasonRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := new(big.Int).SetString("12345678901234567890", 10)
	entry := x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: time.Now().UTC(),
		ReasonCode:     4, // superseded
	}
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{entry},
		Number:                    big.NewInt(2),
		ThisUpdate:                time.Now().UTC(),
		NextUpdate:                time.Now().Add(24 * time.Hour).UTC(),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})

	records, err := crl.ParseCRLRecords(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].Serial != "12345678901234567890" {
		t.Errorf("serial = %s", records[0].Serial)
	}
	if records[0].ReasonCode != 4 || records[0].Reason != "superseded" {
		t.Errorf("reason = %d(%s), want 4(superseded)", records[0].ReasonCode, records[0].Reason)
	}
	if records[0].RevokedAt.IsZero() {
		t.Error("revoked_at is zero")
	}
}

func TestParseCRLRecords_InvalidPEM(t *testing.T) {
	if _, err := crl.ParseCRLRecords([]byte("not a pem")); err == nil {
		t.Error("expected error for invalid PEM")
	}
	if _, err := crl.ParseCRLRecords([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("expected error for wrong PEM block type")
	}
}
