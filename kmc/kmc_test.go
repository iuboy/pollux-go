package kmc

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	gmsmSmx509 "github.com/emmansun/gmsm/smx509"
	"github.com/iuboy/pollux-go/smx509"
)

func TestLocalKMC_GenerateEncryptionKeyPair(t *testing.T) {
	k := NewLocalKMC()
	kp, err := k.GenerateEncryptionKeyPair(context.Background(), pkix.Name{CommonName: "gm-encryption"})
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyPair: %v", err)
	}

	// PKCS#8 DER must parse back to a usable SM2 private key.
	priv, err := smx509.ParsePKCS8PrivateKey(kp.PrivateKeyPKCS8)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	sm2Priv, ok := priv.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("parsed key type = %T, want *sm2.PrivateKey", priv)
	}
	if sm2Priv.Curve != sm2.P256() {
		t.Fatal("parsed private key is not on the SM2 curve")
	}

	// CSR must parse and its SM2 signature must verify. Signature verification
	// runs against the gmsm backend: pollux's ParseCertificateRequest returns
	// the stdlib x509.CertificateRequest type, whose CheckSignature cannot
	// handle the SM2-with-SM3 signature OID.
	block, _ := pem.Decode([]byte(kp.EncryptionCSRPEM))
	if block == nil {
		t.Fatal("EncryptionCSRPEM is not valid PEM")
	}
	smCSR, err := gmsmSmx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("gmsm ParseCertificateRequest: %v", err)
	}
	if err := smCSR.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}
	// The template deliberately leaves SignatureAlgorithm at the zero value
	// for SM2 (stdlib has no SM2WithSM3 constant); gmsm's signer must default
	// SM2 keys to SM2WithSM3. Lock that in so a gmsm upgrade that breaks the
	// defaulting fails here instead of producing SHA256-mismatched CSRs.
	if smCSR.SignatureAlgorithm != gmsmSmx509.SM2WithSM3 {
		t.Fatalf("CSR signature algorithm = %v, want SM2WithSM3", smCSR.SignatureAlgorithm)
	}
	// Default keyUsage extension request: digitalSignature | keyEncipherment,
	// critical. BIT STRING bits 0 and 2 set, trailing zeros trimmed per DER:
	// 03 02 05 A0.
	wantKU := []byte{0x03, 0x02, 0x05, 0xA0}
	var foundKU bool
	for _, ext := range smCSR.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 15}) {
			foundKU = true
			if !ext.Critical {
				t.Error("keyUsage extension is not critical")
			}
			if !bytes.Equal(ext.Value, wantKU) {
				t.Errorf("keyUsage value = % X, want % X (digitalSignature|keyEncipherment)", ext.Value, wantKU)
			}
		}
	}
	if !foundKU {
		t.Error("CSR carries no keyUsage (2.5.29.15) extension request")
	}
	if smCSR.Subject.CommonName != "gm-encryption" {
		t.Fatalf("CSR CN = %q, want gm-encryption (subject parameterization)", smCSR.Subject.CommonName)
	}
}

func TestLocalKMC_SubjectParameterized(t *testing.T) {
	k := NewLocalKMC()
	want := "custom-enc-cn"
	kp, err := k.GenerateEncryptionKeyPair(context.Background(), pkix.Name{CommonName: want})
	if err != nil {
		t.Fatalf("GenerateEncryptionKeyPair: %v", err)
	}
	block, _ := pem.Decode([]byte(kp.EncryptionCSRPEM))
	if block == nil {
		t.Fatal("invalid PEM")
	}
	csr, err := smx509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != want {
		t.Fatalf("CSR CN = %q, want %q", csr.Subject.CommonName, want)
	}
}

func TestLocalKMC_KeysIndependent(t *testing.T) {
	k := NewLocalKMC()
	ctx := context.Background()
	kp1, err1 := k.GenerateEncryptionKeyPair(ctx, pkix.Name{CommonName: "a"})
	kp2, err2 := k.GenerateEncryptionKeyPair(ctx, pkix.Name{CommonName: "a"})
	if err1 != nil || err2 != nil {
		t.Fatalf("generate errors: %v / %v", err1, err2)
	}
	if string(kp1.PrivateKeyPKCS8) == string(kp2.PrivateKeyPKCS8) {
		t.Fatal("two generations produced identical private keys")
	}
}
