package kmc

import (
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
