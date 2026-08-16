// See doc.go for the package documentation (godoc convention).
package kmc

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm2"

	"github.com/iuboy/pollux-go/internal/memsecure"
	"github.com/iuboy/pollux-go/smx509"
)

// Manager is the minimal KMC interface. It deliberately contains a single
// method: in the dual-certificate enrollment flow the KMC's job is to
// generate the encryption key pair and produce a CSR the CA can sign.
type Manager interface {
	// GenerateEncryptionKeyPair generates an SM2 encryption key pair.
	// subject becomes the CSR subject of the encryption certificate
	// (callers pick their naming convention, e.g. CN=gm-encryption); the
	// library imposes no default.
	GenerateEncryptionKeyPair(ctx context.Context, subject pkix.Name) (*EncryptionKeyPair, error)
}

// EncryptionKeyPair is the output of a KMC key generation.
//
// Key-material responsibility: PrivateKeyPKCS8 is plaintext key material.
// The caller owns it after return — zero it with memsecure.ZeroBytes once
// the enrollment protocol has wrapped it, and never log the struct
// (fmt %v/%#v would print the raw key).
type EncryptionKeyPair struct {
	// PrivateKeyPKCS8 is the encryption private key, PKCS#8 DER (wrapped by
	// the enrollment protocol before being returned to the client).
	PrivateKeyPKCS8 []byte
	// EncryptionCSRPEM is the encryption-certificate CSR (self-signed with
	// the encryption private key) that the CA signs to issue the encryption
	// certificate.
	EncryptionCSRPEM string
}

// LocalKMC is a local SM2-keygen placeholder implementation of Manager for
// development and testing. Production deployments replace it with an
// implementation backed by a real KMC device (SDF, GM/T 0018).
type LocalKMC struct{}

// NewLocalKMC creates a LocalKMC.
func NewLocalKMC() *LocalKMC { return &LocalKMC{} }

// Compile-time contract: LocalKMC implements Manager.
var _ Manager = (*LocalKMC)(nil)

// GenerateEncryptionKeyPair generates a local SM2 key pair and self-signs
// the encryption CSR with it. ctx is currently unused (no device I/O) but
// part of the Manager contract for real KMC implementations.
func (k *LocalKMC) GenerateEncryptionKeyPair(_ context.Context, subject pkix.Name) (*EncryptionKeyPair, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kmc: generate SM2 key pair: %w", err)
	}
	// Key-material hygiene: zero the scalar and any intermediate DER on every
	// failure path (the returned PrivateKeyPKCS8 copy is the caller's
	// responsibility — see EncryptionKeyPair docs), matching the memsecure
	// convention used across this module.
	var privDER []byte
	fail := func(err error) (*EncryptionKeyPair, error) {
		if priv.D != nil {
			priv.D.SetInt64(0)
		}
		memsecure.ZeroBytes(privDER)
		return nil, err
	}

	// PKCS#8 DER via gmsm pkcs8, which understands the SM2 private key type.
	privDER, err = pkcs8.MarshalPrivateKey(priv, nil, nil)
	if err != nil {
		return fail(fmt.Errorf("kmc: marshal private key: %w", err))
	}

	// Encryption CSR: signed with the freshly generated key so the CA can
	// issue the encryption certificate from it.
	csrTemplate := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: smx509.SignatureAlgorithmForPrivateKey(priv),
	}
	csrDER, err := smx509.CreateCertificateRequest(csrTemplate, priv)
	if err != nil {
		return fail(fmt.Errorf("kmc: build encryption CSR: %w", err))
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	return &EncryptionKeyPair{
		PrivateKeyPKCS8:  privDER,
		EncryptionCSRPEM: csrPEM,
	}, nil
}
