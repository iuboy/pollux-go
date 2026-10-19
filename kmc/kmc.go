// See doc.go for the package documentation (godoc convention).
package kmc

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
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

// oidExtensionKeyUsage is the RFC 5280 keyUsage extension OID (2.5.29.15).
var oidExtensionKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// keyUsagePositions maps each x509.KeyUsage bit to its RFC 5280 keyUsage
// extension bit position (digitalSignature=0 … decipherOnly=8).
var keyUsagePositions = []struct {
	usage x509.KeyUsage
	pos   int
}{
	{x509.KeyUsageDigitalSignature, 0},
	{x509.KeyUsageContentCommitment, 1},
	{x509.KeyUsageKeyEncipherment, 2},
	{x509.KeyUsageDataEncipherment, 3},
	{x509.KeyUsageKeyAgreement, 4},
	{x509.KeyUsageCertSign, 5},
	{x509.KeyUsageCRLSign, 6},
	{x509.KeyUsageEncipherOnly, 7},
	{x509.KeyUsageDecipherOnly, 8},
}

// keyUsageExtension encodes ku as a critical keyUsage (2.5.29.15) extension.
//
// It rides in CertificateRequest.ExtraExtensions because neither crypto/x509
// nor the gmsm/smx509 fork exposes a KeyUsage template field on
// CertificateRequest (that field exists only on certificate templates). Both
// CreateCertificateRequest backends copy ExtraExtensions verbatim into the
// CSR's extensionRequest attribute. The BIT STRING is DER-canonical: trailing
// zero bits trimmed, mirroring how Go's own certificate builder encodes
// keyUsage.
func keyUsageExtension(ku x509.KeyUsage) (pkix.Extension, error) {
	var bits asn1.BitString
	for _, u := range keyUsagePositions {
		if ku&u.usage != 0 {
			bits.BitLength = u.pos + 1
		}
	}
	if bits.BitLength == 0 {
		return pkix.Extension{}, errors.New("kmc: empty KeyUsage")
	}
	bits.Bytes = make([]byte, (bits.BitLength+7)/8)
	for _, u := range keyUsagePositions {
		if ku&u.usage != 0 {
			bits.Bytes[u.pos/8] |= 0x80 >> uint(u.pos%8)
		}
	}
	der, err := asn1.Marshal(bits)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("kmc: marshal keyUsage extension: %w", err)
	}
	return pkix.Extension{Id: oidExtensionKeyUsage, Critical: true, Value: der}, nil
}

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
	//
	// Key usage: digitalSignature (self-signature / proof of possession) |
	// keyEncipherment (the TLCP key-transport role of an encryption cert) is
	// requested as the default extension. Extended key usage is deliberately
	// NOT requested — usage policy is the issuing CA's call.
	//
	// Signature algorithm: SignatureAlgorithmForPrivateKey returns
	// UnknownSignatureAlgorithm (the zero value) for SM2 keys because stdlib
	// x509 has no SM2WithSM3 constant; gmsm's CreateCertificateRequest then
	// defaults SM2 keys to SM2WithSM3, so the CSR is signed SM2-with-SM3
	// (locked by TestLocalKMC_GenerateEncryptionKeyPair).
	keyUsageExt, err := keyUsageExtension(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
	if err != nil {
		return fail(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: smx509.SignatureAlgorithmForPrivateKey(priv),
		ExtraExtensions:    []pkix.Extension{keyUsageExt},
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
