package smx509

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// SM2 signing algorithm OIDs (GM/T 0009-2012 / GB/T 33560).
var oidSignatureSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

// idPKIXOCSPBasic is the basic OCSP response type OID (RFC 6960 §4.2.1),
// identical to the one in golang.org/x/crypto/ocsp.
var idPKIXOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// The ASN.1 structures below mirror the unexported declarations in
// golang.org/x/crypto/ocsp. Field layout must match exactly — any drift
// surfaces as a parse failure when the response is consumed by ocsp.ParseResponse.

type sm2CertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type sm2ResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type sm2ResponseASN1 struct {
	Status   asn1.Enumerated
	Response sm2ResponseBytes `asn1:"explicit,tag:0,optional"`
}

type sm2BasicResponse struct {
	TBSResponseData    sm2ResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type sm2ResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []sm2SingleResponse
}

type sm2SingleResponse struct {
	CertID           sm2CertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          sm2RevokedInfo   `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type sm2RevokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// createSM2OCSPResponse assembles and SM2+SM3-signs an OCSP response.
// The DER assembly mirrors ocsp.CreateResponse; only the signature step is
// replaced with SM2. issuer is the CA used to compute the CertID hashes;
// responderCert is the responder (signer) certificate.
func createSM2OCSPResponse(issuer, responderCert *x509.Certificate, template ocsp.Response, priv *sm2.PrivateKey) ([]byte, error) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}

	if template.IssuerHash == 0 {
		template.IssuerHash = crypto.SHA1
	}
	if !template.IssuerHash.Available() {
		return nil, errors.New("smx509: issuer hash algorithm not linked into binary")
	}
	hashOID := oidFromHashAlgorithm(template.IssuerHash)
	if hashOID == nil {
		return nil, errors.New("smx509: unsupported issuer hash algorithm")
	}

	h := template.IssuerHash.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	innerResponse := sm2SingleResponse{
		CertID: sm2CertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.RawValue{Tag: 5}, // ASN.1 NULL
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  template.SerialNumber,
		},
		ThisUpdate:       template.ThisUpdate.UTC(),
		NextUpdate:       template.NextUpdate.UTC(),
		SingleExtensions: template.ExtraExtensions,
	}

	switch template.Status {
	case ocsp.Good:
		innerResponse.Good = true
	case ocsp.Unknown:
		innerResponse.Unknown = true
	case ocsp.Revoked:
		innerResponse.Revoked = sm2RevokedInfo{
			RevocationTime: template.RevokedAt.UTC(),
			Reason:         asn1.Enumerated(template.RevocationReason),
		}
	}

	rawResponderID := asn1.RawValue{
		Class:      2, // context-specific
		Tag:        1, // Name (explicit tag)
		IsCompound: true,
		Bytes:      responderCert.RawSubject,
	}
	tbsResponseData := sm2ResponseData{
		Version:        0,
		RawResponderID: rawResponderID,
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses:      []sm2SingleResponse{innerResponse},
	}

	tbsResponseDataDER, err := asn1.Marshal(tbsResponseData)
	if err != nil {
		return nil, err
	}

	// SM2 signing: pass the raw TBS ResponseData DER (no pre-hash) to
	// sm2.PrivateKey.Sign with NewSM2SignerOption(true, nil). gmsm performs
	// ZA+SM3 internally (CalculateSM2Hash, forceGMSign=true, default UID),
	// matching the SM2 injection in gmsm smx509.signTBS.
	signature, err := priv.Sign(rand.Reader, tbsResponseDataDER, sm2.NewSM2SignerOption(true, nil))
	if err != nil {
		return nil, err
	}

	response := sm2BasicResponse{
		TBSResponseData: tbsResponseData,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureSM2WithSM3,
			// SM2 algorithm identifier carries no parameters (empty SEQUENCE),
			// consistent with gmsm.
		},
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: 8 * len(signature),
		},
	}
	if template.Certificate != nil {
		response.Certificates = []asn1.RawValue{
			{FullBytes: template.Certificate.Raw},
		}
	}
	responseDER, err := asn1.Marshal(response)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(sm2ResponseASN1{
		Status: asn1.Enumerated(ocsp.Success),
		Response: sm2ResponseBytes{
			ResponseType: idPKIXOCSPBasic,
			Response:     responseDER,
		},
	})
}

// oidFromHashAlgorithm mirrors the private helper in x/crypto/ocsp
// (SHA1/SHA256/SHA384/SHA512).
func oidFromHashAlgorithm(target crypto.Hash) asn1.ObjectIdentifier {
	switch target {
	case crypto.SHA1:
		return asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	case crypto.SHA256:
		return asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	case crypto.SHA384:
		return asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2})
	case crypto.SHA512:
		return asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
	}
	return nil
}
