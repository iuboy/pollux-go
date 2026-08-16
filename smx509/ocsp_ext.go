// This file adds RFC 6960 response-level extension support (notably the
// §4.4.1 nonce echo) to OCSP response construction, plus request/response
// nonce extraction helpers. The upstream implementations — x/crypto/ocsp and
// this package's CreateOCSPResponse/template path — only support
// singleResponse extensions, so a nonce cannot be echoed in its
// standard-mandated position. The DER assembly mirrors ocsp.CreateResponse /
// createSM2OCSPResponse; the responderID-by-Name, CertID hashing and
// basicResponse envelope are identical, with these differences:
//
//   - responseData carries responseExtensions ([1] EXPLICIT, RFC 6960 §4.2.1);
//   - revokedInfo omits cRLReason entirely when reason=unspecified(0)
//     (RFC 5280 §5.3.1 SHOULD be absent);
//   - the CertID hash is caller-controlled (echo the request's HashAlgorithm);
//   - one signer dispatch covers SM2 (SM2+SM3 with ZA), RSA, ECDSA and
//     Ed25519 — x/crypto.CreateResponse is not reused because it cannot emit
//     responseExtensions.
//
// Interop note: encoding/asn1 ignores trailing SEQUENCE elements it has no
// struct field for, so responses carrying responseExtensions parse fine with
// x/crypto's ParseResponse and with this package's SM2 parser (verified
// experimentally against x/crypto and `openssl ocsp -text`); the nonce is
// always encoded in the standard responseExtensions position.
//
// Verification note: x/crypto's ParseResponse can only VERIFY responses
// signed with RSA or ECDSA (its algorithm table has no Ed25519 or SM2
// entries). SM2-signed responses verify via this package's
// ParseOCSPResponseWithIssuer; Ed25519-signed responses must be verified by
// the caller (ed25519.Verify over the raw tbsResponseData) — see the
// ocsp_ext_test.go Ed25519 case for a reference implementation.
package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// oidExtOCSPNonce is id-pkix-OCSP-noarch (RFC 6960 §4.4.1 nonce).
var oidExtOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// Standard signature-algorithm OIDs for the non-SM2 signer dispatch.
var (
	oidSignatureRSA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureECDSA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519  = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// OCSPResponseParams is the parameter set for CreateOCSPResponseExt. It is a
// controlled superset of x/crypto's ocsp.Response; a standalone type is
// required because ocsp.Response has no field for response-level extensions
// (where the RFC 6960 §4.4.1 nonce must live).
type OCSPResponseParams struct {
	Status           int // ocsp.Good / ocsp.Revoked / ocsp.Unknown
	SerialNumber     *big.Int
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevokedAt        time.Time
	RevocationReason int
	// Certificate is the responder certificate embedded in the response
	// (nil omits the certificates field).
	Certificate *x509.Certificate
	// IssuerHash selects the CertID hash (echo the request's HashAlgorithm).
	// Zero defaults to SHA-256.
	IssuerHash crypto.Hash
	// Nonce, when non-empty, is echoed as an id-pkix-OCSP-noarch
	// responseExtension (RFC 6960 §4.4.1). Responders MUST echo the exact
	// request nonce to bind the response to the request (anti-replay).
	Nonce []byte
	// ExtraExtensions are appended to responseExtensions verbatim, after the
	// Nonce extension (caller is responsible for OID uniqueness).
	ExtraExtensions []pkix.Extension
}

// CreateOCSPResponseExt builds a DER-encoded OCSP response with
// responseExtensions support. The signer dispatch covers SM2 (SM2+SM3 with
// ZA, default UID) and standard algorithms (RSA PKCS#1 v1.5, ECDSA, Ed25519;
// digest SHA-256 or stronger). It complements CreateOCSPResponse, which
// remains for the nonce-free ocsp.Response template path.
func CreateOCSPResponseExt(issuer, responderCert *x509.Certificate, p *OCSPResponseParams, signer crypto.Signer) ([]byte, error) {
	if issuer == nil || responderCert == nil {
		return nil, errors.New("smx509: issuer/responder certificate must not be nil")
	}
	if p == nil {
		return nil, errors.New("smx509: OCSP response params must not be nil")
	}
	if signer == nil {
		return nil, errors.New("smx509: signer must not be nil")
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}

	issuerHash := p.IssuerHash
	if issuerHash == 0 {
		issuerHash = crypto.SHA256
	}
	if !issuerHash.Available() {
		return nil, fmt.Errorf("smx509: issuer hash %v not linked into binary", issuerHash)
	}
	hashOID := oidFromHashAlgorithm(issuerHash)
	if hashOID == nil {
		return nil, errors.New("smx509: unsupported issuer hash algorithm")
	}
	h := issuerHash.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)
	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	inner := extSingleResponse{
		CertID: extCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.RawValue{Tag: 5}, // ASN.1 NULL
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  p.SerialNumber,
		},
		ThisUpdate: p.ThisUpdate.UTC(),
		NextUpdate: p.NextUpdate.UTC(),
	}

	switch p.Status {
	case ocsp.Good:
		inner.Good = true
	case ocsp.Unknown:
		inner.Unknown = true
	case ocsp.Revoked:
		rv, err := marshalRevokedInfoRaw(p.RevokedAt.UTC(), p.RevocationReason)
		if err != nil {
			return nil, err
		}
		inner.Revoked = rv
	default:
		return nil, fmt.Errorf("smx509: unknown OCSP status %d", p.Status)
	}

	respExts := make([]pkix.Extension, 0, 1+len(p.ExtraExtensions))
	if len(p.Nonce) > 0 {
		nonceVal, err := asn1.Marshal(p.Nonce)
		if err != nil {
			return nil, err
		}
		respExts = append(respExts, pkix.Extension{Id: oidExtOCSPNonce, Value: nonceVal})
	}
	respExts = append(respExts, p.ExtraExtensions...)

	tbs := extResponseData{
		Version:            0,
		RawResponderID:     asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: responderCert.RawSubject},
		ProducedAt:         time.Now().Truncate(time.Minute).UTC(),
		Responses:          []extSingleResponse{inner},
		ResponseExtensions: respExts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}

	signature, sigAlg, err := signTBSResponse(signer, tbsDER)
	if err != nil {
		return nil, err
	}

	resp := extBasicResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: sigAlg,
		Signature:          asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	}
	if p.Certificate != nil {
		resp.Certificates = []asn1.RawValue{{FullBytes: p.Certificate.Raw}}
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(extResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: extResponseBytes{ResponseType: idPKIXOCSPBasic, Response: respDER},
	})
}

// OCSPErrorResponse builds a responseStatus-only OCSP response (no
// responseBytes), per RFC 6960 §4.2.1 error handling. status is one of the
// x/crypto/ocsp response statuses: MalformedRequest(1), InternalError(2),
// TryLater(3), SigRequired(5), Unauthorized(6).
func OCSPErrorResponse(status int) []byte {
	der, _ := asn1.Marshal(struct {
		Status asn1.Enumerated
	}{Status: asn1.Enumerated(status)})
	return der
}

// ExtractOCSPRequestNonce parses the requestExtensions of a DER-encoded OCSP
// request and returns the id-pkix-OCSP-noarch nonce (nil when absent or the
// request is malformed — callers rejecting bad requests separately anyway).
// x/crypto's public ocsp.Request does not expose requestExtensions, hence
// this standalone helper.
func ExtractOCSPRequestNonce(reqBytes []byte) []byte {
	var outer struct {
		TBSRequest struct {
			Version           int              `asn1:"optional,explicit,default:0,tag:0"`
			RequestorName     asn1.RawValue    `asn1:"optional,tag:1"`
			RequestList       []asn1.RawValue  `asn1:"optional"`
			RequestExtensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
		}
	}
	if _, err := asn1.Unmarshal(reqBytes, &outer); err != nil {
		return nil
	}
	for _, ext := range outer.TBSRequest.RequestExtensions {
		if ext.Id.Equal(oidExtOCSPNonce) {
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				return nonce
			}
		}
	}
	return nil
}

// ResponseNonce extracts the id-pkix-OCSP-noarch nonce from a DER-encoded
// OCSP response's responseExtensions. It is the parsing counterpart of
// CreateOCSPResponseExt's Nonce field: a client that sent a nonce uses it to
// bind the response to its request (RFC 6960 §4.4.1: on mismatch the response
// MUST be rejected as replayed/forged).
func ResponseNonce(respDER []byte) ([]byte, error) {
	var outer extResponseASN1
	rest, err := asn1.Unmarshal(respDER, &outer)
	if err != nil {
		return nil, fmt.Errorf("smx509: parse OCSP response: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("smx509: trailing data in OCSP response")
	}
	if outer.Status != asn1.Enumerated(ocsp.Success) || !outer.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return nil, errors.New("smx509: response is not a successful BasicOCSPResponse")
	}
	var basic extBasicResponse
	if rest2, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		return nil, fmt.Errorf("smx509: parse basic OCSP response: %w", err)
	} else if len(rest2) > 0 {
		return nil, errors.New("smx509: trailing data in basic OCSP response")
	}
	for _, ext := range basic.TBSResponseData.ResponseExtensions {
		if ext.Id.Equal(oidExtOCSPNonce) {
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err != nil {
				return nil, fmt.Errorf("smx509: malformed OCSP nonce extension: %w", err)
			}
			return nonce, nil
		}
	}
	return nil, nil // no nonce present — not an error
}

// --- ASN.1 structures (encoding side; mirror the unexported x/crypto layout
// plus responseExtensions) ---

type extCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

// extSingleResponse encodes revokedInfo as a pre-assembled RawValue so that
// reason=0 can omit cRLReason entirely (see marshalRevokedInfoRaw).
type extSingleResponse struct {
	CertID           extCertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          asn1.RawValue    `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type extResponseData struct {
	Version            int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID     asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []extSingleResponse
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"` // RFC 6960 §4.2.1 [1] EXPLICIT
}

type extBasicResponse struct {
	TBSResponseData    extResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type extResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type extResponseASN1 struct {
	Status   asn1.Enumerated  `asn1:"enumerated"`
	Response extResponseBytes `asn1:"explicit,tag:0,optional"`
}

// --- signing dispatch ---

// signTBSResponse signs the DER-encoded tbsResponseData with the signer's
// native algorithm. SM2 signs the raw TBS (ZA+SM3 inside gmsm); RSA/ECDSA
// hash first (SHA-256 or curve-appropriate); Ed25519 signs the raw TBS
// (PureEd25519 — crypto.Hash(0).New() would panic, so it is special-cased).
func signTBSResponse(signer crypto.Signer, tbsDER []byte) (signature []byte, sigAlg pkix.AlgorithmIdentifier, err error) {
	if sm2Key, ok := signer.(*sm2.PrivateKey); ok {
		sig, sErr := sm2Key.Sign(rand.Reader, tbsDER, sm2.NewSM2SignerOption(true, nil))
		if sErr != nil {
			return nil, sigAlg, fmt.Errorf("smx509: SM2 sign OCSP response: %w", sErr)
		}
		return sig, pkix.AlgorithmIdentifier{
			Algorithm:  oidSignatureSM2WithSM3,
			Parameters: asn1.RawValue{Tag: 5},
		}, nil
	}

	switch pub := signer.Public().(type) {
	case ed25519.PublicKey:
		// PureEd25519: sign the message directly, no pre-hash.
		sig, sErr := signer.Sign(rand.Reader, tbsDER, crypto.Hash(0))
		if sErr != nil {
			return nil, sigAlg, fmt.Errorf("smx509: ed25519 sign OCSP response: %w", sErr)
		}
		_ = pub
		return sig, pkix.AlgorithmIdentifier{Algorithm: oidSignatureEd25519}, nil
	case *rsa.PublicKey:
		digest := sha256Sum(tbsDER)
		sig, sErr := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if sErr != nil {
			return nil, sigAlg, fmt.Errorf("smx509: rsa sign OCSP response: %w", sErr)
		}
		return sig, pkix.AlgorithmIdentifier{
			Algorithm:  oidSignatureRSA256,
			Parameters: asn1.RawValue{Tag: 5},
		}, nil
	case *ecdsa.PublicKey:
		var hash crypto.Hash
		var sigOID asn1.ObjectIdentifier
		switch pub.Curve.Params().BitSize {
		case 521:
			hash, sigOID = crypto.SHA512, oidSignatureECDSA512
		case 384:
			hash, sigOID = crypto.SHA384, oidSignatureECDSA384
		default:
			hash, sigOID = crypto.SHA256, oidSignatureECDSA256
		}
		digest := hash.New()
		digest.Write(tbsDER)
		sig, sErr := signer.Sign(rand.Reader, digest.Sum(nil), hash)
		if sErr != nil {
			return nil, sigAlg, fmt.Errorf("smx509: ecdsa sign OCSP response: %w", sErr)
		}
		return sig, pkix.AlgorithmIdentifier{
			Algorithm:  sigOID,
			Parameters: asn1.RawValue{Tag: 5},
		}, nil
	default:
		return nil, sigAlg, fmt.Errorf("smx509: unsupported OCSP signer key type %T", signer.Public())
	}
}

// marshalRevokedInfoRaw assembles revokedInfo DER and returns it as a [1]
// IMPLICIT RawValue for mounting in singleResponse. encoding/asn1 cannot
// omit an optional non-pointer field, so reason=unspecified(0) — where
// RFC 5280 §5.3.1 says cRLReason SHOULD be absent — is handled by marshaling
// a reason-less struct.
func marshalRevokedInfoRaw(at time.Time, reason int) (asn1.RawValue, error) {
	var der []byte
	var err error
	if reason != 0 {
		der, err = asn1.Marshal(extRevokedInfo{
			RevocationTime: at,
			Reason:         asn1.Enumerated(reason),
		})
	} else {
		der, err = asn1.Marshal(struct {
			RevocationTime time.Time `asn1:"generalized"`
		}{RevocationTime: at})
	}
	if err != nil {
		return asn1.RawValue{}, err
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return asn1.RawValue{}, err
	}
	// [1] IMPLICIT: Bytes holds the SEQUENCE content (header stripped).
	return asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: outer.Bytes}, nil
}

// extRevokedInfo is the reason-carrying form used only when reason != 0;
// its Reason field is always valid there, so the optional tag encodes.
type extRevokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(b)
	return h.Sum(nil)
}
