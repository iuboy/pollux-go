package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// sm2HashOIDs maps CertID hash algorithm OIDs to crypto.Hash, mirroring the
// private hashOIDs table in golang.org/x/crypto/ocsp.
var sm2HashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
	crypto.SHA256: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
	crypto.SHA384: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2},
	crypto.SHA512: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3},
}

// parseSM2OCSPResponse parses an OCSP response signed with SM2+SM3, verifying
// the signature against the issuer's SM2 public key. It mirrors the structure
// of ocsp.ParseResponseForCert but replaces stdlib x509.CheckSignature (which
// rejects sm2.P256()) with sm2.VerifyASN1WithSM2.
//
// issuer is the CA certificate whose key signed the OCSP response; if nil,
// signature verification is skipped (parse-only). If the response embeds a
// responder certificate, that certificate is also verified against issuer
// (when issuer is non-nil) using SM2 verification.
func parseSM2OCSPResponse(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp sm2ResponseASN1
	rest, err := asn1.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("smx509: trailing data in OCSP response")
	}
	if ocsp.ResponseStatus(resp.Status) != ocsp.Success {
		return nil, ocsp.ResponseError{Status: ocsp.ResponseStatus(resp.Status)}
	}
	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return nil, errors.New("smx509: bad OCSP response type")
	}

	var basicResp sm2BasicResponse
	rest, err = asn1.Unmarshal(resp.Response.Response, &basicResp)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("smx509: trailing data in basic OCSP response")
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 {
		return nil, errors.New("smx509: OCSP response contains no statuses")
	}
	singleResp := basicResp.TBSResponseData.Responses[0]

	ret := &ocsp.Response{
		Raw:                data,
		TBSResponseData:    basicResp.TBSResponseData.Raw,
		Signature:          basicResp.Signature.RightAlign(),
		SignatureAlgorithm: x509.UnknownSignatureAlgorithm, // SM2 has no stdlib enum
		Extensions:         singleResp.SingleExtensions,
		SerialNumber:       singleResp.CertID.SerialNumber,
		ProducedAt:         basicResp.TBSResponseData.ProducedAt,
		ThisUpdate:         singleResp.ThisUpdate,
		NextUpdate:         singleResp.NextUpdate,
	}

	// ResponderID CHOICE: tag 1 = Name, tag 2 = KeyHash.
	switch basicResp.TBSResponseData.RawResponderID.Tag {
	case 1:
		ret.RawResponderName = basicResp.TBSResponseData.RawResponderID.Bytes
	case 2:
		if rest, err := asn1.Unmarshal(basicResp.TBSResponseData.RawResponderID.Bytes, &ret.ResponderKeyHash); err != nil || len(rest) != 0 {
			return nil, errors.New("smx509: invalid responder key hash")
		}
	default:
		return nil, errors.New("smx509: invalid responder id tag")
	}

	// Verify signature. SM2 signing used priv.Sign(rand, tbsDER, NewSM2SignerOption(true, nil)),
	// i.e. ZA+SM3 over the raw TBS DER with the default UID. Verify with the
	// symmetric call: VerifyASN1WithSM2(pub, nil, tbsDER, sig).
	verifyAgainst := func(signerCert *x509.Certificate) error {
		pub, ok := signerCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("smx509: responder public key is not ECDSA (SM2)")
		}
		if !sm2.VerifyWithSM2(pub, nil, ret.TBSResponseData, ret.Signature) {
			return errors.New("smx509: bad SM2 OCSP signature")
		}
		return nil
	}

	if len(basicResp.Certificates) > 0 {
		// Embedded responder cert: parse it (SM2-aware) and verify the
		// response signature against it.
		embedded, perr := ParseCertificate(basicResp.Certificates[0].FullBytes)
		if perr != nil {
			return nil, perr
		}
		ret.Certificate = embedded
		if err := verifyAgainst(embedded); err != nil {
			return nil, errors.New("smx509: bad signature on embedded certificate: " + err.Error())
		}
		// Optionally verify the embedded cert was signed by issuer.
		if issuer != nil {
			issuerPub, ok := issuer.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("smx509: issuer public key is not ECDSA (SM2)")
			}
			if !sm2.VerifyWithSM2(issuerPub, nil, embedded.RawTBSCertificate, embedded.Signature) {
				return nil, errors.New("smx509: embedded responder cert not signed by issuer")
			}
		}
	} else if issuer != nil {
		if err := verifyAgainst(issuer); err != nil {
			return nil, errors.New("smx509: bad SM2 OCSP signature: " + err.Error())
		}
	}

	for _, ext := range singleResp.SingleExtensions {
		if ext.Critical {
			return nil, errors.New("smx509: unsupported critical extension in OCSP singleResponse")
		}
	}

	// CertID hash algorithm.
	certIDHashOID := singleResp.CertID.HashAlgorithm.Algorithm
	for h, oid := range sm2HashOIDs {
		if certIDHashOID.Equal(oid) {
			ret.IssuerHash = h
			break
		}
	}
	if ret.IssuerHash == 0 {
		return nil, errors.New("smx509: unsupported issuer hash algorithm in CertID")
	}

	switch {
	case bool(singleResp.Good):
		ret.Status = ocsp.Good
	case bool(singleResp.Unknown):
		ret.Status = ocsp.Unknown
	default:
		ret.Status = ocsp.Revoked
		ret.RevokedAt = singleResp.Revoked.RevocationTime
		ret.RevocationReason = int(singleResp.Revoked.Reason)
	}

	return ret, nil
}

// isSM2OCSPResponse peeks at the response's signature algorithm OID to decide
// whether to route through the SM2-aware parser. Returns true if the basic
// response is signed with the SM2withSM3 OID.
func isSM2OCSPResponse(data []byte) bool {
	var resp sm2ResponseASN1
	if _, err := asn1.Unmarshal(data, &resp); err != nil {
		return false
	}
	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return false
	}
	var basicResp sm2BasicResponse
	if _, err := asn1.Unmarshal(resp.Response.Response, &basicResp); err != nil {
		return false
	}
	return basicResp.SignatureAlgorithm.Algorithm.Equal(oidSignatureSM2WithSM3)
}
