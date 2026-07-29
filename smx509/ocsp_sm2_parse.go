package smx509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/sm3"
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

// sm3HashOID is the SM3 hash algorithm OID (GM/T 0009-2012).
var sm3HashOID = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

// sm2HashOIDLookup maps OIDs to crypto.Hash for CertID decoding.
// SM3 maps to crypto.SHA256 for OCSP response digest identification since
// crypto.Hash has no SM3 constant; the actual SM3 hashing is done by sm3.New().
var sm2HashOIDLookup = buildHashOIDMap()

func buildHashOIDMap() map[string]crypto.Hash {
	m := make(map[string]crypto.Hash, len(sm2HashOIDs)+1)
	for h, oid := range sm2HashOIDs {
		m[oid.String()] = h
	}
	return m
}

// defaultSM2UID is the default SM2 user identifier per GM/T 0009-2012.
// Used explicitly (rather than nil) to avoid implicit dependency on gmsm's
// default-UID fallback which may change across gmsm releases.
var defaultSM2UID = []byte("1234567812345678")

// parseSM2OCSPResponse is an SM2-aware variant of ocsp.ParseResponseForCert:
// it replaces stdlib x509.CheckSignature (which rejects sm2.P256()) with
// sm2.VerifyASN1WithSM2.
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

	n := len(basicResp.TBSResponseData.Responses)
	if n == 0 {
		return nil, errors.New("smx509: OCSP response contains no statuses")
	}
	if n > 1 {
		// Without a target certificate/serial to filter on (this entry point
		// takes none), a multi-status response is ambiguous: the caller cannot
		// tell which CertID the returned status applies to. x/crypto's
		// ParseResponse rejects this case for the same reason. Accepting
		// Responses[0] blindly would let an attacker satisfy a query about
		// serial X by bundling a "Good" status for serial Y. Fail closed.
		return nil, errors.New("smx509: OCSP response contains multiple statuses; use a cert-filtering parser")
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
	// i.e. ZA+SM3 over the raw TBS DER with the default UID (nil UID + forceGMSign
	// resolves to the default UID inside gmsm). Verify with the explicit
	// defaultSM2UID so both the OCSP-signature path and the embedded-cert issuer
	// path below use identical, self-documenting UIDs.
	verifyAgainst := func(signerCert *x509.Certificate) error {
		pub, ok := signerCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("smx509: responder public key is not ECDSA (SM2)")
		}
		if !sm2.VerifyWithSM2(pub, defaultSM2UID, ret.TBSResponseData, ret.Signature) {
			return errors.New("smx509: bad SM2 OCSP signature")
		}
		return nil
	}

	// matchesResponderID reports whether the ResponderID in the response
	// actually identifies signerCert. RFC 6960 §4.2.2.2/§4.2.2.3 mandate this:
	// ResponderID exists precisely so the relying party can locate the signing
	// cert, and a response whose ResponderID does not match the signer MUST be
	// rejected. Without this check an attacker who controls two authorized
	// responders (or one compromised key plus a second valid cert) could swap
	// the embedded cert while keeping the original ResponderID, defeating the
	// identity binding. x/crypto/ocsp omits this check (it trusts the caller's
	// issuer arg); pollux-go's embedded-cert path goes further and must close
	// the loop.
	//
	// Tag 1 (Name): byte-for-byte DER comparison of the responder's
	// RawSubject against RawResponderName.
	// Tag 2 (KeyHash): Hash(BIT STRING subjectPublicKey) per RFC 6960 §4.4.1,
	// using the CertID hash algorithm.
	matchesResponderID := func(signerCert *x509.Certificate) bool {
		switch basicResp.TBSResponseData.RawResponderID.Tag {
		case 1: // Name
			return bytes.Equal(signerCert.RawSubject, ret.RawResponderName)
		case 2: // KeyHash
			// Determine hash algorithm from the CertID (the same hash MUST be
			// used for both, per RFC 6960 §4.4.1).
			hf := certIDHashFunc(singleResp.CertID.HashAlgorithm.Algorithm)
			if hf == nil {
				return false
			}
			var pubKeyInfo struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(signerCert.RawSubjectPublicKeyInfo, &pubKeyInfo); err != nil {
				return false
			}
			return bytes.Equal(hf(pubKeyInfo.PublicKey.RightAlign()), ret.ResponderKeyHash)
		}
		return false
	}

	if len(basicResp.Certificates) > 0 {
		// Embedded responder cert: parse it (SM2-aware) and verify the
		// response signature against it.
		embedded, perr := ParseCertificate(basicResp.Certificates[0].FullBytes)
		if perr != nil {
			return nil, perr
		}
		// RFC 6960 §4.2.1 vs §4.2.2.2: a CA may sign its own OCSP responses
		// (issuer-direct) using its own certificate, in which case no special
		// EKU applies. Only a DELEGATED responder — a distinct cert whose key
		// the CA authorized to respond on its behalf — MUST carry the
		// id-kp-OCSPSigning EKU. Without that distinction, any leaf the issuer
		// signed (e.g. a TLS cert whose key an attacker holds) could forge
		// valid OCSP responses. We detect issuer-direct by comparing public
		// keys (delegation implies a different key); when issuer is nil we
		// cannot confirm identity, so fail closed by requiring the EKU.
		isIssuerDirect := false
		if issuer != nil {
			ePub, ok1 := embedded.PublicKey.(*ecdsa.PublicKey)
			iPub, ok2 := issuer.PublicKey.(*ecdsa.PublicKey)
			if ok1 && ok2 && ePub.Equal(iPub) {
				isIssuerDirect = true
			}
		}
		if !isIssuerDirect && !hasOCSPSigningEKU(embedded) {
			return nil, errors.New("smx509: embedded responder cert lacks id-kp-OCSPSigning EKU")
		}
		ret.Certificate = embedded
		if err := verifyAgainst(embedded); err != nil {
			return nil, errors.New("smx509: bad signature on embedded certificate: " + err.Error())
		}
		// RFC 6960 §4.2.2.2: ResponderID MUST identify the actual signer.
		if !matchesResponderID(embedded) {
			return nil, errors.New("smx509: OCSP ResponderID does not match embedded responder certificate")
		}
		// Optionally verify the embedded cert was signed by issuer.
		if issuer != nil {
			issuerPub, ok := issuer.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("smx509: issuer public key is not ECDSA (SM2)")
			}
			if !sm2.VerifyWithSM2(issuerPub, defaultSM2UID, embedded.RawTBSCertificate, embedded.Signature) {
				return nil, errors.New("smx509: embedded responder cert not signed by issuer")
			}
		}
	} else if issuer != nil {
		if err := verifyAgainst(issuer); err != nil {
			return nil, errors.New("smx509: bad SM2 OCSP signature: " + err.Error())
		}
		// Same §4.2.2.2 binding for the issuer-direct path.
		if !matchesResponderID(issuer) {
			return nil, errors.New("smx509: OCSP ResponderID does not match issuer certificate")
		}
	}

	for _, ext := range singleResp.SingleExtensions {
		if ext.Critical {
			return nil, errors.New("smx509: unsupported critical extension in OCSP singleResponse")
		}
	}

	// CertID hash algorithm. Check SM3 first (GM-specific), then fall back to
	// the standard crypto.Hash OIDs.
	certIDHashOID := singleResp.CertID.HashAlgorithm.Algorithm
	if certIDHashOID.Equal(sm3HashOID) {
		ret.IssuerHash = crypto.SHA256 // map SM3 to SHA256 (no crypto.Hash constant for SM3)
	} else {
		for h, oid := range sm2HashOIDs {
			if certIDHashOID.Equal(oid) {
				ret.IssuerHash = h
				break
			}
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

// oidExtKeyUsageOCSPSigning is id-kp-OCSPSigning (RFC 6960 §4.2.2.2).
var oidExtKeyUsageOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}

// hasOCSPSigningEKU reports whether cert is authorized to sign OCSP responses
// as a delegated responder. RFC 6960 §4.2.2.2 mandates the id-kp-OCSPSigning
// EKU on delegated responder certs. Both the recognized ExtKeyUsage slice and
// the raw UnknownExtKeyUsage OIDs are checked, so a cert whose EKU the parser
// left unmapped is still handled correctly.
func hasOCSPSigningEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ku := range cert.ExtKeyUsage {
		if ku == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidExtKeyUsageOCSPSigning) {
			return true
		}
	}
	return false
}

// certIDHashFunc returns a function that hashes data using the algorithm named
// by oid, or nil if the OID is unrecognized or unavailable. SM3 (which has no
// crypto.Hash constant) is handled via sm3.New; the standard hashes via
// crypto.Hash.New. Used by ResponderID key-hash matching where the algorithm
// is taken from the CertID per RFC 6960 §4.4.1.
func certIDHashFunc(oid asn1.ObjectIdentifier) func([]byte) []byte {
	if oid.Equal(sm3HashOID) {
		return func(b []byte) []byte {
			h := sm3.New()
			h.Write(b)
			return h.Sum(nil)
		}
	}
	for h, ha := range sm2HashOIDs {
		if oid.Equal(ha) && h.Available() {
			return func(b []byte) []byte {
				ht := h.New()
				ht.Write(b)
				return ht.Sum(nil)
			}
		}
	}
	return nil
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
