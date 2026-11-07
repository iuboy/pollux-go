package smx509

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// OCSP status codes, mirroring golang.org/x/crypto/ocsp constants.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// CreateOCSPResponse creates an OCSP response signed by the responder.
// If signer is an SM2 private key, the response is signed with SM2+SM3
// (GM/T 0009-2012) via createSM2OCSPResponse; otherwise it delegates to
// golang.org/x/crypto/ocsp.CreateResponse, which cannot handle SM2 keys
// (its signingParamsForPublicKey rejects sm2.P256()).
//
// issuer is the CA whose key issued the certificate being responded about (used
// to compute the CertID name/key hashes). responderCert is the certificate
// whose private key signs the response; it MAY equal issuer (CA-direct
// responder) or be a delegated responder cert signed by issuer.
func CreateOCSPResponse(issuer, responderCert *x509.Certificate, template *ocsp.Response, signer crypto.Signer) ([]byte, error) {
	if issuer == nil {
		return nil, errors.New("smx509: issuer certificate is required to compute the OCSP CertID")
	}
	if responderCert == nil {
		return nil, errors.New("smx509: responder certificate is required to sign the OCSP response")
	}
	if template == nil {
		return nil, errors.New("smx509: OCSP response template is required")
	}
	if sm2Key, ok := signer.(*sm2.PrivateKey); ok {
		return createSM2OCSPResponse(issuer, responderCert, *template, sm2Key)
	}
	return ocsp.CreateResponse(issuer, responderCert, *template, signer)
}

// ParseOCSPRequest parses a DER-encoded OCSP request.
func ParseOCSPRequest(data []byte) (*ocsp.Request, error) {
	return ocsp.ParseRequest(data)
}

// ParseOCSPResponseUnverified parses a DER-encoded OCSP response WITHOUT
// signature verification. The returned Response MUST NOT be trusted for
// security decisions — without verification, an attacker can forge an
// arbitrary status (Good/Revoked/Unknown).
//
// This is intended only for:
//   - Logging/inspection of a response that has already been verified by
//     ParseOCSPResponseWithIssuer in the same request.
//   - Debugging/test tooling that intentionally inspects untrusted input.
//
// For any security-relevant code path, use ParseOCSPResponseWithIssuer.
func ParseOCSPResponseUnverified(data []byte) (*ocsp.Response, error) {
	return ocsp.ParseResponse(data, nil)
}

// ParseOCSPResponseWithIssuer parses and verifies a DER-encoded OCSP response.
// The issuer certificate is used to verify the OCSP response signature.
//
// For SM2-signed responses, the SM2-aware verification path is used (the
// stdlib ocsp.ParseResponse rejects sm2.P256() with "unsupported elliptic
// curve"); for standard algorithms, it delegates to ocsp.ParseResponse.
//
// In addition to signature verification, this function enforces a
// validity-period check: the response is rejected if NextUpdate has passed or
// ThisUpdate is in the future (beyond a small clock-skew tolerance). A
// signature-valid but stale response can otherwise be replayed to mask a
// revocation. Use ParseOCSPResponseWithIssuerAt to supply a reference time
// (e.g. for testing or a fixed verification instant).
//
// Returns an error if issuer is nil, as signature verification would be skipped.
func ParseOCSPResponseWithIssuer(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ParseOCSPResponseWithIssuerAt(data, issuer, time.Now())
}

// ParseOCSPResponseWithIssuerAt is like ParseOCSPResponseWithIssuer but uses
// the supplied now as the reference time for the validity-period check. Pass
// time.Time{} (the zero value) to disable the time check — intended only for
// parsing already-trusted or historical responses where staleness is not
// meaningful.
//
// Delegated responder authorization (RFC 6960 §4.2.2.2): both the SM2 and the
// non-SM2 path reject an embedded responder certificate whose key differs from
// the issuer key unless it carries the id-kp-OCSPSigning EKU — x/crypto's
// ParseResponse only checks that the embedded cert was signed by the issuer,
// so any leaf certificate the attacker holds (e.g. a TLS cert) could otherwise
// forge valid responses. issuer-direct responses (responder key == issuer key)
// need no EKU. issuer nil is rejected at entry (fail-closed, as with the SM2
// path); the deliberately unverified parse-only entry point is
// ParseOCSPResponseUnverified, whose result MUST NOT gate trust decisions.
//
// SM3 CertIDs: if the response's CertID hashes with SM3 (GM/T 0009-2012),
// resp.IssuerHash is reported as crypto.SHA256 — x/crypto's ocsp.Response
// cannot express SM3 (no crypto.Hash constant exists). Do NOT recompute
// CertID hashes from resp.IssuerHash for such a response; distinguish it with
// IsSM3CertID(resp) and hash with github.com/iuboy/pollux-go/sm3.
func ParseOCSPResponseWithIssuerAt(data []byte, issuer *x509.Certificate, now time.Time) (*ocsp.Response, error) {
	if issuer == nil {
		return nil, errors.New("smx509: issuer certificate is required for OCSP response verification")
	}
	if isSM2OCSPResponse(data) {
		return parseSM2OCSPResponse(data, issuer, now)
	}
	// Non-SM2 responses are delegated to x/crypto/ocsp, which does not enforce
	// a time check. Apply the same validity-period policy here for consistency.
	resp, err := ocsp.ParseResponse(data, issuer)
	if err != nil {
		return nil, err
	}
	// RFC 6960 §4.2.2.2 委派响应者授权检查，镜像 SM2 路径
	// （parseSM2OCSPResponse）的同名检查：x/crypto 的 ParseResponse 只验证
	// 内嵌证书确由 issuer 签发（签名链），不检查 id-kp-OCSPSigning EKU——
	// 持有 issuer 所签任意叶子证书（如 TLS 证书）私钥的攻击者都能伪造
	// 「签名链合法」的 OCSP 响应。公钥不等于 issuer 公钥即委派响应者，必须
	// 携带 OCSPSigning EKU；公钥相同（issuer-direct）无需 EKU。issuer 在本
	// 入口已保证非 nil（与 SM2 路径同姿态 fail-closed）。
	if resp.Certificate != nil &&
		!sameResponderKey(resp.Certificate, issuer) &&
		!hasOCSPSigningEKU(resp.Certificate) {
		return nil, errors.New("smx509: embedded responder cert lacks id-kp-OCSPSigning EKU")
	}
	// responseExtensions 的 critical 位检查：x/crypto 不解析响应级扩展
	// （encoding/asn1 静默忽略尾部未知元素），未知 critical 扩展按
	// RFC 6960 §4.2.1 语义必须拒绝；nonce 视为已知扩展。与 SM2 解析路径
	// 共用 checkResponseExtensionsCritical 的统一裁决。
	exts, ok := responseExtensionsFromRaw(data)
	if !ok {
		return nil, errors.New("smx509: OCSP response does not decode as a successful BasicOCSPResponse")
	}
	if err := checkResponseExtensionsCritical(exts); err != nil {
		return nil, err
	}
	if !now.IsZero() {
		if !resp.ThisUpdate.IsZero() && now.Add(ocspFreshnessLeeway).Before(resp.ThisUpdate) {
			return nil, errors.New("smx509: OCSP response ThisUpdate is in the future")
		}
		if !resp.NextUpdate.IsZero() {
			if now.After(resp.NextUpdate) {
				return nil, errors.New("smx509: OCSP response is stale (past NextUpdate)")
			}
		} else if !resp.ThisUpdate.IsZero() && now.Sub(resp.ThisUpdate) > maxOCSPNoNextUpdateAge {
			return nil, errors.New("smx509: OCSP response has no NextUpdate and ThisUpdate exceeds the local maximum age")
		}
	}
	return resp, nil
}

// NewOCSPResponseTemplate creates an OCSP response template for a certificate.
// A nil cert returns an error: the template must carry the serial number of the
// certificate being responded about, and dereferencing a nil cert would panic.
//
// The template's IssuerHash is left zero; both signing paths (createSM2OCSPResponse
// and x/crypto's CreateResponse) then default the CertID hash to SHA-256, since
// ocsp.Response.IssuerHash (crypto.Hash) cannot express SM3. SM3-CertID
// responses are produced by third-party GM responders only; when parsing such a
// response the parser reports IssuerHash = crypto.SHA256 — see IsSM3CertID for
// how to distinguish SM3 before recomputing CertID hashes.
func NewOCSPResponseTemplate(cert, issuer *x509.Certificate, status int, thisUpdate, nextUpdate time.Time) (*ocsp.Response, error) {
	if cert == nil {
		return nil, errors.New("smx509: certificate is required for OCSP response template")
	}
	return &ocsp.Response{
		Status:       status,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Certificate:  issuer,
	}, nil
}
