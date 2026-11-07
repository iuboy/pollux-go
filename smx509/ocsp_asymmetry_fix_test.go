package smx509

// 双路径（SM2 / 非 SM2）安全不对称修复回归测试（批 D 清单外发现）：
//  1. 非 SM2 路径的内嵌响应者证书有效期窗（镜像 SM2 路径同名检查）；
//  2. 非 SM2 路径的 ResponderID ↔ 实际签名者绑定（镜像 SM2 路径的
//     matchesResponderID，byName/byKey 两形态）。

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// makeDelegatedECDSACert 用 caKey 为 responderKey 签发一张委派证书
// （ECDSA P-256）：withEKU 决定是否携带 id-kp-OCSPSigning（委派响应者
// 必需，issuer-direct 免除）；notBefore/notAfter 由调用方给定，以构造
// 过期/未生效形态；cn 由调用方指定——同一把 responderKey 配不同 cn 即得
// 同钥异主体证书（证书对调攻击面）。
func makeDelegatedECDSACert(t *testing.T, caKey crypto.Signer, caCert *x509.Certificate, responderKey *ecdsa.PrivateKey, serial int64, cn string, notBefore, notAfter time.Time, withEKU bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    responderKey.Public(),
	}
	if withEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, responderKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create delegated cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse delegated cert: %v", err)
	}
	return cert
}

// standardPublicKeyHash 以指定哈希算法计算证书公钥 BIT STRING 内容的摘要，
// 与 matchesStandardResponderID 的 byKey 重算取法一致。
func standardPublicKeyHash(t *testing.T, cert *x509.Certificate, h crypto.Hash) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatalf("unmarshal SubjectPublicKeyInfo: %v", err)
	}
	d := h.New()
	d.Write(spki.PublicKey.RightAlign())
	return d.Sum(nil)
}

// buildStandardByKeyResponse 组装 responderID-byKey 形态、ECDSA-SHA256
// 真签名的 BasicOCSPResponse（非 SM2 路径）。x/crypto 与本包的构造侧均只
// 产生 byName 形态，byKey 只能手工组 DER：byKey 哈希取 keyHashCert 公钥
// （BIT STRING 内容）按 SHA-256 计算，CertID 哈希算法同为 SHA-256——与
// matchesStandardResponderID 按 CertID 哈希算法重算的取法一致。embedded
// 为 nil 时不内嵌证书。
func buildStandardByKeyResponse(t *testing.T, signerCert *x509.Certificate, signerKey crypto.Signer, keyHashCert *x509.Certificate, embedded *x509.Certificate) []byte {
	t.Helper()
	keyHashDER, err := asn1.Marshal(standardPublicKeyHash(t, keyHashCert, crypto.SHA256))
	if err != nil {
		t.Fatalf("marshal responder key hash: %v", err)
	}
	tbs := extResponseData{
		// responderID-byKey：[2] EXPLICIT OCTET STRING（RFC 6960 §4.2.2.3，
		// 与 SM2 解析侧 asn1.Unmarshal(rid.Bytes, &ResponderKeyHash) 的
		// 期望一致）。
		RawResponderID: asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: keyHashDER},
		ProducedAt:     time.Now().UTC(),
		Responses: []extSingleResponse{{
			CertID: extCertID{
				HashAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm:  oidFromHashAlgorithm(crypto.SHA256),
					Parameters: asn1.RawValue{Tag: 5}, // ASN.1 NULL
				},
				NameHash:      make([]byte, 32),
				IssuerKeyHash: make([]byte, 32),
				SerialNumber:  big.NewInt(42),
			},
			Good:       true,
			ThisUpdate: time.Now().UTC(),
			NextUpdate: time.Now().Add(time.Hour).UTC(),
		}},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbsResponseData: %v", err)
	}
	sig, sigAlg, err := signTBSResponse(signerKey, tbsDER)
	if err != nil {
		t.Fatalf("sign tbsResponseData: %v", err)
	}
	basic := extBasicResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: sigAlg,
		Signature:          asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	}
	if embedded != nil {
		basic.Certificates = []asn1.RawValue{{FullBytes: embedded.Raw}}
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		t.Fatalf("marshal basicOCSPResponse: %v", err)
	}
	respDER, err := asn1.Marshal(extResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: extResponseBytes{ResponseType: idPKIXOCSPBasic, Response: basicDER},
	})
	if err != nil {
		t.Fatalf("marshal OCSPResponse: %v", err)
	}
	return respDER
}

// TestParseOCSPResponseWithIssuer_StandardResponderIDBinding 锁定非 SM2
// 路径的 ResponderID 绑定检查，攻击模型镜像 SM2 路径的
// TestParseOCSPResponseWithIssuer_ResponderIDMismatch：响应者持一把私钥配
// 两张不同主体的授权证书（均带 OCSPSigning EKU），以该钥签名、ResponderID
// 声称 A、内嵌 B——签名对 B 成立（同钥）、签名链与 EKU 亦全部成立，唯有
// 绑定校验能识破证书对调。修复前 x/crypto 完整放行该响应。
func TestParseOCSPResponseWithIssuer_StandardResponderIDBinding(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)
	now := time.Now().UTC()
	validFrom := now.Add(-time.Hour)
	validUntil := now.Add(24 * time.Hour)

	sharedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certA := makeDelegatedECDSACert(t, caKey, caCert, sharedKey, 10, "responder-A", validFrom, validUntil, true)
	certB := makeDelegatedECDSACert(t, caKey, caCert, sharedKey, 11, "responder-B", validFrom, validUntil, true)

	mkResp := func(responderCert, embedded *x509.Certificate, signer crypto.Signer) []byte {
		t.Helper()
		der, err := CreateOCSPResponse(caCert, responderCert, &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(42),
			ThisUpdate:   now,
			NextUpdate:   now.Add(time.Hour),
			Certificate:  embedded,
		}, signer)
		if err != nil {
			t.Fatalf("CreateOCSPResponse: %v", err)
		}
		return der
	}

	// 正例：合法委派（ResponderID 与内嵌证书同体）。
	if _, err := ParseOCSPResponseWithIssuer(mkResp(certA, certA, sharedKey), caCert); err != nil {
		t.Fatalf("ResponderID 与内嵌证书同体的委派响应应通过: %v", err)
	}
	// 正例：issuer-direct（响应者即 issuer，内嵌 issuer 证书）。
	if _, err := ParseOCSPResponseWithIssuer(mkResp(caCert, caCert, caKey), caCert); err != nil {
		t.Fatalf("issuer-direct 响应应通过绑定校验: %v", err)
	}
	// 正例：issuer-direct 且不内嵌证书（签名由 issuer 校验，绑定对象即 issuer）。
	if _, err := ParseOCSPResponseWithIssuer(mkResp(caCert, nil, caKey), caCert); err != nil {
		t.Fatalf("无内嵌证书的 issuer-direct 响应应通过绑定校验: %v", err)
	}

	// 负例（证书对调）：签名钥与内嵌证书一致（certB），ResponderID 却声称
	// certA——x/crypto 的签名/EKU 检查全部放行，绑定校验必须拒绝。
	swap := mkResp(certA, certB, sharedKey)
	_, err = ParseOCSPResponseWithIssuer(swap, caCert)
	if err == nil {
		t.Fatal("ResponderID 与内嵌证书不匹配（证书对调）应被拒绝")
	}
	if !strings.Contains(err.Error(), "ResponderID does not match embedded responder certificate") {
		t.Fatalf("错误应指明 ResponderID 与内嵌证书不匹配，got: %v", err)
	}
	// 绑定校验非时间类检查，不受 parse-only（now 为零）豁免。
	if _, err := ParseOCSPResponseWithIssuerAt(swap, caCert, time.Time{}); err == nil {
		t.Fatal("now 为零时绑定校验仍应拒绝证书对调")
	}
}

// TestParseOCSPResponseWithIssuer_StandardResponderIDByKey 锁定非 SM2 路径
// 绑定检查的 byKey 形态（RFC 6960 §4.2.2.3）：byKey 公钥哈希必须与实际
// 签名者一致——无内嵌证书时为 issuer（issuer-direct），有内嵌证书时为
// 内嵌委派证书。构造侧只产生 byName，byKey 形态由手工 DER 覆盖。
func TestParseOCSPResponseWithIssuer_StandardResponderIDByKey(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)
	now := time.Now().UTC()
	validFrom := now.Add(-time.Hour)
	validUntil := now.Add(24 * time.Hour)

	// certA 只被引用主体与公钥（byKey 声称对象），certB 的私钥实际签名。
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certA := makeDelegatedECDSACert(t, caKey, caCert, keyA, 20, "responder-A", validFrom, validUntil, true)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certB := makeDelegatedECDSACert(t, caKey, caCert, keyB, 21, "responder-B", validFrom, validUntil, true)

	// 正例：issuer-direct（byKey = issuer 公钥哈希，无内嵌证书）。
	if _, err := ParseOCSPResponseWithIssuer(buildStandardByKeyResponse(t, caCert, caKey, caCert, nil), caCert); err != nil {
		t.Fatalf("byKey 指向 issuer 的响应应通过绑定校验: %v", err)
	}
	// 正例：合法委派（byKey = 内嵌委派证书公钥哈希）。
	if _, err := ParseOCSPResponseWithIssuer(buildStandardByKeyResponse(t, certB, keyB, certB, certB), caCert); err != nil {
		t.Fatalf("byKey 指向内嵌委派证书的响应应通过绑定校验: %v", err)
	}

	// 负例：byKey 声称 certA 的公钥，实际签名为 certB 的私钥并内嵌 certB。
	_, err := ParseOCSPResponseWithIssuer(buildStandardByKeyResponse(t, certB, keyB, certA, certB), caCert)
	if err == nil {
		t.Fatal("byKey 与内嵌证书公钥不匹配应被拒绝")
	}
	if !strings.Contains(err.Error(), "ResponderID does not match embedded responder certificate") {
		t.Fatalf("错误应指明 ResponderID 与内嵌证书不匹配，got: %v", err)
	}

	// 负例：byKey 声称 certA 的公钥，无内嵌证书，签名由 issuer 作出——
	// 绑定对象是 issuer，不匹配即拒。
	_, err = ParseOCSPResponseWithIssuer(buildStandardByKeyResponse(t, caCert, caKey, certA, nil), caCert)
	if err == nil {
		t.Fatal("byKey 与 issuer 公钥不匹配应被拒绝")
	}
	if !strings.Contains(err.Error(), "ResponderID does not match issuer certificate") {
		t.Fatalf("错误应指明 ResponderID 与 issuer 不匹配，got: %v", err)
	}
}

// TestParseOCSPResponseWithIssuer_StandardEmbeddedCertValidityWindow 锁定
// 非 SM2 路径的内嵌响应者证书有效期窗（镜像 SM2 路径）：过期/未生效的
// 委派响应者证书拒收；窗口内通过（控制组）；parse-only（now 为零）跳过
// 该窗，与 SM2 路径一致。
func TestParseOCSPResponseWithIssuer_StandardEmbeddedCertValidityWindow(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)
	now := time.Now().UTC()

	mk := func(cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
		t.Helper()
		der, err := CreateOCSPResponse(caCert, cert, &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(42),
			ThisUpdate:   now.Add(-time.Minute),
			NextUpdate:   now.Add(time.Hour),
			Certificate:  cert,
		}, key)
		if err != nil {
			t.Fatalf("CreateOCSPResponse: %v", err)
		}
		return der
	}

	// 控制组：有效窗口内的委派响应者通过。
	liveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	liveCert := makeDelegatedECDSACert(t, caKey, caCert, liveKey, 30, "responder-live", now.Add(-time.Hour), now.Add(24*time.Hour), true)
	if _, err := ParseOCSPResponseWithIssuerAt(mk(liveCert, liveKey), caCert, now); err != nil {
		t.Fatalf("有效期内委派响应者应通过: %v", err)
	}

	// 过期的委派响应者：签名、签名链、EKU、ResponderID 绑定全部成立，
	// 有效期窗必须拒绝。
	expiredKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expiredCert := makeDelegatedECDSACert(t, caKey, caCert, expiredKey, 31, "responder-expired", now.Add(-48*time.Hour), now.Add(-24*time.Hour), true)
	_, err := ParseOCSPResponseWithIssuerAt(mk(expiredCert, expiredKey), caCert, now)
	if err == nil {
		t.Fatal("过期内嵌响应者证书应被拒绝")
	}
	if !strings.Contains(err.Error(), "embedded responder certificate is expired") {
		t.Fatalf("错误应指明内嵌证书过期，got: %v", err)
	}

	// 未生效的委派响应者：同理拒绝（now+leeway 仍早于 NotBefore）。
	futureKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	futureCert := makeDelegatedECDSACert(t, caKey, caCert, futureKey, 32, "responder-future", now.Add(2*time.Hour), now.Add(26*time.Hour), true)
	_, err = ParseOCSPResponseWithIssuerAt(mk(futureCert, futureKey), caCert, now)
	if err == nil {
		t.Fatal("未生效内嵌响应者证书应被拒绝")
	}
	if !strings.Contains(err.Error(), "embedded responder certificate is not yet valid") {
		t.Fatalf("错误应指明内嵌证书未生效，got: %v", err)
	}

	// parse-only（now 为零）：跳过有效期窗，过期响应可解析（与 SM2 路径
	// 的 now.IsZero 豁免一致）。
	if _, err := ParseOCSPResponseWithIssuerAt(mk(expiredCert, expiredKey), caCert, time.Time{}); err != nil {
		t.Fatalf("now 为零时应跳过内嵌证书有效期窗: %v", err)
	}
}
