package smx509

// 第四轮安全审计（批 D）OCSP 面回归测试：
//  1. 非 SM2 委派响应者必须携带 id-kp-OCSPSigning EKU（镜像 SM2 路径）；
//  2. responseExtensions 的未知 critical 扩展拒绝（SM2 与非 SM2 路径一致）；
//  3. ResponseNonce 重复 nonce 扩展报 malformed（RFC 8954 §2.3 exactly-once）。

import (
	"bytes"
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

	"github.com/iuboy/pollux-go/sm2"
	"golang.org/x/crypto/ocsp"
)

// --- Fix 1：非 SM2 委派响应者 EKU 强制 ---

// TestParseOCSPResponseWithIssuer_StandardDelegatedResponder_EKU 锁定 Fix 1：
// 非 SM2 路径直通 x/crypto 的 ParseResponse，其只验证内嵌证书的 issuer 签名
// 链、不检查 OCSPSigning EKU——普通叶子证书（如 TLS 证书）作委派响应者此前
// 可伪造合法 OCSP 响应。修复后：无 EKU 拒、有 EKU 过、issuer-direct 过。
func TestParseOCSPResponseWithIssuer_StandardDelegatedResponder_EKU(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)

	respKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		PublicKey:    respKey.Public(),
	}
	noEKUDER, err := x509.CreateCertificate(rand.Reader, base, caCert, respKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create delegated cert w/o EKU: %v", err)
	}
	noEKUCert, err := x509.ParseCertificate(noEKUDER)
	if err != nil {
		t.Fatal(err)
	}
	withEKUTmpl := *base
	withEKUTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	withEKUDER, err := x509.CreateCertificate(rand.Reader, &withEKUTmpl, caCert, respKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create delegated cert w/ EKU: %v", err)
	}
	withEKUCert, err := x509.ParseCertificate(withEKUDER)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	mkResp := func(signer crypto.Signer, responderCert, embedded *x509.Certificate) []byte {
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

	// 无 EKU 的普通叶子证书作委派响应者：拒绝，且错误指明 EKU 缺失。
	_, err = ParseOCSPResponseWithIssuer(mkResp(respKey, noEKUCert, noEKUCert), caCert)
	if err == nil {
		t.Fatal("无 OCSPSigning EKU 的委派响应者应被拒绝")
	}
	if !strings.Contains(err.Error(), "lacks id-kp-OCSPSigning EKU") {
		t.Fatalf("错误应指明 OCSPSigning EKU 缺失，got: %v", err)
	}

	// 带 EKU 的委派响应者：通过。
	parsed, err := ParseOCSPResponseWithIssuer(mkResp(respKey, withEKUCert, withEKUCert), caCert)
	if err != nil {
		t.Fatalf("带 OCSPSigning EKU 的委派响应者应通过: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %v, want Good", parsed.Status)
	}

	// issuer-direct（响应者即 issuer，公钥相同）：无需 EKU，通过。
	parsed, err = ParseOCSPResponseWithIssuer(mkResp(caKey, caCert, caCert), caCert)
	if err != nil {
		t.Fatalf("issuer-direct 响应者不应要求 EKU: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %v, want Good", parsed.Status)
	}

	// nil issuer 在入口 fail-closed（非 SM2 响应同样适用）。
	if _, err := ParseOCSPResponseWithIssuer(mkResp(respKey, withEKUCert, withEKUCert), nil); err == nil {
		t.Fatal("nil issuer 应在入口拒绝（fail-closed）")
	}
}

// --- Fix 2：responseExtensions critical 位检查 ---

// buildSM2ResponseWithExts 组装一条携带自选 responseExtensions 的
// BasicOCSPResponse：SM2+SM3 签名 OID（路由进 SM2 解析路径），签名为哑字节。
// 目标检查（responseExtensions critical 位）位于签名验证之前，哑签名足以
// 到达该检查。
func buildSM2ResponseWithExts(t *testing.T, responderCert *x509.Certificate, exts []pkix.Extension) []byte {
	t.Helper()
	sha256OID := oidFromHashAlgorithm(crypto.SHA256)
	basic := extBasicResponse{
		TBSResponseData: extResponseData{
			RawResponderID: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: responderCert.RawSubject},
			ProducedAt:     time.Now().UTC(),
			Responses: []extSingleResponse{{
				CertID: extCertID{
					HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sha256OID, Parameters: asn1.RawValue{Tag: 5}},
					NameHash:      make([]byte, 32),
					IssuerKeyHash: make([]byte, 32),
					SerialNumber:  big.NewInt(42),
				},
				Good:       true,
				ThisUpdate: time.Now().UTC(),
			}},
			ResponseExtensions: exts,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidSignatureSM2WithSM3,
			Parameters: asn1.RawValue{Tag: 5},
		},
		Signature: asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		t.Fatalf("marshal basic response: %v", err)
	}
	respDER, err := asn1.Marshal(extResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: extResponseBytes{ResponseType: idPKIXOCSPBasic, Response: basicDER},
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return respDER
}

// TestParseSM2Response_CriticalResponseExtension 锁定 Fix 2（SM2 路径）：
// 未知 critical 扩展拒绝；未知非 critical 扩展不触发 critical 拒绝；
// nonce 无论 critical 与否均按已知扩展处理。
func TestParseSM2Response_CriticalResponseExtension(t *testing.T) {
	caCert, _ := makeOCSPTestCA(t)
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	// 未知 critical：拒绝，错误点名 critical。
	der := buildSM2ResponseWithExts(t, caCert, []pkix.Extension{{
		Id: unknownOID, Critical: true, Value: []byte{0x04, 0x02, 0x01, 0x02},
	}})
	_, err := ParseOCSPResponseWithIssuer(der, caCert)
	if err == nil {
		t.Fatal("未知 critical responseExtension 应被拒绝")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Fatalf("错误应指明 critical 扩展，got: %v", err)
	}

	// 未知非 critical：不触发 critical 拒绝（后续因哑签名失败）。
	der = buildSM2ResponseWithExts(t, caCert, []pkix.Extension{{
		Id: unknownOID, Critical: false, Value: []byte{0x04, 0x02, 0x01, 0x02},
	}})
	_, err = ParseOCSPResponseWithIssuer(der, caCert)
	if err == nil {
		t.Fatal("哑签名应失败（此处验证非 critical 扩展未被 critical 检查拦截）")
	}
	if strings.Contains(err.Error(), "critical") {
		t.Fatalf("非 critical 扩展不应触发 critical 拒绝，got: %v", err)
	}

	// nonce 标记为 critical：本包已知并处理该扩展，不因 critical 位拒绝
	// （后续因哑签名失败，错误与 critical 无关）。
	der = buildSM2ResponseWithExts(t, caCert, []pkix.Extension{{
		Id: oidExtOCSPNonce, Critical: true, Value: []byte{0x04, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}})
	_, err = ParseOCSPResponseWithIssuer(der, caCert)
	if err == nil {
		t.Fatal("哑签名应失败")
	}
	if strings.Contains(err.Error(), "critical") {
		t.Fatalf("nonce 不应被 critical 位拒绝，got: %v", err)
	}
}

// TestParseStandardResponse_CriticalResponseExtension 锁定 Fix 2（非 SM2
// 路径）：x/crypto 的 ParseResponse 不解析响应级扩展（encoding/asn1 静默
// 忽略尾部未知元素），带未知 critical responseExtensions 的合法签名响应
// 此前可通过；修复后由补检拒绝。已知 nonce 扩展不拒绝。
func TestParseStandardResponse_CriticalResponseExtension(t *testing.T) {
	caKey, caCert := selfSignedECDSACA(t)
	now := time.Now().UTC()
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}

	der, err := CreateOCSPResponseExt(caCert, caCert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(7),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id: unknownOID, Critical: true, Value: []byte{0x05, 0x00},
		}},
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseOCSPResponseWithIssuer(der, caCert)
	if err == nil {
		t.Fatal("非 SM2 响应携带未知 critical responseExtension 应被拒绝")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Fatalf("错误应指明 critical 扩展，got: %v", err)
	}

	// 已知 nonce 扩展（标准位置）：完整签名合法响应应通过。
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	der, err = CreateOCSPResponseExt(caCert, caCert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(7),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Nonce:        nonce,
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOCSPResponseWithIssuer(der, caCert)
	if err != nil {
		t.Fatalf("带 nonce responseExtension 的合法响应应通过: %v", err)
	}
	got, err := ResponseNonce(der)
	if err != nil || !bytes.Equal(got, nonce) {
		t.Fatalf("ResponseNonce = %v, %v; want %v", got, err, nonce)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %v, want Good", parsed.Status)
	}
}

// --- Fix 3：ResponseNonce 重复 nonce 报 malformed ---

// TestResponseNonce_DuplicateRejected 锁定 Fix 3：响应携带两个 nonce 扩展
// 时此前取第一个即返回，第二个静默丢失（取值取决于 DER 顺序，与 RFC 8954
// §2.3 exactly-once 及请求侧「重复即拒」不一致）。修复后重复即 malformed，
// VerifyOCSPResponseNonce 同样拒绝。
func TestResponseNonce_DuplicateRejected(t *testing.T) {
	key, _ := sm2.GenerateKey(rand.Reader)
	cert := makeResponderKey(t, key)
	now := time.Now().UTC()
	nonce := bytes.Repeat([]byte{0xAB}, 16)
	nonceDER, err := asn1.Marshal(nonce)
	if err != nil {
		t.Fatal(err)
	}

	// 主 nonce（p.Nonce 路径）+ ExtraExtensions 复制一份 nonce OID → 重复。
	der, err := CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Nonce:        nonce,
		ExtraExtensions: []pkix.Extension{{
			Id: oidExtOCSPNonce, Value: nonceDER,
		}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResponseNonce(der); err == nil {
		t.Fatal("重复 nonce 扩展应报 malformed")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("错误应指明 nonce 重复，got: %v", err)
	}
	if err := VerifyOCSPResponseNonce(der, nonce); err == nil {
		t.Fatal("重复 nonce 的响应应被 VerifyOCSPResponseNonce 拒绝")
	}

	// 两份 nonce 值不同：同样拒绝（不能按 DER 顺序取「第一个」）。
	otherDER, err := asn1.Marshal(bytes.Repeat([]byte{0xCD}, 16))
	if err != nil {
		t.Fatal(err)
	}
	der, err = CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Nonce:        nonce,
		ExtraExtensions: []pkix.Extension{{
			Id: oidExtOCSPNonce, Value: otherDER,
		}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResponseNonce(der); err == nil {
		t.Fatal("两份不同取值的重复 nonce 应拒绝")
	}

	// 单一 nonce 仍正常提取。
	der, err = CreateOCSPResponseExt(cert, cert, &OCSPResponseParams{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Nonce:        nonce,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResponseNonce(der)
	if err != nil {
		t.Fatalf("单一 nonce 应正常提取: %v", err)
	}
	if !bytes.Equal(got, nonce) {
		t.Fatalf("ResponseNonce = %v, want %v", got, nonce)
	}
}
