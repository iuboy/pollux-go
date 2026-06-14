package tls13gm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/sm3"
)

// --- Key Schedule Tests (keyschedule.go) ---

// TestDeriveEarlySecret tests DeriveEarlySecret with both zero and non-zero IKM.
func TestDeriveEarlySecret(t *testing.T) {
	// No PSK → IKM is all zeros
	early := DeriveEarlySecret(nil)
	if len(early) != sm3.Size {
		t.Fatalf("early secret length: got %d, want %d", len(early), sm3.Size)
	}
	if bytes.Equal(early, make([]byte, sm3.Size)) {
		t.Fatal("early secret is all zeros — derivation may be broken")
	}

	// With explicit IKM
	ikm := bytes.Repeat([]byte{0xAB}, 32)
	early2 := DeriveEarlySecret(ikm)
	if len(early2) != sm3.Size {
		t.Fatalf("early secret length: got %d, want %d", len(early2), sm3.Size)
	}
	if bytes.Equal(early, early2) {
		t.Fatal("different IKM produced same early secret")
	}

	// Determinism
	early3 := DeriveEarlySecret(nil)
	if !bytes.Equal(early, early3) {
		t.Fatal("DeriveEarlySecret not deterministic with nil IKM")
	}
}

// TestDeriveHandshakeSecret tests the handshake secret derivation.
func TestDeriveHandshakeSecret(t *testing.T) {
	earlySecret := DeriveEarlySecret(nil)
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)

	hs, err := DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != sm3.Size {
		t.Fatalf("handshake secret length: got %d, want %d", len(hs), sm3.Size)
	}
	if bytes.Equal(hs, make([]byte, sm3.Size)) {
		t.Fatal("handshake secret is all zeros")
	}

	// Determinism
	hs2, err := DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hs, hs2) {
		t.Fatal("DeriveHandshakeSecret not deterministic")
	}

	// Different shared secret → different handshake secret
	sharedSecret2 := bytes.Repeat([]byte{0x43}, 32)
	hs3, err := DeriveHandshakeSecret(earlySecret, sharedSecret2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hs, hs3) {
		t.Fatal("different shared secrets produced same handshake secret")
	}
}

// TestDeriveMasterSecret tests the master secret derivation.
func TestDeriveMasterSecret(t *testing.T) {
	earlySecret := DeriveEarlySecret(nil)
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)

	hs, err := DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}

	ms, err := DeriveMasterSecret(hs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != sm3.Size {
		t.Fatalf("master secret length: got %d, want %d", len(ms), sm3.Size)
	}
	if bytes.Equal(ms, make([]byte, sm3.Size)) {
		t.Fatal("master secret is all zeros")
	}

	// Determinism
	ms2, err := DeriveMasterSecret(hs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ms, ms2) {
		t.Fatal("DeriveMasterSecret not deterministic")
	}
}

// TestDeriveTrafficKeys tests key and IV derivation from a traffic secret.
func TestDeriveTrafficKeys(t *testing.T) {
	trafficSecret := bytes.Repeat([]byte{0x55}, 32)

	// SM4-GCM: key=16, IV=12
	keys, err := DeriveTrafficKeys(trafficSecret, 16, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Key) != 16 {
		t.Fatalf("key length: got %d, want 16", len(keys.Key))
	}
	if len(keys.IV) != 12 {
		t.Fatalf("IV length: got %d, want 12", len(keys.IV))
	}
	if bytes.Equal(keys.Key, make([]byte, 16)) {
		t.Fatal("derived key is all zeros")
	}

	// Determinism
	keys2, err := DeriveTrafficKeys(trafficSecret, 16, 12)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.Key, keys2.Key) {
		t.Fatal("key not deterministic")
	}
	if !bytes.Equal(keys.IV, keys2.IV) {
		t.Fatal("IV not deterministic")
	}
}

// TestDeriveFinishedKey tests the finished key derivation.
func TestDeriveFinishedKey(t *testing.T) {
	trafficSecret := bytes.Repeat([]byte{0x55}, 32)

	fk, err := DeriveFinishedKey(trafficSecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(fk) != sm3.Size {
		t.Fatalf("finished key length: got %d, want %d", len(fk), sm3.Size)
	}

	// Determinism
	fk2, err := DeriveFinishedKey(trafficSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fk, fk2) {
		t.Fatal("finished key not deterministic")
	}
}

// TestComputeFinishedVerifyData tests verify_data computation using HMAC-SM3.
func TestComputeFinishedVerifyData(t *testing.T) {
	finishedKey := bytes.Repeat([]byte{0xAA}, 32)
	transcriptHash := bytes.Repeat([]byte{0xBB}, 32)

	verifyData, err := ComputeFinishedVerifyData(finishedKey, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifyData) != sm3.Size {
		t.Fatalf("verify_data length: got %d, want %d", len(verifyData), sm3.Size)
	}

	// Determinism
	verifyData2, err := ComputeFinishedVerifyData(finishedKey, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifyData, verifyData2) {
		t.Fatal("verify_data not deterministic")
	}

	// Different transcript hash → different verify_data
	transcriptHash2 := bytes.Repeat([]byte{0xCC}, 32)
	verifyData3, err := ComputeFinishedVerifyData(finishedKey, transcriptHash2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(verifyData, verifyData3) {
		t.Fatal("different transcript produced same verify_data")
	}

	// Empty finished key should fail
	_, err = ComputeFinishedVerifyData(nil, transcriptHash)
	if err == nil {
		t.Fatal("expected error for empty finished key, got nil")
	}

	// Manually compute HMAC-SM3 to cross-verify
	mac := sm3.NewHMAC(finishedKey)
	mac.Write(transcriptHash)
	expected := mac.Sum(nil)
	if !bytes.Equal(verifyData, expected) {
		t.Fatalf("verify_data mismatch with manual HMAC-SM3:\n  got  %x\n  want %x", verifyData, expected)
	}
}

// TestDeriveResumptionPSK tests PSK derivation from resumption master secret.
func TestDeriveResumptionPSK(t *testing.T) {
	resMasterSecret := bytes.Repeat([]byte{0xDD}, 32)
	ticketNonce := []byte("ticket-nonce-12345")

	psk, err := DeriveResumptionPSK(resMasterSecret, ticketNonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(psk) != sm3.Size {
		t.Fatalf("PSK length: got %d, want %d", len(psk), sm3.Size)
	}

	// Different nonce → different PSK
	psk2, err := DeriveResumptionPSK(resMasterSecret, []byte("different-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(psk, psk2) {
		t.Fatal("different nonces produced same PSK")
	}
}

// TestDeriveResumptionMasterSecret tests resumption master secret derivation.
func TestDeriveResumptionMasterSecret(t *testing.T) {
	// Full chain: early → handshake → master → resumption master
	earlySecret := DeriveEarlySecret(nil)
	hs, err := DeriveHandshakeSecret(earlySecret, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := DeriveMasterSecret(hs)
	if err != nil {
		t.Fatal(err)
	}

	transcriptHash := sm3.Sum([]byte("handshake transcript"))
	resMaster, err := DeriveResumptionMasterSecret(ms, transcriptHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(resMaster) != sm3.Size {
		t.Fatalf("resumption master length: got %d, want %d", len(resMaster), sm3.Size)
	}
}

// TestDeriveExporterMasterSecret tests exporter master secret derivation.
func TestDeriveExporterMasterSecret(t *testing.T) {
	earlySecret := DeriveEarlySecret(nil)
	hs, err := DeriveHandshakeSecret(earlySecret, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := DeriveMasterSecret(hs)
	if err != nil {
		t.Fatal(err)
	}

	transcriptHash := sm3.Sum([]byte("full transcript"))
	expMaster, err := DeriveExporterMasterSecret(ms, transcriptHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(expMaster) != sm3.Size {
		t.Fatalf("exporter master length: got %d, want %d", len(expMaster), sm3.Size)
	}
}

// --- Key Exchange Tests (keyexchange.go) ---

// TestGenerateCurveSM2KeyPair tests SM2 key pair generation.
func TestGenerateCurveSM2KeyPair(t *testing.T) {
	key, err := GenerateCurveSM2KeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if key.D == nil {
		t.Fatal("private key D is nil")
	}
	if key.PublicKey.X == nil || key.PublicKey.Y == nil {
		t.Fatal("public key point is nil")
	}

	// Generate with explicit reader
	key2, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Two generated keys must be different
	if key.D.Cmp(key2.D) == 0 {
		t.Fatal("two generated keys have the same private scalar (astronomically unlikely)")
	}
}

// TestCurveSM2ECDHE tests ECDH shared secret computation.
func TestCurveSM2ECDHE(t *testing.T) {
	// Generate two key pairs
	aliceKey, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Alice computes shared secret using her private key and Bob's public key
	aliceShared, err := CurveSM2ECDHE(aliceKey, &bobKey.PublicKey)
	if err != nil {
		t.Fatalf("Alice ECDHE: %v", err)
	}
	if len(aliceShared) != 32 {
		t.Fatalf("shared secret length: got %d, want 32", len(aliceShared))
	}

	// Bob computes shared secret using his private key and Alice's public key
	bobShared, err := CurveSM2ECDHE(bobKey, &aliceKey.PublicKey)
	if err != nil {
		t.Fatalf("Bob ECDHE: %v", err)
	}

	// Both must derive the same shared secret
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatalf("ECDH shared secrets don't match:\n  alice: %x\n  bob:   %x", aliceShared, bobShared)
	}

	// Nil private key
	_, err = CurveSM2ECDHE(nil, &bobKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for nil privateKey, got nil")
	}

	// Nil peer public key
	_, err = CurveSM2ECDHE(aliceKey, nil)
	if err == nil {
		t.Fatal("expected error for nil peerPublic, got nil")
	}
}

// TestCurveSM2Constants verifies the exported constants.
func TestCurveSM2Constants(t *testing.T) {
	if CurveSM2 != 0x0029 {
		t.Fatalf("CurveSM2: got 0x%04x, want 0x0029", CurveSM2)
	}
	if CurveSM2KeySize != 65 {
		t.Fatalf("CurveSM2KeySize: got %d, want 65", CurveSM2KeySize)
	}
}

// --- Signature Tests (signature.go) ---

// TestSignatureConstants verifies exported constants.
func TestSignatureConstants(t *testing.T) {
	if ServerCertificateVerifyContext != "TLS 1.3, server CertificateVerify" {
		t.Fatalf("ServerCertificateVerifyContext: got %q", ServerCertificateVerifyContext)
	}
	if ClientCertificateVerifyContext != "TLS 1.3, client CertificateVerify" {
		t.Fatalf("ClientCertificateVerifyContext: got %q", ClientCertificateVerifyContext)
	}
	if SM2IDTLS13KeyExchange != "TLSv1.3+GM+Cipher+Suite" {
		t.Fatalf("SM2IDTLS13KeyExchange: got %q", SM2IDTLS13KeyExchange)
	}
	if SM2IDCertificateVerify != "1234567812345678" {
		t.Fatalf("SM2IDCertificateVerify: got %q", SM2IDCertificateVerify)
	}
}

// TestBuildCertificateVerifyInput tests the CertificateVerify content construction.
func TestBuildCertificateVerifyInput(t *testing.T) {
	context := ServerCertificateVerifyContext
	transcript := []byte("handshake messages")
	transcriptHash := sm3.Sum(transcript)

	// BuildCertificateVerifyInput takes the transcript HASH, not raw bytes.
	input := BuildCertificateVerifyInput(context, transcriptHash[:])

	// Must start with 64 spaces (0x20)
	if len(input) != 64+len(context)+1+sm3.Size {
		t.Fatalf("input length: got %d, want %d", len(input), 64+len(context)+1+sm3.Size)
	}
	for i := range 64 {
		if input[i] != 0x20 {
			t.Fatalf("padding byte %d: got 0x%02x, want 0x20", i, input[i])
		}
	}

	// Context string follows padding
	contextStart := 64
	contextEnd := contextStart + len(context)
	if string(input[contextStart:contextEnd]) != context {
		t.Fatalf("context string: got %q, want %q", input[contextStart:contextEnd], context)
	}

	// Separator byte
	if input[contextEnd] != 0x00 {
		t.Fatalf("separator: got 0x%02x, want 0x00", input[contextEnd])
	}

	// SM3(transcript) follows
	hashStart := contextEnd + 1
	if !bytes.Equal(input[hashStart:], transcriptHash[:]) {
		t.Fatalf("transcript hash mismatch")
	}
}

// TestSignAndVerifyCertificateVerify tests the full CertificateVerify sign/verify flow.
func TestSignAndVerifyCertificateVerify(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	context := ServerCertificateVerifyContext
	transcript := []byte("ClientHello...ServerHello...Certificate...")

	sig, err := SignCertificateVerify(key, context, transcript)
	if err != nil {
		t.Fatalf("SignCertificateVerify: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with correct params
	if !VerifyCertificateVerify(&key.PublicKey, context, transcript, sig) {
		t.Fatal("VerifyCertificateVerify failed for valid signature")
	}

	// Wrong context must fail
	if VerifyCertificateVerify(&key.PublicKey, ClientCertificateVerifyContext, transcript, sig) {
		t.Fatal("VerifyCertificateVerify succeeded with wrong context")
	}

	// Wrong transcript must fail
	if VerifyCertificateVerify(&key.PublicKey, context, []byte("wrong"), sig) {
		t.Fatal("VerifyCertificateVerify succeeded with wrong transcript")
	}

	// Tampered signature must fail
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0x01
	if VerifyCertificateVerify(&key.PublicKey, context, transcript, tamperedSig) {
		t.Fatal("VerifyCertificateVerify succeeded with tampered signature")
	}

	// Nil public key
	if VerifyCertificateVerify(nil, context, transcript, sig) {
		t.Fatal("VerifyCertificateVerify succeeded with nil public key")
	}

	// Nil private key
	_, err = SignCertificateVerify(nil, context, transcript)
	if err == nil {
		t.Fatal("expected error for nil privateKey, got nil")
	}
}

// TestSignAndVerifySM2SM3 tests the generic SM2-SM3 sign/verify functions.
func TestSignAndVerifySM2SM3(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message for SM2-SM3")

	sig, err := SignSM2SM3(key, message)
	if err != nil {
		t.Fatalf("SignSM2SM3: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with correct message
	if !VerifySM2SM3(&key.PublicKey, message, sig) {
		t.Fatal("VerifySM2SM3 failed for valid signature")
	}

	// Wrong message must fail
	if VerifySM2SM3(&key.PublicKey, []byte("wrong message"), sig) {
		t.Fatal("VerifySM2SM3 succeeded with wrong message")
	}

	// Nil private key
	_, err = SignSM2SM3(nil, message)
	if err == nil {
		t.Fatal("expected error for nil privateKey, got nil")
	}

	// Nil public key
	if VerifySM2SM3(nil, message, sig) {
		t.Fatal("VerifySM2SM3 succeeded with nil public key")
	}
}

// TestSM2SignatureWithRFC8998Identifier verifies that the signature uses the
// correct SM2 identifier "TLSv1.3+GM+Cipher+Suite" per RFC 8998 §3.2.1.
// A signature made via SignSM2SM3 must be verifiable with sm2.VerifyWithSM2
// using the same identifier.
func TestSM2SignatureWithRFC8998Identifier(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("RFC 8998 compliance test")
	sig, err := SignSM2SM3(key, message)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the explicit SM2 identifier via sm2.VerifyWithSM2
	if !sm2.VerifyWithSM2(&key.PublicKey, []byte(SM2IDTLS13KeyExchange), message, sig) {
		t.Fatal("signature not verifiable with RFC 8998 identifier via VerifyWithSM2")
	}
}

// TestCertificateVerifyCrossVerify verifies that CertificateVerify signatures
// made with SignCertificateVerify are verifiable with sm2.VerifyWithSM2
// using the RFC 8998 identifier.
func TestCertificateVerifyCrossVerify(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	context := ServerCertificateVerifyContext
	transcript := []byte("cross-verify transcript")

	sig, err := SignCertificateVerify(key, context, transcript)
	if err != nil {
		t.Fatal(err)
	}

	// Reconstruct the message that SignCertificateVerify signed
	message := BuildCertificateVerifyInput(context, transcript)

	// Verify using sm2.VerifyWithSM2 with the RFC 8998 identifier
	if !sm2.VerifyWithSM2(&key.PublicKey, []byte(SM2IDTLS13KeyExchange), message, sig) {
		t.Fatal("CertificateVerify signature not verifiable via sm2.VerifyWithSM2")
	}
}

// --- Integration: Full Key Schedule + Finished ---

// TestFullKeyScheduleWithFinished tests the complete key schedule chain
// from early secret through finished verify_data, using the high-level API.
func TestFullKeyScheduleWithFinished(t *testing.T) {
	// Simulate a TLS 1.3 handshake with SM3

	// 1. Early Secret (no PSK)
	earlySecret := DeriveEarlySecret(nil)

	// 2. Handshake Secret (with simulated ECDHE shared secret)
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	handshakeSecret, err := DeriveHandshakeSecret(earlySecret, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Server handshake traffic keys
	serverHSTraffic, err := DeriveSecret(handshakeSecret, LabelServerHSTraffic, []byte("ClientHello...ServerHello"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveTrafficKeys(serverHSTraffic, 16, 12)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Finished key and verify_data
	finishedKey, err := DeriveFinishedKey(serverHSTraffic)
	if err != nil {
		t.Fatal(err)
	}
	transcriptHash := sm3.Sum([]byte("ClientHello...ServerHello...EncryptedExtensions...Certificate"))
	verifyData, err := ComputeFinishedVerifyData(finishedKey, transcriptHash[:])
	if err != nil {
		t.Fatal(err)
	}

	// 5. Master Secret
	masterSecret, err := DeriveMasterSecret(handshakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	// 6. Application traffic keys
	clientAPTraffic, err := DeriveSecret(masterSecret, LabelClientAPTraffic, []byte("full handshake"))
	if err != nil {
		t.Fatal(err)
	}
	appKeys, err := DeriveTrafficKeys(clientAPTraffic, 16, 12)
	if err != nil {
		t.Fatal(err)
	}

	// Basic sanity: all derived values should be non-trivial
	if bytes.Equal(verifyData, make([]byte, sm3.Size)) {
		t.Fatal("verify_data is all zeros")
	}
	if bytes.Equal(keys.Key, make([]byte, 16)) {
		t.Fatal("handshake key is all zeros")
	}
	if bytes.Equal(appKeys.Key, make([]byte, 16)) {
		t.Fatal("app key is all zeros")
	}
	if bytes.Equal(keys.Key, appKeys.Key) {
		t.Fatal("handshake key and app key are identical")
	}

	_ = masterSecret // used above for derivation
}

// TestECDHEKeyExchangeIntegration tests ECDHE + key schedule integration.
func TestECDHEKeyExchangeIntegration(t *testing.T) {
	// Generate SM2 key pairs for client and server
	clientKey, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Compute shared secrets
	clientShared, err := CurveSM2ECDHE(clientKey, &serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := CurveSM2ECDHE(serverKey, &clientKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Both sides derive the same handshake secret
	earlySecret := DeriveEarlySecret(nil)

	clientHS, err := DeriveHandshakeSecret(earlySecret, clientShared)
	if err != nil {
		t.Fatal(err)
	}
	serverHS, err := DeriveHandshakeSecret(earlySecret, serverShared)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientHS, serverHS) {
		t.Fatalf("handshake secrets don't match:\n  client: %x\n  server: %x", clientHS, serverHS)
	}

	// Derive finished verify data — both sides should compute the same value
	fk, err := DeriveFinishedKey(clientHS)
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("ClientHello...ServerHello")
	th := sm3.Sum(transcript)

	clientVerify, err := ComputeFinishedVerifyData(fk, th[:])
	if err != nil {
		t.Fatal(err)
	}
	serverVerify, err := ComputeFinishedVerifyData(fk, th[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientVerify, serverVerify) {
		t.Fatal("client and server verify_data don't match")
	}
}

// TestPublicKeyTypeCompatibility verifies that sm2.PrivateKey.PublicKey
// can be used as *ecdsa.PublicKey for CurveSM2ECDHE input.
func TestPublicKeyTypeCompatibility(t *testing.T) {
	key, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// sm2.PrivateKey embeds ecdsa.PrivateKey, so &key.PublicKey is *ecdsa.PublicKey.
	// Curve must be the SM2 curve (not nil).
	if key.PublicKey.Curve == nil {
		t.Fatal("curve is nil")
	}

	// Verify ECDHE works with the type-asserted public key
	_, err = CurveSM2ECDHE(key, &key.PublicKey)
	if err != nil {
		t.Fatalf("CurveSM2ECDHE with &key.PublicKey: %v", err)
	}
}

// --- Additional Review-Driven Tests ---

// TestNewAEADInvalidKey verifies that NewAEAD rejects invalid key lengths.
func TestNewAEADInvalidKey(t *testing.T) {
	nonce := make([]byte, 12)

	for _, keyLen := range []int{0, 8, 15, 17, 32} {
		_, err := NewAEAD(make([]byte, keyLen), nonce)
		if err == nil {
			t.Errorf("expected error for %d-byte key, got nil", keyLen)
		}
	}

	// Valid 16-byte key should succeed
	key := make([]byte, 16)
	_, err := NewAEAD(key, nonce)
	if err != nil {
		t.Fatalf("unexpected error for valid 16-byte key: %v", err)
	}
}

// TestBuildHKDFLabelRejectsOversized verifies that buildHKDFLabel returns an
// error on oversized inputs (label/context must each fit in a single length byte).
func TestBuildHKDFLabelRejectsOversized(t *testing.T) {
	t.Run("label_too_long", func(t *testing.T) {
		// "tls13 " (6 bytes) + 250 "a"s = 256 bytes > 255
		longLabel := string(bytes.Repeat([]byte("a"), 250))
		if _, err := buildHKDFLabel(longLabel, nil, 32); err == nil {
			t.Fatal("expected error for label > 255 bytes, got none")
		}
	})

	t.Run("context_too_long", func(t *testing.T) {
		longContext := bytes.Repeat([]byte("x"), 256)
		if _, err := buildHKDFLabel("key", longContext, 32); err == nil {
			t.Fatal("expected error for context > 255 bytes, got none")
		}
	})
}

// TestHKDFExpandLabelBoundaryLengths tests edge cases for the length parameter.
func TestHKDFExpandLabelBoundaryLengths(t *testing.T) {
	secret := make([]byte, 32)

	// Minimum valid length
	out, err := HKDFExpandLabel(secret, "key", nil, 1)
	if err != nil {
		t.Fatalf("length=1: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("length=1: got %d bytes", len(out))
	}

	// Regression test: 255 was the old limit, must still work
	out, err = HKDFExpandLabel(secret, "key", nil, 255)
	if err != nil {
		t.Fatalf("length=255: %v", err)
	}
	if len(out) != 255 {
		t.Fatalf("length=255: got %d bytes", len(out))
	}

	// Length exceeding HKDF-Expand maximum (255 * 32 = 8160)
	_, err = HKDFExpandLabel(secret, "key", nil, 8161)
	if err == nil {
		t.Fatal("expected error for length=8161 (exceeds 255*32), got nil")
	}
}

// TestCurveSM2ECDHEOffCurvePoint verifies that ECDHE rejects a public key
// that is not on the SM2 curve.
func TestCurveSM2ECDHEOffCurvePoint(t *testing.T) {
	key, err := GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a public key with coordinates that are NOT on the curve.
	// Use (1, 1) which is extremely unlikely to be on SM2.
	fakePub := &ecdsa.PublicKey{
		Curve: key.PublicKey.Curve,
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}

	_, err = CurveSM2ECDHE(key, fakePub)
	if err == nil {
		t.Fatal("expected error for off-curve public key, got nil")
	}
}

// TestDeriveTrafficKeysInvalidParams verifies DeriveTrafficKeys with edge cases.
func TestDeriveTrafficKeysInvalidParams(t *testing.T) {
	secret := make([]byte, 32)

	// Zero-length key should fail (HKDFExpandLabel rejects length <= 0)
	_, err := DeriveTrafficKeys(secret, 0, 12)
	if err == nil {
		t.Fatal("expected error for keyLen=0, got nil")
	}

	// Negative length should fail
	_, err = DeriveTrafficKeys(secret, -1, 12)
	if err == nil {
		t.Fatal("expected error for keyLen=-1, got nil")
	}
}

// TestNewCCMAEADInvalidKey verifies that NewCCMAEAD rejects invalid key lengths.
func TestNewCCMAEADInvalidKey(t *testing.T) {
	nonce := make([]byte, 12)

	for _, keyLen := range []int{0, 8, 15, 17, 32} {
		_, err := NewCCMAEAD(make([]byte, keyLen), nonce)
		if err == nil {
			t.Errorf("expected error for %d-byte CCM key, got nil", keyLen)
		}
	}
}
