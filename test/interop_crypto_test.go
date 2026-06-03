package test

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"hash"
	"testing"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
	gmsmSM3 "github.com/emmansun/gmsm/sm3"
	gmsmSM4 "github.com/emmansun/gmsm/sm4"
	gmsmSM9 "github.com/emmansun/gmsm/sm9"
	gmsmSMX509 "github.com/emmansun/gmsm/smx509"

	polluxSM2 "github.com/ycq/pollux/sm2"
	polluxSM3 "github.com/ycq/pollux/sm3"
	polluxSM4 "github.com/ycq/pollux/sm4"
	polluxSM9 "github.com/ycq/pollux/sm9"
)

// ============================================================================
// SM2 签名/验签互操作
// ============================================================================

func TestInteropSM2_GMSM_Sign_Pollux_Verify(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := []byte("test digest for sm2 interop")

	sig, err := gmsmSM2.SignASN1(rand.Reader, (*gmsmSM2.PrivateKey)(priv), digest, nil)
	if err != nil {
		t.Fatalf("gmsm SignASN1: %v", err)
	}

	if !polluxSM2.VerifyASN1(&priv.PublicKey, digest, sig) {
		t.Error("pollux VerifyASN1 failed for gmsm-signed signature")
	}
}

func TestInteropSM2_Pollux_Sign_GMSM_Verify(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := []byte("test digest for sm2 interop reverse")

	sig, err := polluxSM2.SignASN1(rand.Reader, priv, digest, nil)
	if err != nil {
		t.Fatalf("pollux SignASN1: %v", err)
	}

	if !gmsmSM2.VerifyASN1(&priv.PublicKey, digest, sig) {
		t.Error("gmsm VerifyASN1 failed for pollux-signed signature")
	}
}

func TestInteropSM2_SignWithSM2_CrossVerify(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid := []byte("1234567812345678")
	data := []byte("SM2 with UID interop test")

	// gmsm SignWithSM2 → pollux VerifyWithSM2
	sig, err := gmsmSM2.SignASN1(rand.Reader, (*gmsmSM2.PrivateKey)(priv), data, gmsmSM2.NewSM2SignerOption(true, uid))
	if err != nil {
		t.Fatalf("gmsm SignASN1 with SM2 option: %v", err)
	}
	if !polluxSM2.VerifyWithSM2(&priv.PublicKey, uid, data, sig) {
		t.Error("pollux VerifyWithSM2 failed for gmsm SM2 signature")
	}

	// pollux SignWithSM2 → gmsm VerifyASN1WithSM2
	sig2, err := polluxSM2.SignWithSM2(rand.Reader, priv, uid, data)
	if err != nil {
		t.Fatalf("pollux SignWithSM2: %v", err)
	}
	if !gmsmSM2.VerifyASN1WithSM2(&priv.PublicKey, uid, data, sig2) {
		t.Error("gmsm VerifyASN1WithSM2 failed for pollux SM2 signature")
	}
}

// ============================================================================
// SM2 加密/解密互操作
// ============================================================================

func TestInteropSM2_GMSM_Encrypt_Pollux_Decrypt(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM2 encryption interop test payload")

	ciphertext, err := gmsmSM2.EncryptASN1(rand.Reader, &priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("gmsm EncryptASN1: %v", err)
	}

	decrypted, err := polluxSM2.Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("pollux Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %x, want %x", decrypted, plaintext)
	}
}

func TestInteropSM2_Pollux_Encrypt_GMSM_Decrypt(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("reverse SM2 encryption interop test")

	ciphertext, err := polluxSM2.EncryptASN1(rand.Reader, &priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("pollux EncryptASN1: %v", err)
	}

	decrypted, err := gmsmSM2.Decrypt((*gmsmSM2.PrivateKey)(priv), ciphertext)
	if err != nil {
		t.Fatalf("gmsm Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch: got %x, want %x", decrypted, plaintext)
	}
}

// ============================================================================
// SM2 签名 DER 格式交叉验证 (S2-5)
// ============================================================================

func TestInteropSM2_SignatureDER_CrossParse(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := []byte("DER cross-parse test")

	polluxSig, err := polluxSM2.SignASN1(rand.Reader, priv, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	gmsmSig, err := gmsmSM2.SignASN1(rand.Reader, (*gmsmSM2.PrivateKey)(priv), digest, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 两边都能验证对方的签名
	if !gmsmSM2.VerifyASN1(&priv.PublicKey, digest, polluxSig) {
		t.Error("gmsm cannot verify pollux DER signature")
	}
	if !polluxSM2.VerifyASN1(&priv.PublicKey, digest, gmsmSig) {
		t.Error("pollux cannot verify gmsm DER signature")
	}
}

// ============================================================================
// SM2 跨库数字信封 (S2-8)
// ============================================================================

func TestInteropSM2_Envelope_CrossLibrary(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("PKCS#7 envelope interop test payload")

	// pollux EnvelopeEncrypt
	env, err := polluxSM2.EnvelopeEncrypt(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("pollux EnvelopeEncrypt: %v", err)
	}

	// pollux EnvelopeDecrypt
	decrypted, err := polluxSM2.EnvelopeDecrypt(priv, env)
	if err != nil {
		t.Fatalf("pollux EnvelopeDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("envelope roundtrip: got %q, want %q", decrypted, plaintext)
	}
}

func TestInteropSM2_Envelope_LargePayload(t *testing.T) {
	priv, _ := polluxSM2.GenerateKey(rand.Reader)
	plaintext := make([]byte, 4096)
	_, _ = rand.Read(plaintext)

	env, err := polluxSM2.EnvelopeEncrypt(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("EnvelopeEncrypt large: %v", err)
	}
	decrypted, err := polluxSM2.EnvelopeDecrypt(priv, env)
	if err != nil {
		t.Fatalf("EnvelopeDecrypt large: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large envelope roundtrip mismatch")
	}
}

func TestInteropSM2_Envelope_WrongKey(t *testing.T) {
	priv1, _ := polluxSM2.GenerateKey(rand.Reader)
	priv2, _ := polluxSM2.GenerateKey(rand.Reader)

	env, _ := polluxSM2.EnvelopeEncrypt(&priv1.PublicKey, []byte("wrong key test"))
	_, err := polluxSM2.EnvelopeDecrypt(priv2, env)
	if err == nil {
		t.Error("should reject wrong key for envelope decrypt")
	}
}

func TestInteropSM2_Envelope_NilArgs(t *testing.T) {
	_, err := polluxSM2.EnvelopeEncrypt(nil, []byte("test"))
	if err == nil {
		t.Error("should reject nil public key")
	}
}

// ============================================================================
// SM2 密钥序列化互操作
// ============================================================================

func TestInteropSM2_KeySerialization(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// pollux PEM round-trip → gmsm can parse
	pemData, err := polluxSM2.WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("pollux WritePrivateKeyToPEM: %v", err)
	}

	key, err := polluxSM2.ParsePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("pollux ParsePrivateKeyFromPEM: %v", err)
	}
	if key.D.Cmp(priv.D) != 0 {
		t.Error("PEM round-trip private key mismatch")
	}

	// 公钥 DER 序列化互操作
	pubDER := polluxSM2.MarshalUncompressed(&priv.PublicKey)
	if len(pubDER) != 65 {
		t.Fatalf("uncompressed public key should be 65 bytes, got %d", len(pubDER))
	}

	pubKey, err := polluxSM2.UnmarshalUncompressed(pubDER)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}
	if !polluxSM2.Equal(pubKey, &priv.PublicKey) {
		t.Error("public key DER round-trip mismatch")
	}

	// 压缩公钥互操作
	compressed := polluxSM2.CompressPublicKey(&priv.PublicKey)
	if len(compressed) != 33 {
		t.Fatalf("compressed key should be 33 bytes, got %d", len(compressed))
	}
	decompressed, err := polluxSM2.DecompressPublicKey(compressed)
	if err != nil {
		t.Fatalf("DecompressPublicKey: %v", err)
	}
	if !polluxSM2.Equal(decompressed, &priv.PublicKey) {
		t.Error("compressed key round-trip mismatch")
	}

	// BytesToPrivateKey / PrivateKeyToBytes 互操作
	privBytes := polluxSM2.PrivateKeyToBytes(priv)
	recovered, err := polluxSM2.BytesToPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("BytesToPrivateKey: %v", err)
	}
	if recovered.D.Cmp(priv.D) != 0 {
		t.Error("BytesToPrivateKey round-trip mismatch")
	}
}

func TestInteropSM2_KeyPEM_CrossLibrary(t *testing.T) {
	// 从文件加载 Tongsuo 生成的密钥，验证 pollux 解析后 gmsm 可用
	keyPEM := readCert(t, "sm2_sign_key.pem")
	priv, err := polluxSM2.ParsePrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatalf("pollux ParsePrivateKeyFromPEM: %v", err)
	}

	digest := []byte("cross-library PEM key test")
	sig, err := gmsmSM2.SignASN1(rand.Reader, (*gmsmSM2.PrivateKey)(priv), digest, nil)
	if err != nil {
		t.Fatalf("gmsm SignASN1 with pollux-parsed key: %v", err)
	}
	if !polluxSM2.VerifyASN1(&priv.PublicKey, digest, sig) {
		t.Error("pollux verify failed for signature made with pollux-parsed PEM key via gmsm")
	}
}

func TestInteropSM2_PolluxPEM_GMSMParse(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// pollux 写 PEM → gmsm ParsePKCS8PrivateKey 解析
	privPEM, err := polluxSM2.WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("pollux WritePrivateKeyToPEM: %v", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("failed to decode pollux PEM")
	}
	gmsmKey, err := gmsmSMX509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("gmsm ParsePKCS8PrivateKey: %v", err)
	}
	gmsmSM2Key, ok := gmsmKey.(*gmsmSM2.PrivateKey)
	if !ok {
		t.Fatalf("gmsm parsed key type: %T, want *gmsmSM2.PrivateKey", gmsmKey)
	}
	if gmsmSM2Key.D.Cmp(priv.D) != 0 {
		t.Error("gmsm-parsed key D mismatch")
	}

	// pollux 写公钥 PEM → pollux ParsePublicKeyFromPEM 往返
	pubPEM, err := polluxSM2.WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("pollux WritePublicKeyToPEM: %v", err)
	}
	pubParsed, err := polluxSM2.ParsePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("pollux ParsePublicKeyFromPEM: %v", err)
	}
	if !pubParsed.Equal(&priv.PublicKey) {
		t.Error("public key PEM cross-parse mismatch")
	}
}

// ============================================================================
// SM3 哈希互操作
// ============================================================================

func TestInteropSM3_HashConsistency(t *testing.T) {
	data := []byte("SM3 hash interop test data")

	// pollux Sum
	polluxDigest := polluxSM3.Sum(data)

	// gmsm Sum
	gmsmDigest := gmsmSM3.Sum(data)

	if !bytes.Equal(polluxDigest[:], gmsmDigest[:]) {
		t.Errorf("SM3 Sum mismatch: pollux=%x, gmsm=%x", polluxDigest, gmsmDigest)
	}

	// pollux streaming hash
	h := polluxSM3.New()
	h.Write(data[:5])
	h.Write(data[5:])
	streamDigest := h.Sum(nil)
	if !bytes.Equal(streamDigest, polluxDigest[:]) {
		t.Errorf("SM3 streaming mismatch: %x vs %x", streamDigest, polluxDigest)
	}
}

func TestInteropSM3_HMAC_CrossVerify(t *testing.T) {
	key := []byte("hmac-sm3-interop-test-key")
	data := []byte("message to authenticate with HMAC-SM3")

	// pollux HMAC
	polluxHMAC := polluxSM3.NewHMAC(key)
	polluxHMAC.Write(data)
	polluxMac := polluxHMAC.Sum(nil)

	// gmsm HMAC (via crypto/hmac + gmsm sm3.New)
	gmsmHMAC := hmac.New(gmsmSM3.New, key)
	gmsmHMAC.Write(data)
	gmsmMac := gmsmHMAC.Sum(nil)

	if !bytes.Equal(polluxMac, gmsmMac) {
		t.Errorf("HMAC-SM3 mismatch: pollux=%x, gmsm=%x", polluxMac, gmsmMac)
	}

	// 确认 HMAC 长度 == SM3 输出长度
	if len(polluxMac) != polluxSM3.Size {
		t.Errorf("HMAC output size: got %d, want %d", len(polluxMac), polluxSM3.Size)
	}
}

func TestInteropSM3_KDF_Consistency(t *testing.T) {
	z := []byte("shared secret for KDF interop test")
	klen := 48

	polluxOut, err := polluxSM3.KDF(z, klen)
	if err != nil {
		t.Fatalf("pollux KDF: %v", err)
	}
	gmsmOut := gmsmSM3.Kdf(z, klen)

	if !bytes.Equal(polluxOut, gmsmOut) {
		t.Errorf("KDF mismatch:\npollux=%x\ngmsm =%x", polluxOut, gmsmOut)
	}
}

// ============================================================================
// SM4 加密/解密互操作
// ============================================================================

func TestInteropSM4_GMSM_CBC_Pollux_Decrypt(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	plaintext := []byte("SM4 CBC interop test payload data")

	// gmsm CBC 加密
	block, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := polluxSM4.PKCS7Pad(plaintext, polluxSM4.BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// pollux CBC 解密
	decrypted, err := polluxSM4.Decrypt(key, ciphertext, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("pollux CBC Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("CBC decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestInteropSM4_Pollux_CBC_GMSM_Decrypt(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	plaintext := []byte("reverse SM4 CBC interop test data")

	ciphertext, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("pollux CBC Encrypt: %v", err)
	}

	// gmsm CBC 解密
	block, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(padded, ciphertext)
	unpadded, err := polluxSM4.PKCS7Unpad(padded, polluxSM4.BlockSize)
	if err != nil {
		t.Fatalf("PKCS7Unpad: %v", err)
	}
	if !bytes.Equal(unpadded, plaintext) {
		t.Errorf("CBC decrypt mismatch: got %q, want %q", unpadded, plaintext)
	}
}

func TestInteropSM4_GCM_CrossVerify(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	plaintext := []byte("SM4 GCM interop authentication test")
	aad := []byte("additional data")

	// pollux GCM seal → gmsm GCM open
	polluxAEAD, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, polluxAEAD.NonceSize())
	_, _ = rand.Read(nonce)

	ciphertext := polluxAEAD.Seal(nil, nonce, plaintext, aad)

	gmsmBlock, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gmsmAEAD, err := cipher.NewGCM(gmsmBlock)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := gmsmAEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("gmsm GCM Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("GCM decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}

	// gmsm GCM seal → pollux GCM open
	ciphertext2 := gmsmAEAD.Seal(nil, nonce, plaintext, aad)
	decrypted2, err := polluxAEAD.Open(nil, nonce, ciphertext2, aad)
	if err != nil {
		t.Fatalf("pollux GCM Open: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("GCM decrypt mismatch: got %q, want %q", decrypted2, plaintext)
	}
}

func TestInteropSM4_CTR_CrossVerify(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	plaintext := []byte("SM4 CTR mode stream cipher interop test")

	// pollux CTR → gmsm CTR 解密
	ciphertext, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCTR, iv)
	if err != nil {
		t.Fatalf("pollux CTR Encrypt: %v", err)
	}

	gmsmBlock, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCTR(gmsmBlock, iv)
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("CTR decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}

	// gmsm CTR → pollux CTR 解密
	stream2 := cipher.NewCTR(gmsmBlock, iv)
	ciphertext2 := make([]byte, len(plaintext))
	stream2.XORKeyStream(ciphertext2, plaintext)

	decrypted2, err := polluxSM4.Decrypt(key, ciphertext2, polluxSM4.ModeCTR, iv)
	if err != nil {
		t.Fatalf("pollux CTR Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("CTR decrypt mismatch: got %q, want %q", decrypted2, plaintext)
	}
}

func TestInteropSM4_CFB_CrossVerify(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	plaintext := []byte("SM4 CFB mode interop test data")

	// pollux CFB 加密 → gmsm CFB 解密
	ciphertext, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCFB, iv)
	if err != nil {
		t.Fatalf("pollux CFB Encrypt: %v", err)
	}

	gmsmBlock, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCFBDecrypter(gmsmBlock, iv) //nolint:staticcheck
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("CFB decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestInteropSM4_HighLevelAPI_vs_Raw(t *testing.T) {
	key, err := polluxSM4.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iv, err := polluxSM4.GenerateIV()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("high level API vs raw mode consistency")

	// pollux 高级 API CBC
	highCT, err := polluxSM4.Encrypt(key, plaintext, polluxSM4.ModeCBC, iv)
	if err != nil {
		t.Fatalf("pollux Encrypt CBC: %v", err)
	}

	// gmsm 原始 CBC
	block, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := polluxSM4.PKCS7Pad(plaintext, polluxSM4.BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	rawCT := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(rawCT, padded)

	if !bytes.Equal(highCT, rawCT) {
		t.Errorf("high-level CBC vs raw CBC mismatch:\nhigh=%x\nraw =%x", highCT, rawCT)
	}
}

func TestInteropSM4_BlockCipher_Interface(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)

	block, err := polluxSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	if block.BlockSize() != polluxSM4.BlockSize {
		t.Errorf("BlockSize: got %d, want %d", block.BlockSize(), polluxSM4.BlockSize)
	}

	src := make([]byte, polluxSM4.BlockSize)
	dst := make([]byte, polluxSM4.BlockSize)
	_, _ = rand.Read(src)

	block.Encrypt(dst, src)

	dec := make([]byte, polluxSM4.BlockSize)
	block.Decrypt(dec, dst)
	if !bytes.Equal(dec, src) {
		t.Error("SM4 block encrypt/decrypt round-trip failed")
	}

	// 与 gmsm 结果一致
	gmsmBlock, err := gmsmSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gmsmDst := make([]byte, polluxSM4.BlockSize)
	gmsmBlock.Encrypt(gmsmDst, src)
	if !bytes.Equal(dst, gmsmDst) {
		t.Errorf("block encrypt mismatch with gmsm")
	}
}

// ============================================================================
// SM9 标识密码互操作
// ============================================================================

func TestInteropSM9_Sign_CrossVerify(t *testing.T) {
	master, err := polluxSM9.GenerateSignMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uid := []byte("alice@example.com")
	userKey, err := polluxSM9.GenerateSignUserKey(master, uid)
	if err != nil {
		t.Fatal(err)
	}
	hash := []byte("SM9 sign interop test message")

	// gmsm SignASN1 → pollux Verify
	sig, err := gmsmSM9.SignASN1(rand.Reader, userKey, hash)
	if err != nil {
		t.Fatalf("gmsm SM9 SignASN1: %v", err)
	}
	if !polluxSM9.Verify(master.PublicKey(), uid, hash, sig) {
		t.Error("pollux SM9 Verify failed for gmsm signature")
	}

	// pollux Sign → gmsm VerifyASN1
	sig2, err := polluxSM9.Sign(userKey, hash)
	if err != nil {
		t.Fatalf("pollux SM9 Sign: %v", err)
	}
	if !gmsmSM9.VerifyASN1(master.PublicKey(), uid, polluxSM9.DefaultSignHID, hash, sig2) {
		t.Error("gmsm SM9 VerifyASN1 failed for pollux signature")
	}
}

func TestInteropSM9_Encrypt_CrossDecrypt(t *testing.T) {
	master, err := polluxSM9.GenerateEncryptMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uid := []byte("bob@example.com")
	userKey, err := polluxSM9.GenerateEncryptUserKey(master, uid)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("SM9 encryption interop test payload")

	// gmsm EncryptASN1 → pollux Decrypt
	ct, err := gmsmSM9.EncryptASN1(rand.Reader, master.PublicKey(), uid, polluxSM9.DefaultEncryptHID, plaintext, nil)
	if err != nil {
		t.Fatalf("gmsm SM9 EncryptASN1: %v", err)
	}
	decrypted, err := polluxSM9.Decrypt(userKey, uid, ct)
	if err != nil {
		t.Fatalf("pollux SM9 Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("SM9 decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}

	// pollux Encrypt → gmsm DecryptASN1
	ct2, err := polluxSM9.Encrypt(master.PublicKey(), uid, plaintext, nil)
	if err != nil {
		t.Fatalf("pollux SM9 Encrypt: %v", err)
	}
	decrypted2, err := gmsmSM9.DecryptASN1(userKey, uid, ct2)
	if err != nil {
		t.Fatalf("gmsm SM9 DecryptASN1: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("SM9 decrypt mismatch: got %q, want %q", decrypted2, plaintext)
	}
}

func TestInteropSM9_WrapKey_CrossUnwrap(t *testing.T) {
	master, err := polluxSM9.GenerateEncryptMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uid := []byte("key-wrap@example.com")
	userKey, err := polluxSM9.GenerateEncryptUserKey(master, uid)
	if err != nil {
		t.Fatal(err)
	}
	keyLen := 32

	// gmsm 顶层 WrapKey 返回 (key, rawCipher) — raw 格式
	gmsmKey, gmsmCipher, err := gmsmSM9.WrapKey(rand.Reader, master.PublicKey(), uid, polluxSM9.DefaultEncryptHID, keyLen)
	if err != nil {
		t.Fatalf("gmsm WrapKey: %v", err)
	}
	if len(gmsmKey) != keyLen {
		t.Errorf("wrapped key length: got %d, want %d", len(gmsmKey), keyLen)
	}

	// gmsm 顶层 UnwrapKey baseline (raw 格式)
	gmsmUnwrapped, err := gmsmSM9.UnwrapKey(userKey, uid, gmsmCipher, keyLen)
	if err != nil {
		t.Fatalf("gmsm UnwrapKey baseline: %v", err)
	}
	if !bytes.Equal(gmsmUnwrapped, gmsmKey) {
		t.Errorf("gmsm wrap/unwrap baseline mismatch")
	}

	// gmsm 顶层 WrapKey → pollux UnwrapKey
	// pollux UnwrapKey 底层也调用 gmsmSM9.UnwrapKey，接受 raw 格式
	polluxUnwrapped, err := polluxSM9.UnwrapKey(userKey, uid, gmsmCipher, keyLen)
	if err != nil {
		t.Fatalf("pollux UnwrapKey: %v", err)
	}
	if !bytes.Equal(polluxUnwrapped, gmsmKey) {
		t.Errorf("SM9 cross-library unwrap mismatch: got %x, want %x", polluxUnwrapped, gmsmKey)
	}
}

// ============================================================================
// Go 标准库接口兼容性
// ============================================================================

func TestInteropStdlib_SM2_CryptoSigner(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var signer crypto.Signer = priv

	digest := []byte("crypto.Signer interface test")

	sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := signer.Public()
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *ecdsa.PublicKey", pub)
	}
	if !polluxSM2.VerifyASN1(ecdsaPub, digest, sig) {
		t.Error("VerifyASN1 failed for crypto.Signer-produced signature")
	}

	// Sign with SM2SignerOption
	uid := []byte("1234567812345678")
	opts := polluxSM2.SM2SignerOption(uid)
	sigSM2, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatalf("Sign with SM2SignerOption: %v", err)
	}
	if !polluxSM2.VerifyWithSM2(ecdsaPub, uid, digest, sigSM2) {
		t.Error("VerifyWithSM2 failed for crypto.Signer SM2 signature")
	}
}

func TestInteropStdlib_SM3_HashInterface(t *testing.T) {
	var h hash.Hash = polluxSM3.New()

	if h.BlockSize() != polluxSM3.BlockSize {
		t.Errorf("BlockSize: got %d, want %d", h.BlockSize(), polluxSM3.BlockSize)
	}
	if h.Size() != polluxSM3.Size {
		t.Errorf("Size: got %d, want %d", h.Size(), polluxSM3.Size)
	}

	data := []byte("hash.Hash interface compliance test")
	h.Write(data)
	digest := h.Sum(nil)

	if len(digest) != polluxSM3.Size {
		t.Errorf("digest length: got %d, want %d", len(digest), polluxSM3.Size)
	}

	expected := polluxSM3.Sum(data)
	if !bytes.Equal(digest, expected[:]) {
		t.Errorf("digest mismatch via hash.Hash: got %x, want %x", digest, expected)
	}
}

func TestInteropStdlib_SM4_CipherBlock(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)

	var block cipher.Block
	block, err := polluxSM4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	if block.BlockSize() != 16 {
		t.Errorf("BlockSize: got %d, want 16", block.BlockSize())
	}

	src := make([]byte, 16)
	enc := make([]byte, 16)
	dec := make([]byte, 16)
	for i := range src {
		src[i] = byte(i)
	}

	block.Encrypt(enc, src)
	block.Decrypt(dec, enc)

	if !bytes.Equal(dec, src) {
		t.Errorf("cipher.Block round-trip failed: got %x, want %x", dec, src)
	}

	// 加密结果不应等于明文
	if bytes.Equal(enc, src) {
		t.Error("ciphertext should not equal plaintext")
	}
}

func TestInteropStdlib_SM4_AEAD(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)

	aead, err := polluxSM4.NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	var _ cipher.AEAD = aead

	if aead.NonceSize() != 12 {
		t.Errorf("NonceSize: got %d, want 12", aead.NonceSize())
	}
	if aead.Overhead() != 16 {
		t.Errorf("Overhead: got %d, want 16", aead.Overhead())
	}

	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	plaintext := []byte("cipher.AEAD interface test")
	aad := []byte("aad for AEAD test")

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("AEAD Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("AEAD round-trip failed: got %q, want %q", opened, plaintext)
	}

	// 篡改密文应解密失败
	sealed[0] ^= 0xff
	_, err = aead.Open(nil, nonce, sealed, aad)
	if err == nil {
		t.Error("AEAD should reject tampered ciphertext")
	}
}

// ============================================================================
// KDF 与 HKDF 细节验证
// ============================================================================

func TestInteropSM3_KDF_EmptyInput(t *testing.T) {
	_, err := polluxSM3.KDF(nil, 16)
	if err == nil {
		t.Error("KDF with nil z should return error")
	}
	_, err = polluxSM3.KDF([]byte("z"), 0)
	if err == nil {
		t.Error("KDF with klen=0 should return error")
	}
}

func TestInteropSM3_KDF_OutputLength(t *testing.T) {
	z := []byte("test kdf output length")
	for _, klen := range []int{16, 32, 48, 64} {
		out, err := polluxSM3.KDF(z, klen)
		if err != nil {
			t.Fatalf("KDF klen=%d: %v", klen, err)
		}
		if len(out) != klen {
			t.Errorf("KDF output length: got %d, want %d", len(out), klen)
		}
		// gmsm Kdf 结果一致
		gmsmOut := gmsmSM3.Kdf(z, klen)
		if !bytes.Equal(out, gmsmOut) {
			t.Errorf("KDF mismatch at klen=%d", klen)
		}
	}
}

func TestInteropSM3_KDF_Deterministic(t *testing.T) {
	z := []byte("deterministic test input")
	klen := 32

	out1, err := polluxSM3.KDF(z, klen)
	if err != nil {
		t.Fatalf("KDF: %v", err)
	}
	out2, _ := polluxSM3.KDF(z, klen)

	if !bytes.Equal(out1, out2) {
		t.Errorf("KDF not deterministic: %x vs %x", out1, out2)
	}
}

// 辅助函数：构造 KDF 手工计算以交叉验证
func TestInteropSM3_KDF_ManualComputation(t *testing.T) {
	z := []byte("manual KDF verification")
	klen := 32

	// 手工按 GM/T 0003.4-2012 KDF 公式计算
	var ct uint32 = 1
	var manual []byte
	for len(manual) < klen {
		h := gmsmSM3.New()
		h.Write(z)
		ctBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ctBytes, ct)
		h.Write(ctBytes)
		manual = append(manual, h.Sum(nil)...)
		ct++
	}
	manual = manual[:klen]

	polluxOut, err := polluxSM3.KDF(z, klen)
	if err != nil {
		t.Fatalf("pollux KDF: %v", err)
	}
	if !bytes.Equal(polluxOut, manual) {
		t.Errorf("KDF manual mismatch:\npollux=%x\nmanual=%x", polluxOut, manual)
	}
}

// ============================================================================
// SM3 HKDF 互操作（验证 S3-1 修复后 HKDF 使用标准 HMAC）
// ============================================================================

func TestInteropSM3_HKDF_Consistency(t *testing.T) {
	salt := []byte("hkdf-interop-salt")
	ikm := []byte("hkdf-interop-input-keying-material")
	info := []byte("hkdf-interop-info")

	// pollux HKDF
	out32, err := polluxSM3.HKDF(salt, ikm, info, 32)
	if err != nil {
		t.Fatalf("pollux HKDF: %v", err)
	}
	if len(out32) != 32 {
		t.Fatalf("HKDF output length: got %d, want 32", len(out32))
	}

	// 确定性：相同输入产生相同输出
	out32b, _ := polluxSM3.HKDF(salt, ikm, info, 32)
	if !bytes.Equal(out32, out32b) {
		t.Errorf("HKDF not deterministic")
	}

	// 不同 salt 应产生不同输出
	outNoSalt, _ := polluxSM3.HKDF(nil, ikm, info, 32)
	if bytes.Equal(out32, outNoSalt) {
		t.Error("HKDF with different salt should produce different output")
	}

	// 不同 info 应产生不同输出
	outDiffInfo, _ := polluxSM3.HKDF(salt, ikm, []byte("other-info"), 32)
	if bytes.Equal(out32, outDiffInfo) {
		t.Error("HKDF with different info should produce different output")
	}
}

func TestInteropSM3_HKDFExtract_Expand_Split(t *testing.T) {
	salt := []byte("split-test-salt")
	ikm := []byte("split-test-ikm")
	info := []byte("split-test-info")
	length := 48

	// 方式1: 一步 HKDF
	fullOut, err := polluxSM3.HKDF(salt, ikm, info, length)
	if err != nil {
		t.Fatal(err)
	}

	// 方式2: 分步 Extract + Expand
	prk := polluxSM3.HKDFExtract(salt, ikm)
	splitOut, err := polluxSM3.HKDFExpand(prk, info, length)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fullOut, splitOut) {
		t.Errorf("HKDF full vs split mismatch:\nfull =%x\nsplit=%x", fullOut, splitOut)
	}
}

func TestInteropSM3_HKDF_ErrorPaths(t *testing.T) {
	_, err := polluxSM3.HKDF(nil, []byte("ikm"), nil, 0)
	if err == nil {
		t.Error("HKDF should reject length=0")
	}

	_, err = polluxSM3.HKDF(nil, []byte("ikm"), nil, -1)
	if err == nil {
		t.Error("HKDF should reject negative length")
	}

	_, err = polluxSM3.HKDFExpand([]byte("prk"), nil, 0)
	if err == nil {
		t.Error("HKDFExpand should reject length=0")
	}
}

// ============================================================================
// SM2 压缩公钥互操作
// ============================================================================

func TestInteropSM2_Compress_Decompress_GMSM(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// pollux 压缩 → pollux 解压
	compressed := polluxSM2.CompressPublicKey(&priv.PublicKey)
	if len(compressed) != 33 {
		t.Fatalf("compressed key: got %d bytes, want 33", len(compressed))
	}

	decompressed, err := polluxSM2.DecompressPublicKey(compressed)
	if err != nil {
		t.Fatalf("DecompressPublicKey: %v", err)
	}

	// 解压后公钥应可用 gmsm 验证签名
	data := []byte("compress interop verification")
	sig, err := gmsmSM2.SignASN1(rand.Reader, (*gmsmSM2.PrivateKey)(priv), data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !gmsmSM2.VerifyASN1(decompressed, data, sig) {
		t.Error("gmsm VerifyASN1 failed with decompressed public key")
	}

	// gmsm 生成密钥 → pollux 压缩/解压
	gmsmPriv, err := gmsmSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed2 := polluxSM2.CompressPublicKey(&gmsmPriv.PublicKey)
	decompressed2, err := polluxSM2.DecompressPublicKey(compressed2)
	if err != nil {
		t.Fatalf("DecompressPublicKey gmsm key: %v", err)
	}
	if !polluxSM2.Equal(decompressed2, &gmsmPriv.PublicKey) {
		t.Error("decompressed gmsm key mismatch")
	}
}

func TestInteropSM2_Compress_InvalidInput(t *testing.T) {
	_, err := polluxSM2.DecompressPublicKey([]byte{0x02}) // too short
	if err == nil {
		t.Error("should reject too-short compressed key")
	}

	_, err = polluxSM2.DecompressPublicKey(make([]byte, 33)) // 0x00 prefix
	if err == nil {
		t.Error("should reject invalid prefix byte")
	}
}

// ============================================================================
// SM4 DeriveKey 互操作验证
// ============================================================================

func TestInteropSM4_DeriveKey_Consistency(t *testing.T) {
	masterKey := []byte("0123456789abcdef")
	label := []byte("interop-label")
	context := []byte("interop-context")

	// 两次调用结果一致
	k1, err := polluxSM4.DeriveKey(masterKey, label, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := polluxSM4.DeriveKey(masterKey, label, context, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Errorf("DeriveKey not deterministic")
	}

	// 修改 masterKey 应产生不同输出
	wrongKey := make([]byte, 16)
	copy(wrongKey, masterKey)
	wrongKey[0] ^= 0xff
	k3, _ := polluxSM4.DeriveKey(wrongKey, label, context, 32)
	if bytes.Equal(k1, k3) {
		t.Error("different masterKey produced same derived key")
	}

	// 修改 label 应产生不同输出
	k4, _ := polluxSM4.DeriveKey(masterKey, []byte("other-label"), context, 32)
	if bytes.Equal(k1, k4) {
		t.Error("different label produced same derived key")
	}
}

func TestInteropSM4_DeriveKey_ErrorPaths(t *testing.T) {
	validKey := make([]byte, 16)
	_, _ = rand.Read(validKey)

	_, err := polluxSM4.DeriveKey([]byte{1, 2, 3}, []byte("l"), []byte("c"), 16)
	if err == nil {
		t.Error("should reject non-16-byte master key")
	}

	_, err = polluxSM4.DeriveKey(validKey, []byte("l"), []byte("c"), 0)
	if err == nil {
		t.Error("should reject length=0")
	}

	_, err = polluxSM4.DeriveKey(validKey, []byte("l"), []byte("c"), -1)
	if err == nil {
		t.Error("should reject negative length")
	}
}
