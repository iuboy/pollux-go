// Package sm2 implements the SM2 elliptic curve public key cryptography
// algorithm (GM/T 0003-2012), following crypto/ecdsa conventions.
//
// SM2 provides digital signatures and public-key encryption on the SM2
// elliptic curve. PrivateKey implements the crypto.Signer interface.
//
// Note: this package does NOT implement SM2 key agreement (MQV). For TLCP
// ECDHE key agreement, see the internal tlcp engine package which uses the
// gmsm MQV primitives directly.
//
// Basic usage:
//
//	key, err := sm2.GenerateKey(rand.Reader)
//	sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
//	ok := sm2.VerifyASN1(&key.PublicKey, digest, sig)
//
// # Cipher ordering and encoding
//
// SM2 ciphertext is composed of three parts: C1 (an elliptic curve point),
// C2 (the encrypted message), and C3 (an SM3 digest). The national standard
// GB/T 32918.4-2016 mandates the C1C3C2 splicing order and ASN.1 encoding;
// EncryptASN1 / Decrypt (and every envelope function) use this default.
//
// The earlier GM/T 0003-2012 draft specified the C1C2C3 order, and some legacy
// systems (old GmSSL builds, certain Java BC configurations, 金融 IC 卡) also
// use a plain (non-ASN.1) encoding. To interoperate with such systems use the
// explicit-options API:
//
//	// Encrypt in legacy C1C2C3 plain format
//	opts, _ := sm2.NewEncrypterOpts(sm2.EncodingPlain, sm2.OrderC1C2C3, false)
//	ct, _ := sm2.Encrypt(rand.Reader, &key.PublicKey, msg, opts)
//
//	// Decrypt a legacy C1C2C3 ciphertext
//	decOpts, _ := sm2.NewDecrypterOpts(sm2.EncodingPlain, sm2.OrderC1C2C3)
//	pt, _ := sm2.DecryptWithOpts(key, ct, decOpts)
//
//	// Or convert ordering in place and use the standard Decrypt
//	ctStd, _ := sm2.AdjustCipherOrder(ct, sm2.OrderC1C2C3, sm2.OrderC1C3C2)
//	pt, _ = sm2.Decrypt(key, ctStd)
//
// ASN1ToPlain / PlainToASN1 convert between encodings.
//
// Status: wrapper around gmsm/sm2
package sm2
