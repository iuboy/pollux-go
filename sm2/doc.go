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
// Status: wrapper around gmsm/sm2
package sm2
