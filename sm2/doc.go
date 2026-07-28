// Package sm2 implements the SM2 elliptic curve public key cryptography
// algorithm (GM/T 0003-2012), following crypto/ecdsa conventions.
//
// SM2 provides digital signatures and key exchange on the SM2 elliptic curve.
// PrivateKey implements the crypto.Signer interface.
//
// Basic usage:
//
//	key, err := sm2.GenerateKey(rand.Reader)
//	sig, err := sm2.SignASN1(rand.Reader, key, digest, nil)
//	ok := sm2.VerifyASN1(&key.PublicKey, digest, sig)
//
// Status: wrapper around gmsm/sm2
package sm2
