// Package keycrypt provides at-rest private-key encryption and key
// generation primitives for both the GM and international regimes.
//
// # Encryption side
//
// Every private key that lands on disk (CAs, SSH CAs, signing keys) must be
// encrypted as PKCS#8 PBES2 — AES-256-GCM with PBKDF2-SHA256 key derivation
// (NIST SP 800-132 parameters). Plaintext PEM is rejected outright on both
// the marshal and the load path ([ErrPasswordRequired],
// [ErrPlaintextKeyRejected]): the fail-closed posture is deliberate.
//
// The encrypted output is format-compatible with
// [github.com/iuboy/pollux-go/smx509].DecryptPEMPrivateKey, so Marshal and
// Load form a closed loop within pollux-go:
//
//	pem, _ := keycrypt.MarshalEncryptedPrivateKey(key, password)
//	der, _ := keycrypt.LoadEncryptedPrivateKey(pem, password)
//
// # Generation side
//
// The [KeyGenerator] family covers RSA, ECDSA, Ed25519 and SM2. Choosing a
// DEFAULT algorithm (e.g. SM2 under GM mode, ECDSA P-256 otherwise) is an
// application policy and deliberately not provided here — resolve your own
// [KeyType] first, then call [NewKeyGeneratorWithType] (an empty key type is
// rejected).
package keycrypt
