package tlcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/sm2"
)

// This file adapts the gmsm ecdh package's SM2 MQV primitives into thin
// wrappers used by the ECDHE key-agreement layer (engine_keyagreement.go).
// Keeping the gmsm dependency in one place makes the engine portable and the
// MQV call sites readable.
//
// SM2 MQV (GB/T 36322-2018) is implemented by gmsm/ecdh:
//   - (*ecdh.PrivateKey).SM2MQV(eLocal, sRemote, eRemote) → shared point
//   - (*ecdh.PublicKey).SM2SharedKey(isResponder, keyLen, sPub, sRemote, ...)
//
// The wrappers below hide the ecdh type conversions (sm2.PrivateKey →
// ecdh.PrivateKey, ecdsa.PublicKey → ecdh.PublicKey).

// ecdhPrivateKey wraps a gmsm ecdh.PrivateKey (SM2 curve).
type ecdhPrivateKey struct{ k *ecdh.PrivateKey }

// ecdhPublicKey wraps a gmsm ecdh.PublicKey (SM2 curve).
type ecdhPublicKey struct{ k *ecdh.PublicKey }

// bytes returns the uncompressed point encoding (0x04 || X || Y).
func (p *ecdhPublicKey) bytes() []byte { return p.k.Bytes() }

// publicKey returns the public counterpart of a private key.
func (p *ecdhPrivateKey) publicKey() *ecdhPublicKey { return &ecdhPublicKey{k: p.k.PublicKey()} }

// newEcdhPublicKey parses an uncompressed SM2 point (65 bytes: 0x04||X||Y).
func newEcdhPublicKey(point []byte) (*ecdhPublicKey, error) {
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	return &ecdhPublicKey{k: pub}, nil
}

// generateECDHEKey generates a fresh ephemeral SM2 key pair.
func generateECDHEKey(r io.Reader) (*ecdhPrivateKey, error) {
	priv, err := ecdh.P256().GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &ecdhPrivateKey{k: priv}, nil
}

// ecdhPrivFromDecrypter converts a crypto.Decrypter (expected to be an
// *sm2.PrivateKey) into an ecdh private key for MQV.
func ecdhPrivFromDecrypter(dec crypto.Decrypter) (*ecdhPrivateKey, error) {
	sm2Priv, ok := dec.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("tlcp: ECDHE encryption key must be an SM2 private key")
	}
	ecdhKey, err := sm2Priv.ECDH()
	if err != nil {
		return nil, err
	}
	return &ecdhPrivateKey{k: ecdhKey}, nil
}

// ecdhPubFromECDSA converts an *ecdsa.PublicKey (SM2 curve) into an ecdh
// public key.
func ecdhPubFromECDSA(pub *ecdsa.PublicKey) (*ecdhPublicKey, error) {
	ecdhPub, err := sm2.PublicKeyToECDH(pub)
	if err != nil {
		return nil, err
	}
	return &ecdhPublicKey{k: ecdhPub}, nil
}

// sm2mqv computes the SM2 MQV shared secret point using this (long-term) key,
// the local ephemeral key, and the peer's long-term + ephemeral public keys.
func (p *ecdhPrivateKey) sm2mqv(eLocal *ecdhPrivateKey, sRemote, eRemote *ecdhPublicKey) (*ecdhPublicKey, error) {
	uv, err := p.k.SM2MQV(eLocal.k, sRemote.k, eRemote.k)
	if err != nil {
		return nil, err
	}
	return &ecdhPublicKey{k: uv}, nil
}

// sm2SharedKey derives keyLen bytes of shared keying material from the MQV
// shared point uv, using SM3-KDF per GB/T 36322. isResponder selects the ZA
// byte ordering (sponsor vs responder) so both sides derive the same key.
func (uv *ecdhPublicKey) sm2SharedKey(isResponder bool, keyLen int, sPub, sRemote *ecdhPublicKey) ([]byte, error) {
	// gmsm's SM2SharedKey uses the default UID ("1234567812345678") on both
	// sides when uid/remoteUID are nil — matching gotlcp's behavior.
	return uv.k.SM2SharedKey(isResponder, keyLen, sPub.k, sRemote.k, nil, nil)
}

// keep the rand import honest (used indirectly via GenerateKey's reader).
var _ = rand.Reader
