package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// KeyExchangePerformer wraps SM2 key exchange protocol (GM/T 0003.3-2012).
// For two parties to negotiate a shared key using existing long-term key pairs.
type KeyExchangePerformer struct {
	ke       *gmsmSM2.KeyExchange
	keyLen   int
	initDone bool
}

// NewKeyExchangePerformer creates an SM2 key exchange instance.
// selfPriv and peerPub are the local long-term private key and the peer's long-term public key.
// uid and peerUID are the identifiers for both parties (e.g., user IDs as defined in GM/T 0009).
// keyLen is the expected shared key length in bytes, typically 32.
func NewKeyExchangePerformer(selfPriv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int) (*KeyExchangePerformer, error) {
	ke, err := gmsmSM2.NewKeyExchange(selfPriv, peerPub, uid, peerUID, keyLen, true)
	if err != nil {
		return nil, err
	}
	return &KeyExchangePerformer{ke: ke, keyLen: keyLen}, nil
}

// GenerateEphemeralKey generates ephemeral public key as the first step of key exchange.
func (p *KeyExchangePerformer) GenerateEphemeralKey() (*ecdsa.PublicKey, error) {
	return p.GenerateEphemeralKeyWithRandom(rand.Reader)
}

// GenerateEphemeralKeyWithRandom generates ephemeral public key using the specified random source.
func (p *KeyExchangePerformer) GenerateEphemeralKeyWithRandom(r io.Reader) (*ecdsa.PublicKey, error) {
	pub, err := p.ke.InitKeyExchange(r)
	if err != nil {
		return nil, err
	}
	p.initDone = true
	return pub, nil
}

// ComputeSharedSecretAsInitiator initiator computes shared secret.
// peerEphemeralPub is the peer's ephemeral public key, peerSig is the peer's signature.
func (p *KeyExchangePerformer) ComputeSharedSecretAsInitiator(peerEphemeralPub *ecdsa.PublicKey, peerSig []byte) ([]byte, error) {
	if !p.initDone {
		return nil, errors.New("sm2: key exchange not initialized; call GenerateEphemeralKey first")
	}
	sharedKey, _, err := p.ke.ConfirmResponder(peerEphemeralPub, peerSig)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

// ComputeSharedSecretAsResponder responder computes shared secret.
// peerEphemeralPub is the peer's ephemeral public key.
// Returns shared key and local signature (to be sent to the peer for verification).
func (p *KeyExchangePerformer) ComputeSharedSecretAsResponder(r io.Reader, peerEphemeralPub *ecdsa.PublicKey) (sharedKey []byte, sig []byte, err error) {
	if !p.initDone {
		return nil, nil, errors.New("sm2: key exchange not initialized; call GenerateEphemeralKey first")
	}
	_, sig, err = p.ke.RepondKeyExchange(r, peerEphemeralPub) //nolint:misspell // upstream gmsm typo: Repond→Respond
	if err != nil {
		return nil, nil, err
	}
	sharedKey, err = p.ke.ConfirmInitiator(nil)
	if err != nil {
		return nil, nil, err
	}
	return sharedKey, sig, nil
}

// Destroy clears internal key exchange state, including any derived shared secrets.
// This should be called after the key exchange is complete to minimize the window
// during which sensitive material exists in memory.
//
// Security note: the underlying gmsm KeyExchange does not expose an explicit
// zeroing method, so Destroy releases the reference for GC. For higher assurance,
// callers should independently zero the shared secret bytes returned by
// ComputeSharedSecretAsInitiator or ComputeSharedSecretAsResponder using
// memsecure.ZeroBytes.
func (p *KeyExchangePerformer) Destroy() {
	p.ke = nil
	p.initDone = false
}
