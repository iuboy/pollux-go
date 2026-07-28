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

// RespondKeyExchange is the responder's first step (GM/T 0003.3 step B2):
// after receiving the initiator's ephemeral public key, it computes the
// responder's signature (sB) to send back to the initiator. It does NOT derive
// the shared secret yet — the responder must wait for the initiator's signature
// and call ConfirmInitiator to verify it and derive the shared key, completing
// mutual authentication.
func (p *KeyExchangePerformer) RespondKeyExchange(r io.Reader, initiatorEphemeralPub *ecdsa.PublicKey) ([]byte, error) {
	if !p.initDone {
		return nil, errors.New("sm2: key exchange not initialized; call GenerateEphemeralKey first")
	}
	_, sig, err := p.ke.RepondKeyExchange(r, initiatorEphemeralPub) //nolint:misspell // upstream gmsm typo: Repond→Respond
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// ConfirmInitiator is the responder's final step (GM/T 0003.3 step B3): it
// verifies the initiator's signature (sA) received from the initiator and, on
// success, derives the shared secret. Passing a nil/empty initiatorSig skips
// verification — DO NOT do this in production; it forfeits mutual
// authentication and allows a MITM to impersonate the initiator.
func (p *KeyExchangePerformer) ConfirmInitiator(initiatorSig []byte) ([]byte, error) {
	if !p.initDone {
		return nil, errors.New("sm2: key exchange not initialized; call GenerateEphemeralKey first")
	}
	return p.ke.ConfirmInitiator(initiatorSig)
}

// ComputeSharedSecretAsInitiator is the initiator's step (GM/T 0003.3 step A2):
// it verifies the responder's signature (sB) and, on success, derives the shared
// secret. It also returns the initiator's own signature (sA), which the
// initiator MUST send to the responder so the responder can authenticate it via
// ConfirmInitiator.
func (p *KeyExchangePerformer) ComputeSharedSecretAsInitiator(peerEphemeralPub *ecdsa.PublicKey, peerSig []byte) (sharedKey, initiatorSig []byte, err error) {
	if !p.initDone {
		return nil, nil, errors.New("sm2: key exchange not initialized; call GenerateEphemeralKey first")
	}
	sharedKey, initiatorSig, err = p.ke.ConfirmResponder(peerEphemeralPub, peerSig)
	if err != nil {
		return nil, nil, err
	}
	return sharedKey, initiatorSig, nil
}

// ComputeSharedSecretAsResponder is the legacy one-shot responder API.
//
// Deprecated: it skips verification of the initiator's signature (GM/T 0003.3
// step B3), forfeiting mutual authentication and allowing a man-in-the-middle to
// impersonate the initiator. Use RespondKeyExchange to produce the responder
// signature, then ConfirmInitiator(initiatorSig) once the initiator's signature
// has been received and verified. This wrapper retains the old (insecure)
// behavior for compile compatibility only.
func (p *KeyExchangePerformer) ComputeSharedSecretAsResponder(r io.Reader, peerEphemeralPub *ecdsa.PublicKey) (sharedKey []byte, sig []byte, err error) {
	sig, err = p.RespondKeyExchange(r, peerEphemeralPub)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, err = p.ConfirmInitiator(nil) // legacy: no initiator verification
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
// ComputeSharedSecretAsInitiator or ConfirmInitiator using memsecure.ZeroBytes.
func (p *KeyExchangePerformer) Destroy() {
	p.ke = nil
	p.initDone = false
}
