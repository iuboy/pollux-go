package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"

	gmsmSM2 "github.com/emmansun/gmsm/sm2"
)

// KeyExchangePerformer 封装 SM2 密钥协商协议 (GM/T 0003.3-2012)。
// 用于双方在已有长期密钥对的情况下协商出共享密钥。
type KeyExchangePerformer struct {
	ke       *gmsmSM2.KeyExchange
	keyLen   int
	initDone bool
}

// NewKeyExchangePerformer 创建 SM2 密钥协商实例。
// selfPriv 和 peerPub 分别是本方长期私钥和对端长期公钥。
// uid 和 peerUID 是双方的标识符（如 GM/T 0009 中定义的用户 ID）。
// keyLen 是期望的共享密钥长度（字节），通常为 32。
func NewKeyExchangePerformer(selfPriv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int) (*KeyExchangePerformer, error) {
	ke, err := gmsmSM2.NewKeyExchange(selfPriv, peerPub, uid, peerUID, keyLen, true)
	if err != nil {
		return nil, err
	}
	return &KeyExchangePerformer{ke: ke, keyLen: keyLen}, nil
}

// GenerateEphemeralKey 生成临时公钥，作为密钥协商的第一步。
func (p *KeyExchangePerformer) GenerateEphemeralKey() (*ecdsa.PublicKey, error) {
	return p.GenerateEphemeralKeyWithRandom(rand.Reader)
}

// GenerateEphemeralKeyWithRandom 使用指定随机源生成临时公钥。
func (p *KeyExchangePerformer) GenerateEphemeralKeyWithRandom(r io.Reader) (*ecdsa.PublicKey, error) {
	pub, err := p.ke.InitKeyExchange(r)
	if err != nil {
		return nil, err
	}
	p.initDone = true
	return pub, nil
}

// ComputeSharedSecretAsInitiator 发起方计算共享密钥。
// peerEphemeralPub 是对端的临时公钥，peerSig 是对端签名。
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

// ComputeSharedSecretAsResponder 响应方计算共享密钥。
// peerEphemeralPub 是对端的临时公钥。
// 返回共享密钥和本方签名（需发送给对端验证）。
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
func (p *KeyExchangePerformer) Destroy() {
	p.ke = nil
	p.initDone = false
}
