package sshca

import (
	cryptostd "crypto"
	"fmt"

	xssh "golang.org/x/crypto/ssh"
)

// KeyPairFromRawKey 从原始私钥（*rsa.PrivateKey / ed25519.PrivateKey 等）
// 构造 KeyPair。从 PEM 重载后用此函数把解析出的原始密钥包回 ssh.Signer。
func KeyPairFromRawKey(rawKey cryptostd.PrivateKey) (*KeyPair, error) {
	signer, err := xssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: create SSH signer: %w", err)
	}
	return &KeyPair{
		PrivateKey: signer,
		PublicKey:  signer.PublicKey(),
	}, nil
}
