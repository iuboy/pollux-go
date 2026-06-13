package tls13gm

import (
	"fmt"

	"github.com/iuboy/pollux-go/sm4"
)

// QUICHeaderSampleLen is the header protection sample length in bytes
// (RFC 9001 §5.4.2). For SM4 (128-bit block) it equals the block size.
const QUICHeaderSampleLen = sm4.BlockSize

// HeaderProtectionMask generates the 16-byte header protection mask from a
// ciphertext sample using SM4-ECB, per RFC 9001 §5.4.3. For SM4-GCM, QUIC header
// protection is the raw SM4 block cipher applied to a single 16-byte sample.
//
// The sample is 16 bytes of packet ciphertext taken starting 4 bytes after the
// start of the (still protected) packet number field (RFC 9001 §5.4.2).
func HeaderProtectionMask(hpKey, sample []byte) ([]byte, error) {
	if len(hpKey) != sm4.BlockSize {
		return nil, fmt.Errorf("tls13gm: QUIC header protection key must be %d bytes (SM4-128), got %d", sm4.BlockSize, len(hpKey))
	}
	if len(sample) != QUICHeaderSampleLen {
		return nil, fmt.Errorf("tls13gm: QUIC header protection sample must be %d bytes, got %d", QUICHeaderSampleLen, len(sample))
	}
	block, err := sm4.NewCipher(hpKey)
	if err != nil {
		return nil, fmt.Errorf("tls13gm: create SM4 header protection cipher: %w", err)
	}
	mask := make([]byte, sm4.BlockSize)
	block.Encrypt(mask, sample) // single-block SM4-ECB
	return mask, nil
}
