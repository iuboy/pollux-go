package quicgm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"
)

// benchSizes covers a small coalesced packet, a typical full-size QUIC packet,
// and a large multi-packet payload.
var benchSizes = []int{64, 1200, 16384}

func benchSecret() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// BenchmarkPayloadEncrypt_SM4GCM measures QUIC payload encryption with the
// RFC 8998 SM4-GCM cipher suite (Route C — transport-level GM QUIC).
func BenchmarkPayloadEncrypt_SM4GCM(b *testing.B) {
	p, err := NewQUICPacketProtector(benchSecret())
	if err != nil {
		b.Fatal(err)
	}
	defer p.Zero()
	header := make([]byte, 16)
	for _, size := range benchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = p.EncryptPayload(1, header, payload)
			}
		})
	}
}

// BenchmarkPayloadDecrypt_SM4GCM measures QUIC payload decryption (Route C).
func BenchmarkPayloadDecrypt_SM4GCM(b *testing.B) {
	p, _ := NewQUICPacketProtector(benchSecret())
	defer p.Zero()
	header := make([]byte, 16)
	for _, size := range benchSizes {
		ct, _ := p.EncryptPayload(1, header, make([]byte, size))
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = p.DecryptPayload(1, header, ct)
			}
		})
	}
}

// BenchmarkPayloadEncrypt_AES128GCM is the standard-route baseline (Route A):
// identical payload/header sizes encrypted with AES-128-GCM via crypto/aes, so
// SM4-GCM throughput can be compared directly.
func BenchmarkPayloadEncrypt_AES128GCM(b *testing.B) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{0x42}, 16))
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	header := make([]byte, 16)
	for _, size := range benchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				aead.Seal(nil, nonce, payload, header)
			}
		})
	}
}

// BenchmarkPayloadDecrypt_AES128GCM is the standard-route decryption baseline.
func BenchmarkPayloadDecrypt_AES128GCM(b *testing.B) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{0x42}, 16))
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	header := make([]byte, 16)
	for _, size := range benchSizes {
		ct := aead.Seal(nil, nonce, make([]byte, size), header)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = aead.Open(nil, nonce, ct, header)
			}
		})
	}
}

// BenchmarkHeaderProtection measures in-place header protection (apply + remove)
// on a 1200-byte packet with a 2-byte packet number at offset 4.
func BenchmarkHeaderProtection(b *testing.B) {
	p, _ := NewQUICPacketProtector(benchSecret())
	defer p.Zero()
	original := make([]byte, 1200)
	for i := range original {
		original[i] = byte(0xA0 + i%16)
	}
	original[0] = 0xC1
	original[4] = 0x12
	original[5] = 0x34
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := append([]byte(nil), original...)
		_ = p.ApplyHeaderProtection(buf, 4, 2, true)
		_, _ = p.RemoveHeaderProtection(buf, 4, true)
	}
}
