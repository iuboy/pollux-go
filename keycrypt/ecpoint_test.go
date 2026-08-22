package keycrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestMarshalECPointUncompressed_MatchesDeprecatedMarshal 锁定与
// elliptic.Marshal 的逐字节等价性（迁移自弃用 API 的守卫测试）。
func TestMarshalECPointUncompressed_MatchesDeprecatedMarshal(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} { // 等价性守卫必须对照弃用实现
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		want := elliptic.Marshal(curve, key.X, key.Y) // 对照基准
		got := MarshalECPointUncompressed(curve, key.X, key.Y)
		if string(got) != string(want) {
			t.Errorf("%s: output mismatch\n got %X\nwant %X", curve.Params().Name, got, want)
		}
	}
}

// TestMarshalECPointUncompressed_PadsShortCoordinates 验证高位零填充
// （坐标小于字节长度时 FillBytes 左填充，与 elliptic.Marshal 一致）。
func TestMarshalECPointUncompressed_PadsShortCoordinates(t *testing.T) {
	curve := elliptic.P256()
	byteLen := 32
	got := MarshalECPointUncompressed(curve, big.NewInt(1), big.NewInt(2))
	if len(got) != 1+2*byteLen {
		t.Fatalf("len = %d, want %d", len(got), 1+2*byteLen)
	}
	if got[0] != 4 {
		t.Errorf("prefix = %d, want 4", got[0])
	}
	// X=1 应左填充至 32 字节（末字节 0x01，前 31 字节 0x00）
	if got[byteLen] != 1 || got[1] != 0 {
		t.Errorf("X 坐标填充错误: %X", got[1:1+byteLen])
	}
	// Y=2 同理
	if got[2*byteLen] != 2 {
		t.Errorf("Y 坐标填充错误: %X", got[1+byteLen:])
	}
}
