package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

func TestBlackBox_SM2_CompressNil(t *testing.T) {
	result := polluxSM2.CompressPublicKey(nil)
	if result != nil {
		t.Errorf("CompressPublicKey(nil) = %v, want nil", result)
	}
}

func TestBlackBox_SM2_CompressDecompress_Roundtrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	compressed := polluxSM2.CompressPublicKey(&priv.PublicKey)
	if len(compressed) != 33 {
		t.Fatalf("compressed length: got %d, want 33", len(compressed))
	}

	recovered, err := polluxSM2.DecompressPublicKey(compressed)
	if err != nil {
		t.Fatalf("DecompressPublicKey: %v", err)
	}

	if !polluxSM2.Equal(&priv.PublicKey, recovered) {
		t.Error("recovered key does not match original")
	}
}

func TestBlackBox_SM2_Decompress_InvalidLength(t *testing.T) {
	for _, data := range [][]byte{{}, {0x02}, make([]byte, 32), make([]byte, 34)} {
		_, err := polluxSM2.DecompressPublicKey(data)
		if err == nil {
			t.Errorf("DecompressPublicKey(%d bytes): expected error", len(data))
		}
	}
}

func TestBlackBox_SM2_Decompress_InvalidPrefix(t *testing.T) {
	data := make([]byte, 33)
	for _, prefix := range []byte{0x00, 0x04, 0x05} {
		data[0] = prefix
		_, err := polluxSM2.DecompressPublicKey(data)
		if err == nil {
			t.Errorf("DecompressPublicKey with prefix 0x%02x: expected error", prefix)
		}
	}
}

func TestBlackBox_SM2_MarshalUncompressed_Roundtrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	uncompressed := polluxSM2.MarshalUncompressed(&priv.PublicKey)
	if len(uncompressed) != 65 {
		t.Fatalf("uncompressed length: got %d, want 65", len(uncompressed))
	}
	if uncompressed[0] != 0x04 {
		t.Errorf("uncompressed prefix: got 0x%02x, want 0x04", uncompressed[0])
	}

	recovered, err := polluxSM2.UnmarshalUncompressed(uncompressed)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}
	if !polluxSM2.Equal(&priv.PublicKey, recovered) {
		t.Error("recovered key does not match original")
	}
}

func TestBlackBox_SM2_UnmarshalUncompressed_Invalid(t *testing.T) {
	_, err := polluxSM2.UnmarshalUncompressed([]byte{0x04})
	if err == nil {
		t.Error("expected error for short input")
	}
}

func TestBlackBox_SM2_CompressPublicKey_Deterministic(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c1 := polluxSM2.CompressPublicKey(&priv.PublicKey)
	c2 := polluxSM2.CompressPublicKey(&priv.PublicKey)
	if !bytes.Equal(c1, c2) {
		t.Error("CompressPublicKey should be deterministic")
	}
}

func TestBlackBox_SM2_Equal_NilBoth(t *testing.T) {
	if !polluxSM2.Equal(nil, nil) {
		t.Error("Equal(nil, nil) should be true")
	}
}

func TestBlackBox_SM2_Equal_SameKey(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !polluxSM2.Equal(&priv.PublicKey, &priv.PublicKey) {
		t.Error("key should equal itself")
	}
}

func TestBlackBox_SM2_PrivateKeyToBytes_Length(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// PrivateKeyToBytes（已移除）的替代是 PrivateKeyToBytesSecure，Destroy 清零敏感内存。
	skb, err := polluxSM2.PrivateKeyToBytesSecure(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	b := skb.Data()
	if len(b) == 0 || len(b) > 32 {
		t.Errorf("PrivateKeyToBytesSecure length: got %d, want 1-32", len(b))
	}
}

func TestBlackBox_SM2_BytesToPrivateKey_Roundtrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// PrivateKeyToBytes（已移除）的替代是 PrivateKeyToBytesSecure，Destroy 清零敏感内存。
	skb, err := polluxSM2.PrivateKeyToBytesSecure(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToBytesSecure: %v", err)
	}
	defer skb.Destroy()
	b := skb.Data()
	recovered, err := polluxSM2.BytesToPrivateKey(b)
	if err != nil {
		t.Fatalf("BytesToPrivateKey: %v", err)
	}
	if recovered.D.Cmp(priv.D) != 0 {
		t.Error("recovered private key D mismatch")
	}
}

func TestBlackBox_SM2_PublicKeyToBytes_Nil(t *testing.T) {
	// PublicKeyToBytes（已移除）的替代是 MarshalUncompressed。
	result := polluxSM2.MarshalUncompressed(nil)
	if result != nil {
		t.Errorf("MarshalUncompressed(nil) = %v, want nil", result)
	}
}

func TestBlackBox_SM2_MarshalUncompressed_Nil(t *testing.T) {
	result := polluxSM2.MarshalUncompressed(nil)
	if result != nil {
		t.Errorf("MarshalUncompressed(nil) = %v, want nil", result)
	}
}
