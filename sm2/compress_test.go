package sm2

import (
	"testing"
)

func TestCompressPublicKey(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	compressed := CompressPublicKey(&priv.PublicKey)
	if len(compressed) != 33 {
		t.Errorf("compressed key length: got %d, want 33", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Errorf("compressed key prefix: got 0x%02x, want 0x02 or 0x03", compressed[0])
	}
}

func TestCompressPublicKeyNil(t *testing.T) {
	result := CompressPublicKey(nil)
	if result != nil {
		t.Error("nil key should return nil")
	}
}

func TestDecompressPublicKey(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	compressed := CompressPublicKey(&priv.PublicKey)
	decompressed, err := DecompressPublicKey(compressed)
	if err != nil {
		t.Fatalf("DecompressPublicKey: %v", err)
	}

	if decompressed.X.Cmp(priv.PublicKey.X) != 0 || decompressed.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("decompressed key does not match original")
	}
}

func TestDecompressPublicKeyInvalid(t *testing.T) {
	tests := [][]byte{
		{0x02},                   // too short
		{0x02, 0x01, 0x02, 0x03}, // too short
		make([]byte, 34),         // too long
	}

	for _, tt := range tests {
		_, err := DecompressPublicKey(tt)
		if err == nil {
			t.Errorf("DecompressPublicKey(%x) should error", tt)
		}
	}
}

func TestMarshalUncompressed(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	data := MarshalUncompressed(&priv.PublicKey)
	if len(data) != 65 {
		t.Errorf("uncompressed length: got %d, want 65", len(data))
	}
	if data[0] != 0x04 {
		t.Errorf("uncompressed prefix: got 0x%02x, want 0x04", data[0])
	}
}

func TestMarshalUncompressedNil(t *testing.T) {
	result := MarshalUncompressed(nil)
	if result != nil {
		t.Error("nil key should return nil")
	}
}

func TestUnmarshalUncompressed(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	marshaled := MarshalUncompressed(&priv.PublicKey)
	unmarshaled, err := UnmarshalUncompressed(marshaled)
	if err != nil {
		t.Fatalf("UnmarshalUncompressed: %v", err)
	}

	if unmarshaled.X.Cmp(priv.PublicKey.X) != 0 || unmarshaled.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("unmarshaled key does not match original")
	}
}

func TestUnmarshalUncompressedInvalid(t *testing.T) {
	_, err := UnmarshalUncompressed([]byte{0x04, 0x01})
	if err == nil {
		t.Error("short data should error")
	}
}

func TestPublicKeyToBytes(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	data := PublicKeyToBytes(&priv.PublicKey)
	if len(data) != 65 {
		t.Errorf("PublicKeyToBytes length: got %d, want 65", len(data))
	}
}

func TestBytesToPublicKey(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	data := PublicKeyToBytes(&priv.PublicKey)
	pub, err := BytesToPublicKey(data)
	if err != nil {
		t.Fatalf("BytesToPublicKey: %v", err)
	}

	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("converted key does not match original")
	}
}

func TestBytesToPrivateKey(t *testing.T) {
	priv, err := GenerateKeyDefault()
	if err != nil {
		t.Fatal(err)
	}

	privBytes := PrivateKeyToBytes(priv)
	restored, err := BytesToPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("BytesToPrivateKey: %v", err)
	}

	if restored.D.Cmp(priv.D) != 0 {
		t.Error("restored private key does not match original")
	}
}

func TestBytesToPrivateKeyInvalid(t *testing.T) {
	tests := [][]byte{
		make([]byte, 31), // too short
		make([]byte, 33), // too long
		make([]byte, 32), // valid length, but invalid scalar (all zeros)
	}

	for _, tt := range tests {
		_, err := BytesToPrivateKey(tt)
		if err == nil {
			t.Errorf("BytesToPrivateKey(%x) should error", tt)
		}
	}
}
