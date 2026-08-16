package keycrypt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/iuboy/pollux-go/sm2"
)

func TestRSAKeyGenerator_Generate(t *testing.T) {
	priv, err := NewRSAKeyGenerator(2048).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Fatalf("type = %T, want *rsa.PrivateKey", priv)
	}
}

func TestECDSAKeyGenerator_Generate(t *testing.T) {
	priv, err := NewECDSAKeyGenerator(elliptic.P256()).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("type = %T, want *ecdsa.PrivateKey", priv)
	}
	if k.Curve != elliptic.P256() {
		t.Fatal("curve mismatch")
	}
}

func TestEd25519KeyGenerator_Generate(t *testing.T) {
	priv, err := NewEd25519KeyGenerator().Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Fatalf("type = %T, want ed25519.PrivateKey", priv)
	}
}

func TestSM2KeyGenerator_Generate(t *testing.T) {
	priv, err := NewSM2KeyGenerator().Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k, ok := priv.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("type = %T, want *sm2.PrivateKey", priv)
	}
	if k.Curve != sm2.P256() {
		t.Fatal("not on the SM2 curve")
	}
}

func TestNewKeyGeneratorWithType_AllTypes(t *testing.T) {
	for _, kt := range []KeyType{
		KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096,
		KeyTypeECDSAP256, KeyTypeECDSAP384,
		KeyTypeEd25519, KeyTypeSM2,
	} {
		if _, err := NewKeyGeneratorWithType(string(kt)); err != nil {
			t.Errorf("NewKeyGeneratorWithType(%s): %v", kt, err)
		}
	}
}

func TestNewKeyGeneratorWithType_RejectsEmptyAndUnknown(t *testing.T) {
	// 空串报错：默认选择是应用策略，不由库决定。
	if _, err := NewKeyGeneratorWithType(""); err == nil {
		t.Error("empty key type should be rejected")
	}
	if _, err := NewKeyGeneratorWithType("dsa-1024"); err == nil {
		t.Error("unknown key type should be rejected")
	}
}

func TestGenerateKeyPairWithType_ExtractsPublicKey(t *testing.T) {
	for _, kt := range []KeyType{KeyTypeECDSAP256, KeyTypeSM2} {
		priv, pub, err := GenerateKeyPairWithType(kt)
		if err != nil {
			t.Fatalf("GenerateKeyPairWithType(%s): %v", kt, err)
		}
		if pub == nil {
			t.Fatalf("(%s) public key is nil", kt)
		}
		_ = priv
	}
}
