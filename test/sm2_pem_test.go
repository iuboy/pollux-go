package test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	polluxSM2 "github.com/iuboy/pollux-go/sm2"
)

func TestBlackBox_SM2_PrivateKeyPEM_Roundtrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := polluxSM2.WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("WritePrivateKeyToPEM: %v", err)
	}
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("PEM should start with BEGIN PRIVATE KEY, got: %s", pemBytes[:min(len(pemBytes), 40)])
	}

	recovered, err := polluxSM2.ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyFromPEM: %v", err)
	}
	if recovered.D.Cmp(priv.D) != 0 {
		t.Error("recovered private key D mismatch")
	}
}

func TestBlackBox_SM2_PublicKeyPEM_Roundtrip(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := polluxSM2.WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("WritePublicKeyToPEM: %v", err)
	}
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("PEM should start with BEGIN PUBLIC KEY, got: %s", pemBytes[:min(len(pemBytes), 40)])
	}

	recovered, err := polluxSM2.ParsePublicKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM: %v", err)
	}
	if !polluxSM2.Equal(&priv.PublicKey, recovered) {
		t.Error("recovered public key mismatch")
	}
}

func TestBlackBox_SM2_ParsePrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := polluxSM2.ParsePrivateKeyFromPEM([]byte("not valid PEM data"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestBlackBox_SM2_ParsePrivateKeyFromPEM_NoKeyBlock(t *testing.T) {
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n")
	_, err := polluxSM2.ParsePrivateKeyFromPEM(certPEM)
	if err == nil {
		t.Error("expected error for non-key PEM block")
	}
}

func TestBlackBox_SM2_ParsePublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := polluxSM2.ParsePublicKeyFromPEM([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestBlackBox_SM2_WritePrivateKeyToPEM_Format(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := polluxSM2.WritePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pemBytes, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Error("missing BEGIN PRIVATE KEY marker")
	}
	if !bytes.Contains(pemBytes, []byte("-----END PRIVATE KEY-----")) {
		t.Error("missing END PRIVATE KEY marker")
	}
}

func TestBlackBox_SM2_WritePublicKeyToPEM_Format(t *testing.T) {
	priv, err := polluxSM2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := polluxSM2.WritePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pemBytes, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Error("missing BEGIN PUBLIC KEY marker")
	}
	if !bytes.Contains(pemBytes, []byte("-----END PUBLIC KEY-----")) {
		t.Error("missing END PUBLIC KEY marker")
	}
}
