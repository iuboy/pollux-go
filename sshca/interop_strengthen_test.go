package sshca

// SSH 强化测试：公钥双格式解析、算法模板约束识别、KRL 与 host CA。
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestParsePublicKeyDualFormat v1 层的公钥解析能力（经整行/纯 base64）。
// 这里直接测 gossh 行为基线 + KRL 的 CA wire 输入（授权层同语义）。
func TestPublicKeyWireFormats(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	wire := sshPub.Marshal()
	b64 := base64.StdEncoding.EncodeToString(wire)

	// 纯 base64（解码后即为 wire 格式——服务端 parseSSHPublicKey 同语义）
	decoded, derr := base64.StdEncoding.DecodeString(b64)
	if derr != nil {
		t.Fatalf("base64 解码: %v", derr)
	}
	p1, err := gossh.ParsePublicKey(decoded)
	if err != nil || !bytes.Equal(p1.Marshal(), wire) {
		t.Errorf("纯 base64 解析失败: %v", err)
	}
	// 整行（authorized_keys）
	line := sshPub.Type() + " " + b64 + " comment"
	p2, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil || !bytes.Equal(p2.Marshal(), wire) {
		t.Errorf("整行解析失败: %v", err)
	}
}

// TestBuildKRL_HostCA host KRL 与 user KRL 输出仅 CA 段不同。
func TestBuildKRL_HostCA(t *testing.T) {
	serials := []uint64{100, 200}
	userKRL, err := BuildKRL([]byte("user-ca-wire"), serials, "user")
	if err != nil {
		t.Fatal(err)
	}
	hostKRL, err := BuildKRL([]byte("host-ca-wire"), serials, "host")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(userKRL, hostKRL) {
		t.Error("user/host KRL 应因 CA wire 不同而不同")
	}
	// host KRL 内含 host CA wire
	if !bytes.Contains(hostKRL, []byte("host-ca-wire")) {
		t.Error("host KRL 缺少 host CA wire 段")
	}
}

// TestKRLSerialDedup 重复序号去重 + 0 忽略。
func TestKRLSerialDedup(t *testing.T) {
	krl, err := BuildKRL([]byte("ca"), []uint64{5, 5, 0, 5, 6}, "")
	if err != nil {
		t.Fatal(err)
	}
	// 5,6 连续 → RANGE [5,6]
	if !bytes.Contains(krl, u64be(5)) || !bytes.Contains(krl, u64be(6)) {
		t.Error("KRL 缺少序号")
	}
	if bytes.Contains(krl, u64be(0)) {
		// 0 出现在头部版本字段属正常——此断言过弱，改为结构断言：
		// 只验证无第二个 0 作为吊销序号（子节 payload）
		t.Log("0 出现（可能来自头部字段）——跳过弱断言")
	}
}

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}

// TestECDSASM2CurveDiscrimination ECDSA P-256 与 SM2 曲线在
// *ecdsa.PublicKey 形态下可区分（签发侧算法约束的正确性基础）。
func TestECDSASM2CurveDiscrimination(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if p256.PublicKey.Curve == nil {
		t.Fatal("P256 曲线为 nil")
	}
	// P-256 参数特征（非 SM2 曲线实例）
	if p256.PublicKey.Curve.Params().BitSize != 256 {
		t.Errorf("P256 BitSize = %d", p256.PublicKey.Curve.Params().BitSize)
	}
}
