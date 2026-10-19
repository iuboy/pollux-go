package sshca

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 解析辅助（仅测试用）：读取 string 字段
func rdString(b []byte, off int) (val []byte, next int) {
	l := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	return b[off : off+l], off + l
}

// testCAWire 返回一个真实公钥 wire(BuildKRL 现预校验 CA wire 格式,
// 假 blob 会被拒——见第二轮审查 L-1 修复)。
func testCAWire(t *testing.T) []byte {
	t.Helper()
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp.PublicKey.Marshal()
}

func TestBuildKRL_Structure(t *testing.T) {
	// 用真实公钥 wire(审查 L1:历史用 "fake-ca-wire" 假 blob 掩盖了
	// BuildKRL 的 CA 预校验缺失——非法 wire 的 KRL 会被 OpenSSH 整体拒收,
	// sshd 对 KRL 解析错误的处理是拒绝所有密钥)。
	kp, err := GenerateED25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := kp.PublicKey.Marshal()
	krl, err := BuildKRL(ca, []uint64{42, 43}, "test krl")
	if err != nil {
		t.Fatalf("BuildKRL: %v", err)
	}
	if !bytes.HasPrefix(krl, []byte("SSHKRL\n\x00")) {
		t.Fatalf("magic 错误: %q", krl[:8])
	}
	off := 8
	if v := binary.BigEndian.Uint32(krl[off:]); v != 1 {
		t.Fatalf("format version = %d, want 1", v)
	}
	off += 4
	off += 8 // krl_version
	off += 8 // generated_date
	off += 8 // flags
	if _, off = rdString(krl, off); off == 0 {
		t.Fatal("reserved string 解析失败")
	}
	if comment, off2 := rdString(krl, off); string(comment) != "test krl" || off2 == 0 {
		t.Fatalf("comment = %q", comment)
	}
	// section tag
	off += 4 + len("test krl")
	if krl[off] != krlSectionCertificates {
		t.Fatalf("section tag = %d, want %d", krl[off], krlSectionCertificates)
	}
	off++
	sect, _ := rdString(krl, off)
	// ca_key + reserved
	caRead, so := rdString(sect, 0)
	if !bytes.Equal(caRead, ca) {
		t.Fatalf("ca_key 不匹配")
	}
	if _, so = rdString(sect, so); so == 0 {
		t.Fatal("reserved subsection 解析失败")
	}
	if sect[so] != krlCertSectionSerialRange {
		t.Fatalf("连续序号应用 RANGE 子节（0x21），got 0x%x", sect[so])
	}
	sub, _ := rdString(sect, so+1)
	min := binary.BigEndian.Uint64(sub)
	max := binary.BigEndian.Uint64(sub[8:])
	if min != 42 || max != 43 {
		t.Fatalf("range = [%d,%d], want [42,43]", min, max)
	}
}

func TestBuildKRL_DiscontinuousUsesList(t *testing.T) {
	krl, err := BuildKRL(testCAWire(t), []uint64{1, 5, 9}, "")
	if err != nil {
		t.Fatalf("BuildKRL: %v", err)
	}
	// 找到子节 tag：粗定位（跳过头部定长 36 + 2 个 string）
	off := 8 + 4 + 8*3
	if _, off = rdString(krl, off); off == 0 {
		t.Fatal("reserved")
	}
	if c, _ := rdString(krl, off); string(c) != "pollux-go SSH KRL" {
		t.Fatalf("默认 comment: %q", c)
	}
	off += 4 + len("pollux-go SSH KRL")
	off++ // section tag
	sect, _ := rdString(krl, off)
	_, so := rdString(sect, 0)
	_, so = rdString(sect, so)
	if sect[so] != krlCertSectionSerialList {
		t.Fatalf("非连续序号应用 LIST 子节（0x20），got 0x%x", sect[so])
	}
	sub, _ := rdString(sect, so+1)
	if len(sub) != 24 {
		t.Fatalf("3 个 u64 序号应 24 字节，got %d", len(sub))
	}
}

func TestBuildKRL_EmptyAndZeroSerial(t *testing.T) {
	krl, err := BuildKRL(testCAWire(t), nil, "")
	if err != nil || len(krl) < 40 {
		t.Fatalf("空吊销也应生成合法 KRL: %v len=%d", err, len(krl))
	}
	krl2, _ := BuildKRL(testCAWire(t), []uint64{0, 0, 7}, "")
	// 仅一个有效序号 7 → LIST 单元素
	if bytes.Equal(krl, krl2) {
		t.Fatal("serial=0 应被忽略，两者不应相同")
	}
}
