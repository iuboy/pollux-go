// Package sshca — krl.go
// SSH KRL（Known Revocation List）生成器，二进制格式遵循 OpenSSH
// PROTOCOL.krl。sshd 经 RevokedKeys/RevokedHostKeys 消费 KRL 文件，
// 是 SSH 证书吊销对服务端生效的标准通道。
//
// 格式（多字节整数一律大端；string = u32 长度 + 字节串）：
//
//	magic "SSHKRL\n\0"
//	u32  format_version = 1
//	u64  krl_version    （每次变更递增）
//	u64  generated_date （Unix 秒）
//	u64  flags = 0
//	string reserved
//	string comment
//	sections:
//	  byte  section_type（1 = CERTIFICATES）
//	  string section_data = string(ca_key_wire) + string(reserved="")
//	              + 子节: byte 0x20(SERIAL_LIST) + string(u64 serial*)
//	                      | byte 0x21(SERIAL_RANGE) + string(u64 min + u64 max)
package sshca

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	krlMagic = "SSHKRL\n\x00"

	krlSectionCertificates = 1

	krlCertSectionSerialList  = 0x20
	krlCertSectionSerialRange = 0x21
)

// BuildKRL 生成 KRL 二进制。caKeyWire 为对应 CA 公钥的 SSH wire 序列化
// （cert.Key.Marshal()）；serials 为被吊销的证书序号列表（去重/忽略 0）。
// caKeyWire 为空表示适用于所有 CA（宽松，不推荐）。
func BuildKRL(caKeyWire []byte, serials []uint64, comment string) ([]byte, error) {
	now := uint64(time.Now().Unix())
	// krl_version：每次生成单调递增（随机高 32 位 + 时间戳低位，
	// 避免时钟回拨导致"新 KRL 版本更旧"）
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("生成 KRL 版本随机数失败: %w", err)
	}
	krlVersion := uint64(binary.BigEndian.Uint32(nonce[:]))<<32 | (now & 0xFFFFFFFF)

	buf := make([]byte, 0, 256)
	buf = append(buf, krlMagic...)
	buf = beU32(buf, 1) // format version
	buf = beU64(buf, krlVersion)
	buf = beU64(buf, now)
	buf = beU64(buf, 0)      // flags
	buf = beString(buf, nil) // reserved
	if comment == "" {
		comment = "mekbuda SSH KRL"
	}
	buf = beString(buf, []byte(comment))

	// CERTIFICATES 节
	sect := make([]byte, 0, 128)
	sect = beString(sect, caKeyWire)
	sect = beString(sect, nil) // reserved

	dedup := make(map[uint64]struct{}, len(serials))
	var uniq []uint64
	for _, s := range serials {
		if s == 0 {
			continue // 0 = 历史记录未关联 serial（按 KeyID 吊销仍生效）
		}
		if _, ok := dedup[s]; !ok {
			dedup[s] = struct{}{}
			uniq = append(uniq, s)
		}
	}
	if len(uniq) == 0 {
		// 无吊销也生成合法空 KRL（仅 CA 绑定节），便于 sshd 空挂载
		buf = append(buf, krlSectionCertificates)
		buf = beString(buf, sect)
		return buf, nil
	}

	if len(uniq) == 1 {
		// SERIAL_LIST
		sub := beU64(nil, uniq[0])
		sect = append(sect, krlCertSectionSerialList)
		sect = beString(sect, sub)
	} else {
		// 多序号合并为 min..max 连续区间当且仅当完全连续，否则用 LIST
		minS, maxS := uniq[0], uniq[0]
		continuous := true
		for i, s := range uniq {
			if s < minS {
				minS = s
			}
			if s > maxS {
				maxS = s
			}
			if i > 0 && s != uniq[i-1]+1 {
				continuous = false
			}
		}
		if continuous {
			sub := beU64(nil, minS)
			sub = beU64(sub, maxS)
			sect = append(sect, krlCertSectionSerialRange)
			sect = beString(sect, sub)
		} else {
			var sub []byte
			for _, s := range uniq {
				sub = beU64(sub, s)
			}
			sect = append(sect, krlCertSectionSerialList)
			sect = beString(sect, sub)
		}
	}

	buf = append(buf, krlSectionCertificates)
	buf = beString(buf, sect)
	return buf, nil
}

func beU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

func beU64(b []byte, v uint64) []byte {
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], v)
	return append(b, t[:]...)
}

func beString(b []byte, v []byte) []byte {
	b = beU32(b, uint32(len(v)))
	return append(b, v...)
}
