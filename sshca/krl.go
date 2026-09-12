// See doc.go for the package documentation (godoc convention).
// This file: SSH KRL (key revocation list) generation.
package sshca

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	xssh "golang.org/x/crypto/ssh"
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
	// 预校验 CA wire 格式:结构非法的 KRL 会被 OpenSSH 整体拒收,而 sshd 的
	// auth_key_is_revoked 对 KRL 解析错误的处理是拒绝所有密钥——一次
	// base64/wire 混用即导致全网 SSH 认证锁死,故在生成端拦截。
	if len(caKeyWire) > 0 {
		if _, err := xssh.ParsePublicKey(caKeyWire); err != nil {
			return nil, fmt.Errorf("caKeyWire 不是合法的 SSH 公钥 wire 格式: %w", err)
		}
	}
	now := uint64(time.Now().Unix())
	// krl_version：随机唯一版本（同 ssh-keygen 的 arc4random_buf 做法）。
	// 注:随机高位不保证单调——sshd 仅记录该值不做比较,单调性无消费方;
	// 此前注释声称的"防时钟回拨的单调递增"与实现不符,已更正。
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
		comment = "pollux-go SSH KRL"
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
