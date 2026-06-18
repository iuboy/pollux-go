package tls13gm

import (
	"errors"
	"fmt"
)

// marshalClientKeyShare builds the ClientHello key_share extension data: a
// 2-byte-prefixed list of (group | key_exchange) entries (RFC 8446 §4.2.8).
func marshalClientKeyShare(group uint16, key []byte) []byte {
	entryLen := 4 + len(key)
	out := make([]byte, 2+entryLen)
	out[0] = byte(entryLen >> 8)
	out[1] = byte(entryLen)
	out[2] = byte(group >> 8)
	out[3] = byte(group)
	out[4] = byte(len(key) >> 8)
	out[5] = byte(len(key))
	copy(out[6:], key)
	return out
}

// marshalServerKeyShare builds the ServerHello key_share extension data: a
// single (group | key_exchange) entry with no list prefix.
func marshalServerKeyShare(group uint16, key []byte) []byte {
	out := make([]byte, 4+len(key))
	out[0] = byte(group >> 8)
	out[1] = byte(group)
	out[2] = byte(len(key) >> 8)
	out[3] = byte(len(key))
	copy(out[4:], key)
	return out
}

// parseKeyShareEntry parses one (group | key_exchange) entry, returning the
// group, the key exchange bytes, and the number of bytes consumed.
func parseKeyShareEntry(b []byte) (group uint16, key []byte, n int, err error) {
	if len(b) < 4 {
		return 0, nil, 0, fmt.Errorf("tls13gm: truncated key_share entry (have %d bytes)", len(b))
	}
	group = uint16(b[0])<<8 | uint16(b[1])
	keyLen := int(b[2])<<8 | int(b[3])
	if 4+keyLen > len(b) {
		return 0, nil, 0, fmt.Errorf("tls13gm: key_share key length %d out of range", keyLen)
	}
	return group, b[4 : 4+keyLen], 4 + keyLen, nil
}

// parseClientKeyShare parses the ClientHello key_share list and returns the key
// exchange bytes for the requested group, or an error if that group is absent.
func parseClientKeyShare(data []byte, wantGroup uint16) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("tls13gm: ClientHello key_share truncated at list length")
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return nil, fmt.Errorf("tls13gm: ClientHello key_share list length %d out of range", listLen)
	}
	p := data[2 : 2+listLen]
	for len(p) > 0 {
		group, key, n, err := parseKeyShareEntry(p)
		if err != nil {
			return nil, err
		}
		if group == wantGroup {
			return key, nil
		}
		p = p[n:]
	}
	return nil, fmt.Errorf("tls13gm: ClientHello key_share has no entry for group %#x", wantGroup)
}

// parseServerKeyShare parses the ServerHello single key_share entry and returns
// its key exchange bytes, verifying the group matches wantGroup.
func parseServerKeyShare(data []byte, wantGroup uint16) ([]byte, error) {
	group, key, _, err := parseKeyShareEntry(data)
	if err != nil {
		return nil, err
	}
	if group != wantGroup {
		return nil, fmt.Errorf("tls13gm: ServerHello key_share group %#x, want %#x", group, wantGroup)
	}
	return key, nil
}
