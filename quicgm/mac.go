package quicgm

import (
	"crypto/hmac"
	"crypto/subtle"

	"github.com/ycq/pollux/internal/memsecure"
	"github.com/ycq/pollux/sm3"
)

// MACSM3 computes an HMAC-SM3 tag for the given data.
func MACSM3(key, data []byte) []byte {
	h := hmac.New(sm3.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyMACSM3 verifies an HMAC-SM3 tag in constant time.
func VerifyMACSM3(key, data, mac []byte) bool {
	expected := MACSM3(key, data)
	return subtle.ConstantTimeCompare(expected, mac) == 1
}

// ZeroKeys securely zeroes a SessionKeys structure.
func ZeroKeys(keys *SessionKeys) {
	if keys == nil {
		return
	}
	memsecure.ZeroBytes(keys.HMACKey)
	memsecure.ZeroBytes(keys.SM4Key)
	keys.HMACKey = nil
	keys.SM4Key = nil
	keys.KeyID = ""
	keys.SessionID = ""
}
