//go:build tlcp_native

package tlcp

import (
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"hash"

	polluxSM3 "github.com/iuboy/pollux-go/sm3"
	polluxSM4 "github.com/iuboy/pollux-go/sm4"
)

// This file implements the TLCP record-layer cipher suites per GB/T 38636-2020
// §6.4.5. Only the four SM4/SM3 suites are in scope for the native engine:
//
//   - ECC_SM4_CBC_SM3   (0xe013): SM2-PKE key exchange + SM4-CBC + HMAC-SM3
//   - ECC_SM4_GCM_SM3   (0xe053): SM2-PKE key exchange + SM4-GCM (prefix-nonce AEAD)
//   - ECDHE_SM4_*_SM3   (0xe011/0xe051): SM2 MQV — out of scope (Phase 7+)
//
// The AEAD variant uses a prefix-nonce construction (RFC 5116 style): a 4-byte
// implicit nonce (from key expansion) concatenated with an 8-byte explicit
// nonce carried in the record. This is NOT the TLS 1.3 XOR-nonce used by
// tls13gm.AEAD.
//
// Reference: gotlcp/tlcp/cipher_suites.go (logic consulted, independently written).

// tlcpAEADNonceLength is the full 12-byte GCM nonce size (RFC 5116).
const tlcpAEADNonceLength = 12

// tlcpNoncePrefixLength is the implicit-nonce prefix length (bytes of IV from
// key expansion that seed each AEAD nonce).
const tlcpNoncePrefixLength = 4

// tlcpCipherFlags characterizes a cipher suite for selection logic.
type tlcpCipherFlags uint8

const (
	tlcpFlagECDHE tlcpCipherFlags = 1 << iota // suite uses ECDHE key exchange
	tlcpFlagECSign                            // suite involves an ECDSA/SM2 signature cert
)

// tlcpCipherSuite describes a negotiated TLCP cipher suite: its key-exchange
// factory, record cipher/MAC or AEAD construction, and material lengths.
type tlcpCipherSuite struct {
	id     uint16
	keyLen int // symmetric key length (SM4 = 16)
	macLen int // MAC key length (HMAC-SM3 = 32; 0 for AEAD)
	ivLen  int // IV/implicit-nonce length (CBC=16, GCM=4)
	flags  tlcpCipherFlags
}

// isAEAD reports whether this suite uses AEAD (GCM) rather than CBC+MAC.
func (s *tlcpCipherSuite) isAEAD() bool { return s.macLen == 0 }

// tlcpCipherSuites is the registry of implemented suites keyed by suite ID.
// ECDHE entries are placeholders until Phase 7 — they are present so the table
// is complete and IDs resolve, but the keyAgreement factory is not wired here.
var tlcpCipherSuites = map[uint16]*tlcpCipherSuite{
	SuiteECC_SM2_SM4_GCM_SM3:   {id: SuiteECC_SM2_SM4_GCM_SM3, keyLen: 16, macLen: 0, ivLen: tlcpNoncePrefixLength, flags: tlcpFlagECSign},
	SuiteECC_SM2_SM4_CBC_SM3:   {id: SuiteECC_SM2_SM4_CBC_SM3, keyLen: 16, macLen: 32, ivLen: 16, flags: tlcpFlagECSign},
	SuiteECDHE_SM2_SM4_GCM_SM3: {id: SuiteECDHE_SM2_SM4_GCM_SM3, keyLen: 16, macLen: 0, ivLen: tlcpNoncePrefixLength, flags: tlcpFlagECSign | tlcpFlagECDHE},
	SuiteECDHE_SM2_SM4_CBC_SM3: {id: SuiteECDHE_SM2_SM4_CBC_SM3, keyLen: 16, macLen: 32, ivLen: 16, flags: tlcpFlagECSign | tlcpFlagECDHE},
}

// tlcpLookupCipherSuite returns the suite descriptor for id, or nil if unknown.
func tlcpLookupCipherSuite(id uint16) *tlcpCipherSuite {
	return tlcpCipherSuites[id]
}

// tlcpMutualCipherSuite selects the first suite from preference that the peer
// also advertised. Returns nil if no overlap.
func tlcpMutualCipherSuite(preference, peerIDs []uint16) *tlcpCipherSuite {
	for _, id := range preference {
		candidate := tlcpCipherSuites[id]
		if candidate == nil {
			continue
		}
		for _, peerID := range peerIDs {
			if id == peerID {
				return candidate
			}
		}
	}
	return nil
}

// --- CBC + HMAC-SM3 record cipher ---

// tlcpCBCStream wraps an SM4-CBC block mode (encrypter or decrypter) for the
// MAC-then-encrypt record framing of TLCP's CBC suites.
type tlcpCBCStream struct {
	mode cipher.BlockMode
}

func newTLCPCBCEncrypter(key, iv []byte) (*tlcpCBCStream, error) {
	mode, err := polluxSM4.NewCBCEncrypter(key, iv)
	if err != nil {
		return nil, err
	}
	return &tlcpCBCStream{mode: mode}, nil
}

func newTLCPCBCDecrypter(key, iv []byte) (*tlcpCBCStream, error) {
	mode, err := polluxSM4.NewCBCDecrypter(key, iv)
	if err != nil {
		return nil, err
	}
	return &tlcpCBCStream{mode: mode}, nil
}

func (s *tlcpCBCStream) CryptBlocks(dst, src []byte) { s.mode.CryptBlocks(dst, src) }
func (s *tlcpCBCStream) BlockSize() int              { return s.mode.BlockSize() }

// tlcpHMACSM3 returns an HMAC-SM3 instance keyed with the given MAC key.
func tlcpHMACSM3(key []byte) hash.Hash {
	return hmac.New(polluxSM3.New, key)
}

// tlcpRecordMAC computes the TLS 1.0-style MAC over the record header
// (sequence number + type + version + length) and payload. Used by CBC suites.
// header is the 5-byte TLCP record header; seq is the 8-byte sequence number.
func tlcpRecordMAC(h hash.Hash, out, seq, header, payload []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(payload)
	return h.Sum(out)
}

// --- SM4-GCM prefix-nonce AEAD ---

// tlcpPrefixNonceAEAD wraps an SM4-GCM AEAD so that each Seal/Open combines a
// fixed 4-byte implicit nonce (from key expansion) with an 8-byte explicit
// nonce carried in the record. The full nonce is implicit || explicit (12 bytes).
// This matches RFC 5116 / GB/T 38636-2020 §6.4.5.6, and differs from the
// TLS 1.3 XOR-nonce in tls13gm.AEAD.
type tlcpPrefixNonceAEAD struct {
	nonce [tlcpAEADNonceLength]byte // [0:4] implicit, [4:12] filled per call
	aead  cipher.AEAD
}

// newTLCPAEADSM4GCM builds an SM4-GCM AEAD with the given key and 4-byte
// implicit nonce prefix.
func newTLCPAEADSM4GCM(key, implicitNonce []byte) (*tlcpPrefixNonceAEAD, error) {
	if len(implicitNonce) != tlcpNoncePrefixLength {
		return nil, fmt.Errorf("tlcp: implicit nonce length %d, want %d", len(implicitNonce), tlcpNoncePrefixLength)
	}
	block, err := polluxSM4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, tlcpAEADNonceLength)
	if err != nil {
		return nil, err
	}
	ret := &tlcpPrefixNonceAEAD{aead: aead}
	copy(ret.nonce[:tlcpNoncePrefixLength], implicitNonce)
	return ret, nil
}

// ExplicitNonceSize returns the number of explicit nonce bytes carried in each
// record (8). Callers transmit these and feed them back to Open.
func (f *tlcpPrefixNonceAEAD) ExplicitNonceSize() int { return tlcpAEADNonceLength - tlcpNoncePrefixLength }

// Overhead is the AEAD tag length appended to each sealed record.
func (f *tlcpPrefixNonceAEAD) Overhead() int { return f.aead.Overhead() }

// Seal encrypts plaintext under the implicit prefix + the per-record explicit
// nonce. additionalData is the TLCP record header.
func (f *tlcpPrefixNonceAEAD) Seal(out, explicitNonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[tlcpNoncePrefixLength:], explicitNonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

// Open decrypts. explicitNonce is the 8 bytes read from the record.
func (f *tlcpPrefixNonceAEAD) Open(out, explicitNonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[tlcpNoncePrefixLength:], explicitNonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}
