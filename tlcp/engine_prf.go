package tlcp

import (
	"crypto/hmac"
	"hash"

	polluxSM3 "github.com/iuboy/pollux-go/sm3"
)

// This file implements the TLCP pseudo-random function (PRF) and key derivation
// per GB/T 38636-2020 §6.5. TLCP reuses the TLS 1.2 PRF structure (RFC 5246 §5)
// but with SM3 as the hash, i.e. HMAC-SM3 based P_hash. This is unrelated to the
// TLS 1.3 HKDF-Expand-Label used by tls13gm.
//
// Reference: gotlcp/tlcp/prf.go (logic consulted, independently written).

const (
	tlcpMasterSecretLength   = 48 // master secret size, GB/T 38636-2020 §6.5.1
	tlcpFinishedVerifyLength = 12 // verify_data size in a Finished message
)

// TLS 1.2 PRF labels (identical to RFC 5246; TLCP reuses them verbatim).
var (
	tlcpMasterSecretLabel  = []byte("master secret")
	tlcpKeyExpansionLabel  = []byte("key expansion")
	tlcpClientFinishedLabel = []byte("client finished")
	tlcpServerFinishedLabel = []byte("server finished")
)

// tlcpPHash implements P_hash from RFC 5246 §5: HMAC output blocks are
// concatenated to fill the result buffer. (TLCP uses a single-hash PRF
// with no secret-splitting XOR step, unlike TLS 1.0/1.1.)
func tlcpPHash(result, secret, seed []byte, newHash func() hash.Hash) {
	h := hmac.New(newHash, secret)
	h.Write(seed)
	a := h.Sum(nil) // A(1) = HMAC(secret, seed)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil) // HMAC(secret, A(i) + seed)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil) // A(i+1) = HMAC(secret, A(i))
	}
}

// tlcpPRF is the TLS 1.2 PRF keyed on SM3: PRF(secret, label, seed) =
// P_hash(secret, label + seed). See RFC 5246 §5.
func tlcpPRF(result, secret, label, seed []byte) {
	// The PRF input is the concatenation of the label and the seed (RFC 5246 §5).
	labelAndSeed := make([]byte, 0, len(label)+len(seed))
	labelAndSeed = append(labelAndSeed, label...)
	labelAndSeed = append(labelAndSeed, seed...)
	tlcpPHash(result, secret, labelAndSeed, polluxSM3.New)
}

// tlcpMasterFromPreMaster derives the 48-byte master secret from the
// pre-master secret and the two hello randoms (GB/T 38636-2020 §6.5.1).
func tlcpMasterFromPreMaster(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, tlcpMasterSecretLength)
	tlcpPRF(masterSecret, preMasterSecret, tlcpMasterSecretLabel, seed)
	return masterSecret
}

// tlcpKeyMaterial holds the six derived traffic-key components produced by
// key expansion (GB/T 38636-2020 §6.5.2). The iv slices are empty for AEAD
// suites (which carry only a 4-byte implicit nonce prefix in ivLen).
type tlcpKeyMaterial struct {
	clientMAC, serverMAC []byte
	clientKey, serverKey []byte
	clientIV, serverIV   []byte
}

// tlcpKeysFromMaster expands the master secret into the traffic keys.
// macLen/keyLen/ivLen are determined by the negotiated cipher suite:
//   - SM4-CBC+HMAC-SM3: macLen=32, keyLen=16, ivLen=16
//   - SM4-GCM (AEAD):   macLen=0,  keyLen=16, ivLen=4 (implicit nonce prefix)
func tlcpKeysFromMaster(masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) tlcpKeyMaterial {
	// Note the seed order for key expansion is server_random + client_random
	// (opposite of master-secret derivation). RFC 5246 §6.3.
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	raw := make([]byte, n)
	tlcpPRF(raw, masterSecret, tlcpKeyExpansionLabel, seed)

	off := 0
	slice := func(length int) []byte {
		s := raw[off : off+length]
		off += length
		return s
	}
	// Order per RFC 5246 §6.3: client_write_MAC_key, server_write_MAC_key,
	// client_write_key, server_write_key, client_write_IV, server_write_IV.
	return tlcpKeyMaterial{
		clientMAC: slice(macLen),
		serverMAC: slice(macLen),
		clientKey: slice(keyLen),
		serverKey: slice(keyLen),
		clientIV:  slice(ivLen),
		serverIV:  slice(ivLen),
	}
}

// tlcpFinishedHash accumulates the SM3 hash of the handshake transcript and
// produces the Finished verify_data. TLCP uses a single SM3 transcript hash
// (unlike TLS 1.0/1.1's MD5+SHA1 pair).
type tlcpFinishedHash struct {
	msgHash hash.Hash
}

func newTLCPFinishedHash() *tlcpFinishedHash {
	return &tlcpFinishedHash{msgHash: polluxSM3.New()}
}

func (h *tlcpFinishedHash) Write(msg []byte) (int, error) {
	return h.msgHash.Write(msg)
}

// sum returns the current handshake transcript hash.
func (h *tlcpFinishedHash) sum() []byte {
	return h.msgHash.Sum(nil)
}

// clientSum returns the verify_data for the client's Finished message:
// PRF(master_secret, "client finished", SM3(handshake_messages)).
func (h *tlcpFinishedHash) clientSum(masterSecret []byte) []byte {
	out := make([]byte, tlcpFinishedVerifyLength)
	tlcpPRF(out, masterSecret, tlcpClientFinishedLabel, h.sum())
	return out
}

// serverSum returns the verify_data for the server's Finished message:
// PRF(master_secret, "server finished", SM3(handshake_messages)).
func (h *tlcpFinishedHash) serverSum(masterSecret []byte) []byte {
	out := make([]byte, tlcpFinishedVerifyLength)
	tlcpPRF(out, masterSecret, tlcpServerFinishedLabel, h.sum())
	return out
}
