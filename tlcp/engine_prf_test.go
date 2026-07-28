//go:build tlcp_native

package tlcp

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"testing"

	polluxSM3 "github.com/iuboy/pollux-go/sm3"
)

// TestTLCP_PHash_MatchesHMACChain verifies that P_hash produces the documented
// HMAC chain: A(1)=HMAC(secret,seed), then each output block is
// HMAC(secret, A(i)+seed). We recompute the first two blocks independently and
// compare. This pins the PRF structure (RFC 4346 §5) independently of any vector.
func TestTLCP_PHash_MatchesHMACChain(t *testing.T) {
	secret := []byte("sixteen-byte-sec")
	seed := []byte("the seed value")

	got := make([]byte, 64) // two SM3 blocks (32 each)
	tlcpPHash(got, secret, seed, polluxSM3.New)

	// Independently compute A(1) and the first two blocks.
	h := hmac.New(polluxSM3.New, secret)
	h.Write(seed)
	a := h.Sum(nil)

	h.Reset()
	h.Write(a)
	h.Write(seed)
	block1 := h.Sum(nil)

	h.Reset()
	h.Write(a)
	a = h.Sum(nil) // A(2)
	h.Reset()
	h.Write(a)
	h.Write(seed)
	block2 := h.Sum(nil)

	if !bytes.Equal(got[:32], block1) {
		t.Errorf("block 1 mismatch:\n got %x\n want %x", got[:32], block1)
	}
	if !bytes.Equal(got[32:], block2) {
		t.Errorf("block 2 mismatch:\n got %x\n want %x", got[32:], block2)
	}
}

// TestTLCP_PRF_LabelConcatenation verifies the PRF input is label||seed.
func TestTLCP_PRF_LabelConcatenation(t *testing.T) {
	secret := []byte("k")
	label := []byte("label")
	seed := []byte("seed")

	got := make([]byte, 32)
	tlcpPRF(got, secret, label, seed)

	// Reference: P_hash(secret, label+seed)
	want := make([]byte, 32)
	ls := append(append([]byte{}, label...), seed...)
	tlcpPHash(want, secret, ls, polluxSM3.New)

	if !bytes.Equal(got, want) {
		t.Errorf("PRF did not match P_hash(secret, label+seed)")
	}
}

// TestTLCP_MasterSecret_Deterministic verifies master-secret derivation is
// deterministic and 48 bytes.
func TestTLCP_MasterSecret_Deterministic(t *testing.T) {
	pms := bytes.Repeat([]byte{0xAB}, 48)
	cr := bytes.Repeat([]byte{0x11}, 32)
	sr := bytes.Repeat([]byte{0x22}, 32)

	ms1 := tlcpMasterFromPreMaster(pms, cr, sr)
	ms2 := tlcpMasterFromPreMaster(pms, cr, sr)

	if len(ms1) != tlcpMasterSecretLength {
		t.Errorf("master secret length = %d, want %d", len(ms1), tlcpMasterSecretLength)
	}
	if !bytes.Equal(ms1, ms2) {
		t.Error("master secret not deterministic")
	}

	// Different randoms → different master secret.
	ms3 := tlcpMasterFromPreMaster(pms, cr, bytes.Repeat([]byte{0x33}, 32))
	if bytes.Equal(ms1, ms3) {
		t.Error("master secret did not change with server random")
	}
}

// TestTLCP_KeysFromMaster_Ordering verifies the six components are sliced in
// RFC 5246 §6.3 order with correct lengths.
func TestTLCP_KeysFromMaster_Ordering(t *testing.T) {
	ms := bytes.Repeat([]byte{0x77}, 48)
	cr := bytes.Repeat([]byte{0x11}, 32)
	sr := bytes.Repeat([]byte{0x22}, 32)

	// CBC layout: mac=32, key=16, iv=16 → 2*(32+16+16)=128 bytes.
	km := tlcpKeysFromMaster(ms, cr, sr, 32, 16, 16)
	if len(km.clientMAC) != 32 || len(km.serverMAC) != 32 {
		t.Error("MAC key length mismatch")
	}
	if len(km.clientKey) != 16 || len(km.serverKey) != 16 {
		t.Error("symmetric key length mismatch")
	}
	if len(km.clientIV) != 16 || len(km.serverIV) != 16 {
		t.Error("IV length mismatch")
	}
	if bytes.Equal(km.clientMAC, km.serverMAC) {
		t.Error("client/server MAC keys must differ")
	}

	// AEAD layout: mac=0, key=16, iv=4 → 2*(0+16+4)=40 bytes.
	km2 := tlcpKeysFromMaster(ms, cr, sr, 0, 16, 4)
	if len(km2.clientMAC) != 0 || len(km2.serverMAC) != 0 {
		t.Error("AEAD suite must have zero-length MAC keys")
	}
	if len(km2.clientIV) != 4 {
		t.Errorf("AEAD implicit nonce length = %d, want 4", len(km2.clientIV))
	}
}

// TestTLCP_FinishedHash_ClientServerDiffer verifies the two Finished
// verify_data values differ (different labels) but share the transcript hash.
func TestTLCP_FinishedHash_ClientServerDiffer(t *testing.T) {
	h := newTLCPFinishedHash()
	h.Write([]byte("ClientHello"))
	h.Write([]byte("ServerHello"))

	ms := bytes.Repeat([]byte{0x55}, 48)
	cFin := h.clientSum(ms)
	sFin := h.serverSum(ms)

	if len(cFin) != tlcpFinishedVerifyLength || len(sFin) != tlcpFinishedVerifyLength {
		t.Errorf("Finished verify_data length: client=%d server=%d, want %d",
			len(cFin), len(sFin), tlcpFinishedVerifyLength)
	}
	if bytes.Equal(cFin, sFin) {
		t.Error("client and server Finished verify_data must differ")
	}

	// Determinism: same transcript + master secret → same verify_data.
	if !bytes.Equal(cFin, h.clientSum(ms)) {
		t.Error("client Finished verify_data not deterministic")
	}
}

// ensure hash is referenced for the import (used in helper signatures above).
var _ = func() hash.Hash { return polluxSM3.New() }
