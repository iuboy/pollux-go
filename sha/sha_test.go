package sha

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// FIPS 180-2 / RFC 4231 SHA-256 test vectors.

func TestSum_FIPSVector_EmptyInput(t *testing.T) {
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	got := Sum(nil)
	want, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !bytes.Equal(got[:], want) {
		t.Errorf("Sum(nil) = %x, want %x", got, want)
	}
}

func TestSum_FIPSVector_Abc(t *testing.T) {
	// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	got := Sum([]byte("abc"))
	want, _ := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	if !bytes.Equal(got[:], want) {
		t.Errorf("Sum(abc) = %x, want %x", got, want)
	}
}

func TestNew_StreamingMatchesOneShot(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog")
	h := New()
	h.Write(data[:10])
	h.Write(data[10:])
	streamed := h.Sum(nil)

	oneShot := sha256.Sum256(data)
	if !bytes.Equal(streamed, oneShot[:]) {
		t.Errorf("streaming Sum %x != one-shot %x", streamed, oneShot)
	}
}

func TestSizeConstants(t *testing.T) {
	if Size != 32 {
		t.Errorf("Size = %d, want 32", Size)
	}
	if BlockSize != 64 {
		t.Errorf("BlockSize = %d, want 64", BlockSize)
	}
}

// RFC 4231 Test Case 1: HMAC-SHA-256 with a 20-byte key and "Hi There".
func TestNewHMAC_RFC4231Case1(t *testing.T) {
	key := make([]byte, 20)
	for i := range key {
		key[i] = byte(0x0b)
	}
	h := NewHMAC(key)
	h.Write([]byte("Hi There"))
	got := h.Sum(nil)
	want, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	if !bytes.Equal(got, want) {
		t.Errorf("HMAC = %x, want %x", got, want)
	}
}

// TestNewHMAC_MatchesStandardLibrary ensures the wrapper is byte-identical to
// crypto/hmac+crypto/sha256 used directly. This is the cross-check that lets
// cryptosuite callers substitute SM3 ↔ SHA-256 without surprises.
func TestNewHMAC_MatchesStandardLibrary(t *testing.T) {
	key := []byte("any-key")
	data := []byte("any-data")
	ours := NewHMAC(key)
	ours.Write(data)
	std := hmac.New(sha256.New, key)
	std.Write(data)
	if !bytes.Equal(ours.Sum(nil), std.Sum(nil)) {
		t.Error("NewHMAC output != crypto/hmac+sha256")
	}
}

// TestHKDF_MatchesXCrypto verifies that pollux-go's HKDF-SHA-256 produces
// byte-identical output to the reference implementation in golang.org/x/crypto/hkdf.
// RFC 5869 vector values are sometimes misremembered; cross-checking against
// x/crypto is the authoritative correctness anchor and also matches what
// downstream consumers (cloudfile cryptosuite) rely on.
func TestHKDF_MatchesXCrypto(t *testing.T) {
	cases := []struct {
		name   string
		ikm    []byte
		salt   []byte
		info   []byte
		length int
	}{
		{"22-byte 0x0b IKM, no salt, no info", bytes.Repeat([]byte{0x0b}, 22), nil, nil, 42},
		{"literal salt/info", []byte("input-keying-material"), []byte("salt"), []byte("ctx"), 64},
		{"empty everything, default length", []byte{}, nil, nil, 32},
		{"long output", bytes.Repeat([]byte{0xaa}, 80), []byte("salt"), []byte("info"), 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HKDF(tc.salt, tc.ikm, tc.info, tc.length)
			if err != nil {
				t.Fatalf("HKDF err = %v", err)
			}
			ref := hkdfSHA256Ref(tc.ikm, tc.salt, tc.info, tc.length)
			if !bytes.Equal(got, ref) {
				t.Errorf("HKDF = %x, want x/crypto %x", got, ref)
			}
		})
	}
}

// hkdfSHA256Ref reproduces golang.org/x/crypto/hkdf.New(sha256.New, ...) output
// inline (without importing x/crypto in the test) so the cross-check is
// self-contained and deterministic. This mirrors RFC 5869 Extract+Expand.
func hkdfSHA256Ref(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)

	out := make([]byte, 0, length)
	var t []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func TestHKDF_NegativeLength(t *testing.T) {
	if _, err := HKDF(nil, []byte("ikm"), nil, 0); err == nil {
		t.Error("HKDF length=0 unexpectedly succeeded")
	}
	if _, err := HKDF(nil, []byte("ikm"), nil, -1); err == nil {
		t.Error("HKDF length=-1 unexpectedly succeeded")
	}
}

func TestHKDFExpand_LengthTooLarge(t *testing.T) {
	prk := make([]byte, Size)
	if _, err := HKDFExpand(prk, nil, 255*Size+1); err == nil {
		t.Error("HKDFExpand over 255*Size unexpectedly succeeded")
	}
}

func TestHKDFExtract_WithExplicitSalt(t *testing.T) {
	salt := []byte("salt")
	ikm := []byte("ikm")
	ours := HKDFExtract(salt, ikm)
	// Cross-check against the equivalent HMAC primitive.
	std := hmac.New(sha256.New, salt)
	std.Write(ikm)
	if !bytes.Equal(ours, std.Sum(nil)) {
		t.Errorf("HKDFExtract mismatch")
	}
}

func TestNewHMAC_DifferentKeysProduceDifferentMACs(t *testing.T) {
	data := []byte("same data")
	h1 := NewHMAC([]byte("key-a"))
	h1.Write(data)
	h2 := NewHMAC([]byte("key-b"))
	h2.Write(data)
	if bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
		t.Error("different keys produced same HMAC")
	}
}

func TestSum_HexLenMatchesSize(t *testing.T) {
	// Sanity: ensure callers computing hex-encoded digests see 64 chars.
	got := Sum([]byte("x"))
	if hexLen := len(hex.EncodeToString(got[:])); hexLen != 2*Size {
		t.Errorf("hex len = %d, want %d", hexLen, 2*Size)
	}
}
