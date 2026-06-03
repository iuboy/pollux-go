package smx509

import (
	"testing"
)

func FuzzParseCertificate(f *testing.F) {
	// Seed with valid and invalid DER data
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x82, 0x00, 0x10, 0x30, 0x00, 0x30, 0x00, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x04, 0x00, 0x30, 0x00, 0x30, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte{0x30, 0x01, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := ParseCertificate(data)
		if err != nil {
			return
		}
		if cert == nil {
			t.Error("ParseCertificate returned nil cert without error")
		}
	})
}

func FuzzDecryptPrivateKey(f *testing.F) {
	// Seed with minimal encrypted PKCS#8 structure
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHsMIHsAgEAMIHlMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTES\nMBAGA1UECgwJU29tZS1PcmcxJTAjBgNVBAMMHGV4YW1wbGUuY29tMB4XDTI0MDEw\nMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowgdMwgdAGCSqGSIb3DQEHBqA0MDIwAgEC\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("not PEM at all"))
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nshort\n-----END ENCRYPTED PRIVATE KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		password := "test-password"
		result, err := DecryptPEMPrivateKey(data, password)
		if err != nil {
			return
		}
		if result == nil {
			t.Error("DecryptPEMPrivateKey returned nil result without error")
		}
	})
}
