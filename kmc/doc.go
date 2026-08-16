// Package kmc provides the Key Management Center (KMC) abstraction for the
// GM dual-certificate model.
//
// In the dual-certificate model (GB/T 38636 TLCP deployments and GM/T
// enrollment flows), the ENCRYPTION certificate's private key is generated
// and escrowed by a KMC — enabling key recovery — unlike the SIGNING key,
// which is generated inside a USB token and is non-exportable.
//
// [Manager] is the minimal interface capturing that responsibility: in the
// dual-certificate enrollment flow the KMC's job is to generate the
// encryption key pair and produce a CSR the CA can sign. A production
// deployment implements it against a real KMC device via the SDF interface
// (GM/T 0018); [LocalKMC] is a local-SM2-keygen placeholder for development
// and testing.
//
// # Usage
//
//	k := kmc.NewLocalKMC()
//	kp, err := k.GenerateEncryptionKeyPair(ctx, pkix.Name{CommonName: "gm-encryption"})
//	// kp.PrivateKeyPKCS8  — encryption private key, PKCS#8 DER
//	// kp.EncryptionCSRPEM — self-signed CSR; the CA signs it to issue
//	//                       the encryption certificate
//
// The CSR subject is caller-supplied: the library imposes no naming
// convention (the historical hard-coded CN=gm-encryption lives in the
// application's enrollment assembly).
package kmc
