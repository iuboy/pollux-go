// Package sshca implements an SSH certificate authority: user/host
// certificate signing, certificate validation, and KRL (key revocation
// list) generation.
//
// The signing model follows OpenSSH PROTOCOL.certkeys: an [Authority] holds
// two [CertificateSigner]s (user + host) built from CA key pairs; requests
// are expressed as [CertificateRequest] and validated before signing
// (principal whitelist, validity window, max-duration enforcement). Default
// permission sets mirror ssh-keygen conventions (full permit-* for user
// certificates; none for host certificates, which must not carry permit-*
// extensions).
//
// # Revocation
//
// [BuildKRL] produces a binary SSH KRL revoking certificates by serial
// number under one CA key. golang.org/x/crypto/ssh can PARSE KRLs but
// cannot generate them — this is the scarce capability the package adds.
// Serial lists are deduplicated and encoded as packed continuation-style
// lists per the KRL wire format.
//
// # Validation
//
// [Authority.ValidateCertificate] performs full cryptographic verification
// via ssh.CertChecker (CA key byte-match, signature, critical options,
// validity window) and rejects unrecognized critical options — user
// certificates only support force-command and source-address.
//
// Key persistence (encrypted at-rest storage) is deliberately NOT part of
// this package: combine [KeyPairFromRawKey] with
// [github.com/iuboy/pollux-go/keycrypt] at the application layer.
package sshca
