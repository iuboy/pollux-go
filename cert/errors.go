package cert

import "errors"

// Sentinel errors returned by certificate loading, parsing, and verification.
// They wrap the underlying cause via errors.Is so callers can branch on type.
var (
	// ErrNoCertificates is returned when no certificate is provided where at least one is required.
	ErrNoCertificates = errors.New("cert: at least one certificate is required")
	// ErrNoRoots is returned when no root certificates are configured for verification.
	ErrNoRoots = errors.New("cert: no root certificates configured")
	// ErrLeafAsRoot is returned when a leaf certificate is treated as a trusted root.
	ErrLeafAsRoot = errors.New("cert: leaf certificate is not a trusted root")
	// ErrUnsupportedCert is returned for a certificate type this package cannot handle.
	ErrUnsupportedCert = errors.New("cert: unsupported certificate type")
	// ErrInvalidPEM is returned when a PEM block cannot be decoded.
	ErrInvalidPEM = errors.New("cert: failed to decode PEM block")
	// ErrInvalidPrivateKey is returned when a private key cannot be parsed.
	ErrInvalidPrivateKey = errors.New("cert: failed to parse private key")
)
