package cert

import "errors"

var (
	ErrNoCertificates    = errors.New("cert: at least one certificate is required")
	ErrNoRoots           = errors.New("cert: no root certificates configured")
	ErrLeafAsRoot        = errors.New("cert: leaf certificate is not a trusted root")
	ErrUnsupportedCert   = errors.New("cert: unsupported certificate type")
	ErrInvalidPEM        = errors.New("cert: failed to decode PEM block")
	ErrInvalidPrivateKey = errors.New("cert: failed to parse private key")
)
