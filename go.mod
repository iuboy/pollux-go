module github.com/iuboy/pollux-go

go 1.26.0

require (
	github.com/emmansun/gmsm v0.44.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/quic-go/quic-go v0.61.0
	golang.org/x/crypto v0.57.0
)

require (
	github.com/stretchr/testify v1.12.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// Route C: vendored quic-go fork. Adds a GMCryptoSetup implementation of the
// (internal) CryptoSetup interface driven by pollux-go's tls13gm handshake
// engine + quicgm packet protection. Fork source kept under quic-go/ at the
// repo root (git subtree of upstream, see quic-go/PATCHES.md). The upstream
// module name is preserved so internal imports are unchanged.
replace github.com/quic-go/quic-go => ./quic-go
