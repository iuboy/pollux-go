module github.com/iuboy/pollux-go

go 1.26

require github.com/emmansun/gmsm v0.43.0

require golang.org/x/crypto v0.53.0

require (
	gitee.com/Trisia/gotlcp v1.4.5
	github.com/quic-go/quic-go v0.60.0
)

require (
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

// Route C: vendored quic-go fork. Adds a GMCryptoSetup implementation of the
// (internal) CryptoSetup interface driven by pollux-go's tls13gm handshake
// engine + quicgm packet protection. Fork source kept under quic-go/ at the
// repo root (git subtree of upstream, see quic-go/PATCHES.md). The upstream
// module name is preserved so internal imports are unchanged.
replace github.com/quic-go/quic-go => ./quic-go
