module github.com/quic-go/quic-go

go 1.26.0

require (
	github.com/iuboy/pollux-go v0.0.0
	github.com/quic-go/go-ossfuzz-seeds v0.1.0
	github.com/quic-go/qpack v0.6.0
	github.com/stretchr/testify v1.12.1
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/emmansun/gmsm v0.44.1 // indirect
	github.com/jordanlewis/gcassert v0.0.0-20250430164644-389ef753e22e // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

tool (
	github.com/jordanlewis/gcassert/cmd/gcassert
	go.uber.org/mock/mockgen
)

// Route C: this fork consumes pollux-go's tls13gm handshake engine to implement
// GMCryptoSetup. This creates a module-level cycle (pollux-go requires this fork
// via the repo-root replace; this fork requires pollux-go). Go permits module
// cycles as long as there is no package-level import cycle — tls13gm/gmsm never
// import quic-go, so the cycle is safe. The local replace resolves pollux-go to
// the repo root during development.
replace github.com/iuboy/pollux-go => ..
