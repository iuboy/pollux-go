module github.com/quic-go/quic-go

go 1.26

require (
	github.com/iuboy/pollux-go v0.0.0
	github.com/quic-go/go-ossfuzz-seeds v0.1.0
	github.com/quic-go/qpack v0.6.0
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emmansun/gmsm v0.44.0 // indirect
	github.com/jordanlewis/gcassert v0.0.0-20260313214104-ad3fae17affe // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
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
