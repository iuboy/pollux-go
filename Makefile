## pollux-go build & test targets
##
## Usage:
##   make test             # run all tests incl. integration (race detector on)
##   make test-unit        # run only unit/functional tests (skips //go:build integration)
##   make test-integration # run only the integration suite (-tags=integration)
##   make cover            # coverage with -coverpkg (counts test/ integration coverage)
##   make cover-html       # same, rendered as HTML (opens coverage.html)
##   make vet              # go vet
##   make gosec            # security scan (excludes reviewed-as-safe rules)
##   make build            # build all packages
##
## Integration tests are gated behind the `integration` build tag because they
## need external resources (Tongsuo binary, real sockets, RFC 8998 interop).
## `make test` and `make test-integration` enable it; `make test-unit` does not.

GO ?= go
COVER_PROFILE ?= coverage.out
COVER_HTML ?= coverage.html

# gosec rules excluded after manual review (see .gosec.json for the rationale):
#   G104 — ignored errors are conn.Close() on already-failed TLS handshakes
#   G115 — integer narrowing in protocol fixed-width field encoding (big-endian
#          length/version/cipher bytes, nonce counter XOR); values are protocol-bounded
#   G304 — path inclusion from configurable cert/key paths (caller-controlled config)
#   G401/G405/G501/G502/G505 — legacy crypto (MD5/SHA1/DES) used only by smx509
#          PBE/legacy-cert compatibility paths
#   G402  — InsecureSkipVerify is a caller config flag with fail-closed defaults
# Listed on the command line because gosec dev ignores the config's "exclude" key.
GOSEC_EXCLUDE ?= G104,G115,G304,G401,G402,G405,G501,G502,G505

.PHONY: test test-unit test-integration cover cover-html vet gosec build clean fmt

## build: compile all packages
build:
	$(GO) build ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## gosec: run gosec, excluding reviewed-as-safe rules (see GOSEC_EXCLUDE above).
## G103 (memsecure unsafe for key zeroing) remains reported by design — it must
## stay visible so new unsafe uses are noticed.
gosec:
	gosec -exclude $(GOSEC_EXCLUDE) -quiet ./...

## test: run all tests incl. integration (race detector enabled).
test:
	$(GO) test -race -tags=integration ./...

## test-unit: run unit + functional tests only (integration files are excluded
## by the `integration` build tag). Fast feedback loop for day-to-day work.
test-unit:
	$(GO) test -race ./...

## test-integration: run only the integration suite (files with //go:build
## integration). Requires the Tongsuo binary at /opt/local/tongsuo for the
## cross-library interop tests; missing deps are reported via t.Skip.
test-integration:
	$(GO) test -race -tags=integration ./...

## cover: line coverage counting integration tests in test/ against every package.
## The default `go test -cover ./...` only credits each package with its own
## _test.go files; protocol packages (tlcp, http, smx509) are exercised by the
## integration suite under test/, so -coverpkg=./... is required to reflect the
## true coverage of those wrapper layers.
cover:
	$(GO) test -race -tags=integration -coverprofile=$(COVER_PROFILE) -coverpkg=./... ./...
	@echo "--- Total coverage (integration-inclusive) ---"
	@$(GO) tool cover -func=$(COVER_PROFILE) | tail -1
	@echo "--- Per-package aggregate (avg of function coverage) ---"
	@$(GO) tool cover -func=$(COVER_PROFILE) \
		| awk -F'\t' '/github.com\/iuboy\/pollux-go\// { \
			path=$$1; sub(/github.com\/iuboy\/pollux-go\//, "", path); \
			split(path, a, "/"); pkg=a[1]; \
			if (a[1]=="internal") pkg=a[1]"/"a[2]; \
			pct=$$NF; sub(/%/, "", pct); \
			sum[pkg]+=pct; n[pkg]++; \
		} END { \
			for (p in n) printf "  %-18s %.1f%%\n", p, sum[p]/n[p]; \
		}' | sort

## cover-html: render coverage as HTML
cover-html: cover
	$(GO) tool cover -html=$(COVER_PROFILE) -o $(COVER_HTML)
	@echo "Coverage report: $(COVER_HTML)"

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...

## clean: remove coverage artifacts
clean:
	rm -f $(COVER_PROFILE) $(COVER_HTML)
