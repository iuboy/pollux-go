## pollux-go build & test targets
##
## Usage:
##   make test        # run all unit + integration tests
##   make cover       # coverage with -coverpkg (counts test/ integration coverage)
##   make cover-html  # same, rendered as HTML (opens coverage.html)
##   make vet         # go vet
##   make build       # build all packages

GO ?= go
COVER_PROFILE ?= coverage.out
COVER_HTML ?= coverage.html

.PHONY: test cover cover-html vet build clean fmt

## build: compile all packages
build:
	$(GO) build ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## test: run all tests (race detector enabled)
test:
	$(GO) test -race ./...

## cover: line coverage counting integration tests in test/ against every package.
## The default `go test -cover ./...` only credits each package with its own
## _test.go files; protocol packages (tlcp, http, smx509) are exercised by the
## integration suite under test/, so -coverpkg=./... is required to reflect the
## true coverage of those wrapper layers.
cover:
	$(GO) test -race -coverprofile=$(COVER_PROFILE) -coverpkg=./... ./...
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
