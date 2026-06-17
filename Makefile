# PenRUSH — developer make targets. Thin wrappers over the toolchain + build.sh
# so `make verify-reproducible` proves the §H.1 byte-identical-build property
# locally, matching what the release pipeline enforces in CI.
#
# No third-party tooling: only `go` and POSIX sh (build.sh). On Windows, run
# these under Git Bash, or invoke build.sh / go directly.

.POSIX:
.PHONY: all build test vet verify-reproducible ci clean

GO ?= go

all: vet test build

# Standard reproducible build for the host platform (delegates to build.sh).
build:
	sh build.sh build

# The full local quality gate that CI mirrors.
test:
	GOFLAGS=-mod=readonly $(GO) test ./...

vet:
	GOFLAGS=-mod=readonly $(GO) vet ./...

# Prove determinism: build twice, assert identical SHA-256 (exit 1 on drift).
verify-reproducible:
	sh build.sh verify-reproducible

# Local approximation of the CI pipeline (vet + build + test + repro proof).
ci: vet build test verify-reproducible

clean:
	rm -rf dist
