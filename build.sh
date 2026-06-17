#!/usr/bin/env sh
# PenRUSH local build + reproducible-build verifier (architecture §H.1).
#
# This script encodes the SAME deterministic build invocation the SLSA Go
# builder runs in CI (see .slsa-goreleaser/<os>-<arch>.yml), so a developer can
# prove locally that the build is byte-for-byte reproducible — the property the
# two-runner CI job (.github/workflows/release.yml) enforces on every release.
#
# Reproducibility pillars (go.dev/blog/rebuild):
#   CGO_ENABLED=0  +  -trimpath  +  -buildvcs=false
#     +  -ldflags "-s -w -buildid= -X main.version -X main.commit"
# -buildvcs=false drops Go's automatic VCS stamping so reproducibility does not
# depend on .git presence/state. A build timestamp is deliberately NOT embedded.
#
# Subcommands:
#   build              build penrush for the host OS/arch into ./dist
#   verify-reproducible  build twice, assert identical SHA-256 (exit 1 on drift)
#
# Zero third-party tools: uses only `go`, `sha256sum` (or `shasum -a 256`), sh.
# Pin the version/commit explicitly to defeat any host-derived nondeterminism.

set -eu

# --- Resolve version + commit (deterministic, overridable) ---
# VERSION/COMMIT may be supplied by the caller (CI passes the tag + sha). For a
# local dev build we derive a stable-enough value but the verify path pins them
# to constants so a dirty working tree can't introduce drift between the two
# builds it compares.
VERSION="${VERSION:-$(git -C "$(dirname "$0")" describe --tags --always --dirty 2>/dev/null || echo 0.0.0-local)}"
COMMIT="${COMMIT:-$(git -C "$(dirname "$0")" rev-parse HEAD 2>/dev/null || echo unknown)}"

DIST="${DIST:-dist}"
PKG="./cmd/penrush"

# Identical to the ldflags in every .slsa-goreleaser/<os>-<arch>.yml. Keep these
# in lock-step: any change here must mirror there (and the -buildvcs=false /
# -trimpath flags) or local proof diverges from CI.
ldflags() {
  printf -- '-s -w -buildid= -X main.version=%s -X main.commit=%s' "$1" "$2"
}

# sha256 helper that works on Linux (sha256sum), macOS (shasum), and Git Bash.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "ERROR: no sha256sum/shasum available" >&2
    exit 2
  fi
}

do_build() {
  out="$1"
  v="$2"
  c="$3"
  mkdir -p "$(dirname "$out")"
  # -buildvcs=false disables Go's automatic VCS stamping (vcs.revision/vcs.time/
  # vcs.modified) so the artifact does NOT depend on .git presence/state — an
  # independent rebuild from a source tarball or `git archive` export is then
  # byte-identical to the shipped binary (§H.1). The release commit is stamped
  # explicitly via -ldflags, so the auto-stamp carries no extra information.
  CGO_ENABLED=0 GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false -ldflags "$(ldflags "$v" "$c")" -o "$out" "$PKG"
}

cmd_build() {
  ext=""
  case "$(go env GOOS)" in windows) ext=".exe" ;; esac
  out="$DIST/penrush-$(go env GOOS)-$(go env GOARCH)$ext"
  do_build "$out" "$VERSION" "$COMMIT"
  echo "[OK] built $out"
  echo "     version=$VERSION commit=$COMMIT"
  echo "     sha256=$(sha256_of "$out")"
}

cmd_verify_reproducible() {
  # Pin version+commit to fixed constants so the ONLY thing that could differ
  # between the two builds is build nondeterminism itself — not a changing
  # `git describe` or a dirty-tree marker.
  v="reproducible-check"
  c="0000000000000000000000000000000000000000"
  ext=""
  case "$(go env GOOS)" in windows) ext=".exe" ;; esac

  a="$DIST/repro-a/penrush$ext"
  b="$DIST/repro-b/penrush$ext"

  echo "[*] reproducible-build check: building twice with identical inputs"
  echo "    GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) version=$v"
  do_build "$a" "$v" "$c"
  do_build "$b" "$v" "$c"

  ha="$(sha256_of "$a")"
  hb="$(sha256_of "$b")"
  echo "    build A sha256=$ha"
  echo "    build B sha256=$hb"

  if [ "$ha" = "$hb" ]; then
    echo "[OK] REPRODUCIBLE — both builds are byte-identical"
    exit 0
  fi
  echo "[FAIL] NON-REPRODUCIBLE — hashes differ; release would be rejected (§H.1)" >&2
  exit 1
}

case "${1:-build}" in
  build) cmd_build ;;
  verify-reproducible) cmd_verify_reproducible ;;
  *)
    echo "usage: $0 {build|verify-reproducible}" >&2
    exit 2
    ;;
esac
