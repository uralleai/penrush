// Package payload performs the hardened fetch + bounded, in-memory, read-only
// scan of an untrusted package artifact for Gate 8 (FR-106).
//
// TRUST BOUNDARY TB2b (architecture delta §V4): the bytes handled here are an
// arbitrary, attacker-authored, compressed archive downloaded from an
// artifact-distribution host. That is a strict superset of v0's small metadata
// JSON and invites the whole archive-bomb / path-traversal / parser-DoS class.
// Every control in this package is a required §V4 defense:
//
//   - §V4.1 decompression-bomb: uncompressed-byte cap + entry-count cap +
//     per-entry cap. A bomb hits a wall in bytes, in file count, and per file.
//   - §V4.2 zip-slip / path-traversal: NOTHING is written to disk (§V4.4), so
//     there is nothing to traverse into; declared paths are additionally cleaned
//     and `..`/absolute paths are rejected.
//   - §V4.3 symlink / hardlink / device rejection: only regular files are ever
//     read; link/device entries fail closed.
//   - §V4.4 no auto-extraction: only the small allowlist of hook files is read,
//     into a bounded in-memory buffer; every other byte is discarded.
//   - §V4.5 nested-archive depth cap (gem = tar-of-data.tar.gz is depth 2).
//   - §V4.6 SSRF on the artifact URL (ssrf.go).
//   - §V4.7 parser-DoS / panic-as-bypass: size caps before parse; RE2 regexps;
//     the whole scan runs under a panic→fail-closed recover; a dedicated
//     wall-clock budget (scanner.go).
//   - §V4.9 no-execution invariant: the payload is NEVER executed. This package
//     only reads bytes. Property-tested.
//
// Zero third-party deps: archive/tar, archive/zip, compress/gzip,
// compress/bzip2, io, net/http, net/url, net (stdlib only).
package payload

// Format is the on-the-wire archive container of an artifact. It is set by the
// per-ecosystem locator (never sniffed from attacker-controlled magic bytes
// beyond what the stdlib decoder validates).
type Format int

const (
	// FormatUnknown is fail-closed: an artifact of unknown container is not read.
	FormatUnknown Format = iota
	// FormatTarGz: npm .tgz, crates .crate, PyPI sdist .tar.gz (gzip(tar)).
	FormatTarGz
	// FormatTarBz2: PyPI sdist .tar.bz2 (bzip2(tar)).
	FormatTarBz2
	// FormatZip: PyPI wheel .whl, Go module .zip.
	FormatZip
	// FormatGem: RubyGems .gem — an (uncompressed) tar whose data.tar.gz member
	// holds the real tree. Depth-2 nesting.
	FormatGem
	// FormatTar: a plain uncompressed tar (defensive completeness).
	FormatTar
	// FormatDockerConfig: not an archive — a JSON image-config blob whose
	// history[].created_by carries the RUN surface. Handled by the scanner, not
	// the archive reader.
	FormatDockerConfig
)

func (f Format) String() string {
	switch f {
	case FormatTarGz:
		return "tar.gz"
	case FormatTarBz2:
		return "tar.bz2"
	case FormatZip:
		return "zip"
	case FormatGem:
		return "gem"
	case FormatTar:
		return "tar"
	case FormatDockerConfig:
		return "docker-config"
	default:
		return "unknown"
	}
}
