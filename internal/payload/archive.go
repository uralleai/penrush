package payload

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// Limits bound the untrusted-archive read (delta §V4.1/§V4.5). Zero disk, zero
// execution; these caps are the only thing standing between a decompression
// bomb and OOM.
type Limits struct {
	MaxTotalUncompressed int64 // sum of decompressed bytes read across all entries + nesting
	MaxEntries           int   // total archive entries walked (defeats many-tiny-files bombs)
	MaxPerEntry          int64 // per-file decompressed byte cap
	MaxDepth             int   // nested-archive depth cap (gem = 2)
}

// DefaultLimits are conservative caps sufficient for real install-hook files
// (a package.json / setup.py / build.rs is kilobytes) while stopping bombs.
func DefaultLimits() Limits {
	return Limits{
		MaxTotalUncompressed: 64 << 20, // 64 MiB total decompressed budget
		MaxEntries:           20000,    // 20k entries
		MaxPerEntry:          8 << 20,  // 8 MiB per hook file
		MaxDepth:             3,        // gem needs 2; 3 is headroom, quines die here
	}
}

// Sentinel errors — all fail CLOSED (the caller blocks). Distinct values so
// tests and the pentest can assert the exact control that fired.
var (
	ErrDecompressionCap = errors.New("payload: decompression byte cap exceeded (possible decompression bomb)")
	ErrEntryCap         = errors.New("payload: archive entry-count cap exceeded (possible zip bomb)")
	ErrPerEntryCap      = errors.New("payload: per-entry size cap exceeded")
	ErrLinkEntry        = errors.New("payload: symlink/hardlink/device entry rejected (only regular files are read)")
	ErrPathTraversal    = errors.New("payload: archive entry path escapes root (zip-slip) rejected")
	ErrDepthCap         = errors.New("payload: nested-archive depth cap exceeded")
	ErrUnknownFormat    = errors.New("payload: unknown/unsupported archive format — fail-closed")
	ErrParse            = errors.New("payload: malformed archive — fail-closed")
)

// scanState threads the shared budget through tar/zip walks and nesting so a
// bomb split across nested archives is still caught by the global caps.
type scanState struct {
	lim         Limits
	interesting func(cleanPath string) bool
	out         map[string][]byte
	entries     int
	total       int64
}

// ReadArchive performs the bounded, in-memory, read-only scan of an untrusted
// archive. It reads ONLY entries for which interesting(cleanPath) is true, into
// a bounded in-memory map. It NEVER writes to disk and NEVER executes anything.
//
// A panic anywhere in the decode path (a hostile archive crashing a stdlib
// decoder) is recovered and converted to a fail-closed error (§V4.7) — a
// crashing scanner must never become a bypass primitive.
func ReadArchive(r io.Reader, format Format, lim Limits, interesting func(string) bool) (out map[string][]byte, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			out, err = nil, fmt.Errorf("%w: recovered decoder panic: %v", ErrParse, rec)
		}
	}()

	st := &scanState{lim: lim, interesting: interesting, out: map[string][]byte{}}

	switch format {
	case FormatTarGz:
		zr, zerr := gzip.NewReader(r)
		if zerr != nil {
			return nil, fmt.Errorf("%w: gzip: %v", ErrParse, zerr)
		}
		defer zr.Close()
		err = st.walkTar(capReader(zr, lim.MaxTotalUncompressed), 1)
	case FormatTarBz2:
		err = st.walkTar(capReader(bzip2.NewReader(r), lim.MaxTotalUncompressed), 1)
	case FormatTar:
		err = st.walkTar(capReader(r, lim.MaxTotalUncompressed), 1)
	case FormatGem:
		err = st.readGem(r, 1)
	case FormatZip:
		err = st.readZip(r)
	default:
		return nil, ErrUnknownFormat
	}
	if err != nil {
		return nil, err
	}
	return st.out, nil
}

// capReader wraps a decompression stream so the TOTAL decompressed bytes read
// can never exceed n. This is the primary decompression-bomb wall (§V4.1): the
// bomb is stopped at the source, before any per-entry logic.
func capReader(r io.Reader, n int64) *cappedReader { return &cappedReader{r: r, left: n} }

type cappedReader struct {
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, ErrDecompressionCap
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// walkTar streams a tar archive, enforcing entry-count + per-entry + link-type
// + path-traversal defenses, reading only interesting regular files. depth is
// the nesting level (gem's inner tar is depth 2).
func (st *scanState) walkTar(r io.Reader, depth int) error {
	if depth > st.lim.MaxDepth {
		return ErrDepthCap
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if errors.Is(err, ErrDecompressionCap) {
				return ErrDecompressionCap
			}
			return fmt.Errorf("%w: tar: %v", ErrParse, err)
		}
		st.entries++
		if st.entries > st.lim.MaxEntries {
			return ErrEntryCap
		}

		// §V4.3 — reject links and special files outright. We only ever read
		// regular files. A symlink pointing outside the root + a follow-up write
		// "through" it is the classic escape; rejecting links closes it.
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			// fall through to the read path
		case tar.TypeDir, tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("%w: %q type=%d", ErrLinkEntry, hdr.Name, hdr.Typeflag)
		default:
			return fmt.Errorf("%w: %q unexpected type=%d", ErrLinkEntry, hdr.Name, hdr.Typeflag)
		}

		clean, perr := cleanEntryPath(hdr.Name)
		if perr != nil {
			return perr
		}

		// Nested gem data.tar.gz: recurse under the shared budget + depth cap.
		if isNestedGzTar(clean) {
			data, rerr := st.readEntry(tr)
			if rerr != nil {
				return rerr
			}
			zr, zerr := gzip.NewReader(bytes.NewReader(data))
			if zerr != nil {
				return fmt.Errorf("%w: nested gzip: %v", ErrParse, zerr)
			}
			if werr := st.walkTar(capReader(zr, st.lim.MaxTotalUncompressed-st.total), depth+1); werr != nil {
				zr.Close()
				return werr
			}
			zr.Close()
			continue
		}

		if !st.interesting(clean) {
			continue // §V4.4 — not an allowlisted hook file; do not buffer it
		}
		data, rerr := st.readEntry(tr)
		if rerr != nil {
			return rerr
		}
		st.out[clean] = data
	}
}

// readEntry reads one entry body under the per-entry cap and the shared total
// budget. Uses a LimitReader at MaxPerEntry+1 so an over-cap entry is detected
// rather than silently truncated.
func (st *scanState) readEntry(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, st.lim.MaxPerEntry+1)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, limited)
	if err != nil {
		if errors.Is(err, ErrDecompressionCap) {
			return nil, ErrDecompressionCap
		}
		return nil, fmt.Errorf("%w: entry read: %v", ErrParse, err)
	}
	if n > st.lim.MaxPerEntry {
		return nil, ErrPerEntryCap
	}
	st.total += n
	if st.total > st.lim.MaxTotalUncompressed {
		return nil, ErrDecompressionCap
	}
	return buf.Bytes(), nil
}

// readGem walks the outer (uncompressed) gem tar; walkTar itself recurses into
// the data.tar.gz member at depth+1.
func (st *scanState) readGem(r io.Reader, depth int) error {
	return st.walkTar(capReader(r, st.lim.MaxTotalUncompressed), depth)
}

// readZip reads a zip (wheel / Go module). zip needs random access, so the
// caller must have buffered the compressed bytes (bounded by the download cap).
// Only interesting regular files are opened; symlink entries are rejected via
// the Unix mode bits.
func (st *scanState) readZip(r io.Reader) error {
	var buf bytes.Buffer
	// Bound the buffered compressed size defensively (the fetch layer also caps
	// this; belt and braces).
	if _, err := io.Copy(&buf, io.LimitReader(r, st.lim.MaxTotalUncompressed+1)); err != nil {
		return fmt.Errorf("%w: zip buffer: %v", ErrParse, err)
	}
	if int64(buf.Len()) > st.lim.MaxTotalUncompressed {
		return ErrDecompressionCap
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return fmt.Errorf("%w: zip open: %v", ErrParse, err)
	}
	for _, f := range zr.File {
		st.entries++
		if st.entries > st.lim.MaxEntries {
			return ErrEntryCap
		}
		// §V4.3 — reject symlinks (encoded in the Unix mode bits).
		if f.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: zip %q is a symlink", ErrLinkEntry, f.Name)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		clean, perr := cleanEntryPath(f.Name)
		if perr != nil {
			return perr
		}
		if !st.interesting(clean) {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return fmt.Errorf("%w: zip entry open: %v", ErrParse, oerr)
		}
		data, rerr := st.readEntry(rc)
		rc.Close()
		if rerr != nil {
			return rerr
		}
		st.out[clean] = data
	}
	return nil
}

// cleanEntryPath cleans an archive-declared path and rejects any absolute path
// or `..` escape (§V4.2). We never write to disk, so this is defense-in-depth;
// it also keeps the allowlist match honest (an entry cannot masquerade as a
// hook via a traversal-laced name).
func cleanEntryPath(name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrPathTraversal, name)
	}
	clean := path.Clean(n)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	return clean, nil
}

func isNestedGzTar(clean string) bool {
	b := clean
	if i := strings.LastIndex(clean, "/"); i >= 0 {
		b = clean[i+1:]
	}
	return b == "data.tar.gz"
}
