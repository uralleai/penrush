package installscan

import (
	"encoding/json"
	"sort"
	"strings"
)

// Locate turns the bounded, in-memory archive contents (path -> raw bytes,
// already read by internal/payload with all §V4 caps enforced) into the set of
// install-lifecycle hooks for the given ecosystem. It reads bytes only — it
// never executes anything (delta §V4.9).
//
// files is keyed by the archive-entry path (as read, path-cleaned upstream).
// For docker, files must carry one entry named "image-config.json" whose bytes
// are the image config blob (history[].created_by is the RUN surface).
func Locate(eco string, files map[string][]byte) []HookFile {
	switch eco {
	case "npm":
		return locateNPM(files)
	case "pypi":
		return locatePyPI(files)
	case "cargo":
		return locateCargo(files)
	case "gem":
		return locateGem(files)
	case "docker":
		return locateDocker(files)
	default:
		return nil
	}
}

// sortedPaths returns the file paths in deterministic order.
func sortedPaths(files map[string][]byte) []string {
	ps := make([]string, 0, len(files))
	for p := range files {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

// base returns the final path element, lowercased for suffix matching.
func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// locateNPM parses package.json and extracts the install-lifecycle scripts:
// preinstall / install / postinstall / prepare (FR-106 mandatory surface).
func locateNPM(files map[string][]byte) []HookFile {
	var hooks []HookFile
	for _, p := range sortedPaths(files) {
		if base(p) != "package.json" {
			continue
		}
		var doc struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(files[p], &doc); err != nil {
			// A package.json we cannot parse where a scripts block is expected is
			// itself a red flag: surface it as an unparseable hook so Detect can
			// fail closed rather than silently ignore it.
			hooks = append(hooks, HookFile{Path: p + " (unparseable JSON)", Content: "eval $(base64 -d)"})
			continue
		}
		for _, name := range []string{"preinstall", "install", "postinstall", "prepare"} {
			if body, ok := doc.Scripts[name]; ok && strings.TrimSpace(body) != "" {
				hooks = append(hooks, HookFile{Path: p + "#scripts." + name, Content: body})
			}
		}
	}
	return hooks
}

// locatePyPI locates setup.py (executable build body) and pyproject.toml
// (PEP-517/518 build-backend declaration, byte-scanned as enrichment) plus any
// top-level *.py build hook. The gemspec-style structured parse is deferred
// (delta §V1.4) — detection runs on the plain-text source body.
func locatePyPI(files map[string][]byte) []HookFile {
	var hooks []HookFile
	for _, p := range sortedPaths(files) {
		b := base(p)
		switch {
		case b == "setup.py":
			hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
		case b == "pyproject.toml":
			// Enrichment only: byte-scan for a non-standard build-backend. The
			// text is scanned by Detect; a standard backend yields no sink.
			hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
		case strings.HasSuffix(b, ".py") && (strings.Contains(p, "build") || strings.Contains(p, "hook")):
			hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
		}
	}
	return hooks
}

// locateCargo locates build.rs (the Cargo build script — the only pre-build
// code-exec hook Cargo runs).
func locateCargo(files map[string][]byte) []HookFile {
	var hooks []HookFile
	for _, p := range sortedPaths(files) {
		if base(p) == "build.rs" {
			hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
		}
	}
	return hooks
}

// locateGem locates native-extension build files by PATH CONVENTION
// (ext/**/extconf.rb, ext/**/*.rb, ext/**/*.c) — the gemspec `extensions` YAML
// declaration is authoritative enrichment and is deferred (delta §V1.4). Ruby
// gems are tar-of-(data.tar.gz); internal/payload unwraps the nesting and hands
// the inner regular files here.
func locateGem(files map[string][]byte) []HookFile {
	var hooks []HookFile
	for _, p := range sortedPaths(files) {
		b := base(p)
		if b == "extconf.rb" {
			hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
			continue
		}
		if strings.HasPrefix(p, "ext/") || strings.Contains(p, "/ext/") {
			if strings.HasSuffix(b, ".rb") || strings.HasSuffix(b, ".c") {
				hooks = append(hooks, HookFile{Path: p, Content: string(files[p])})
			}
		}
	}
	return hooks
}

// locateDocker parses the image-config blob's history[].created_by RUN
// directives (encoding/json). This complements the digest-pin control
// (architecture §D.8): a `RUN curl … | sh` build layer is a fetch+exec.
func locateDocker(files map[string][]byte) []HookFile {
	cfg, ok := files["image-config.json"]
	if !ok {
		return nil
	}
	var doc struct {
		History []struct {
			CreatedBy  string `json:"created_by"`
			EmptyLayer bool   `json:"empty_layer"`
		} `json:"history"`
	}
	if err := json.Unmarshal(cfg, &doc); err != nil {
		// Unparseable config where RUN history is expected: fail-closed marker.
		return []HookFile{{Path: "image-config.json (unparseable)", Content: "eval $(base64 -d)"}}
	}
	var hooks []HookFile
	for i, h := range doc.History {
		cb := h.CreatedBy
		// Only the shell-command layers matter; the buildkit prefix is stripped
		// so the RUN body is scanned directly.
		if idx := strings.Index(cb, "RUN "); idx >= 0 {
			hooks = append(hooks, HookFile{Path: dockerLayerPath(i), Content: cb[idx+len("RUN "):]})
		} else if strings.Contains(cb, "/bin/sh -c") {
			hooks = append(hooks, HookFile{Path: dockerLayerPath(i), Content: cb})
		}
	}
	return hooks
}

func dockerLayerPath(i int) string {
	return "image-config.json#history[" + itoa(i) + "].created_by"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
