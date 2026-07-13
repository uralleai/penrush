package installscan

import (
	"strings"
	"testing"
)

func TestLocatePyPI(t *testing.T) {
	files := map[string][]byte{
		"pkg-1.0/setup.py":       []byte("import os; os.system('x')"),
		"pkg-1.0/pyproject.toml": []byte(`[build-system]` + "\n" + `build-backend = "setuptools.build_meta"`),
		"pkg-1.0/README.md":      []byte("hi"), // ignored
	}
	hooks := Locate("pypi", files)
	var haveSetup, havePyproject bool
	for _, h := range hooks {
		if strings.HasSuffix(h.Path, "setup.py") {
			haveSetup = true
		}
		if strings.HasSuffix(h.Path, "pyproject.toml") {
			havePyproject = true
		}
	}
	if !haveSetup || !havePyproject {
		t.Fatalf("pypi locate missing hooks: %+v", hooks)
	}
}

func TestLocateCargo(t *testing.T) {
	hooks := Locate("cargo", map[string][]byte{"crate-1.0/build.rs": []byte("fn main(){}"), "crate-1.0/src/lib.rs": []byte("x")})
	if len(hooks) != 1 || !strings.HasSuffix(hooks[0].Path, "build.rs") {
		t.Fatalf("cargo locate wrong: %+v", hooks)
	}
}

func TestLocateNPM_UnparseablePackageJSON(t *testing.T) {
	// A package.json where scripts are expected but the JSON is broken is a red
	// flag: it must surface as a fail-closed hook, not be silently ignored.
	hooks := Locate("npm", map[string][]byte{"package/package.json": []byte("{ not json")})
	if len(hooks) == 0 {
		t.Fatal("unparseable package.json must surface a hook")
	}
	if Detect("npm", hooks).Level != LevelFailClosed {
		t.Error("unparseable package.json should drive fail-closed")
	}
}

func TestLocateDocker_UnparseableConfig(t *testing.T) {
	hooks := Locate("docker", map[string][]byte{"image-config.json": []byte("not json")})
	if Detect("docker", hooks).Level != LevelFailClosed {
		t.Errorf("unparseable docker config should fail-closed, got %v", Detect("docker", hooks).Level)
	}
}

func TestLocate_UnknownEcosystemNil(t *testing.T) {
	if Locate("conda", map[string][]byte{"x": []byte("y")}) != nil {
		t.Fatal("unknown ecosystem should locate no hooks")
	}
}

func TestMessage_AllLevels(t *testing.T) {
	levels := []Finding{
		{Level: LevelHigh, HookPath: "package.json#scripts.postinstall"},
		{Level: LevelFailClosed},
		{Level: LevelMedium},
		{Level: LevelNA},
		{Level: LevelNone},
	}
	for _, f := range levels {
		msg := f.Message("npm", "pkg")
		if !strings.Contains(msg, "pkg") {
			t.Errorf("level %v message missing artifact name: %q", f.Level, msg)
		}
	}
	// shortHook variants.
	if shortHook("") != "install hook" || shortHook("a/b/c") != "c" || shortHook("bare") != "bare" {
		t.Error("shortHook edge cases wrong")
	}
}
