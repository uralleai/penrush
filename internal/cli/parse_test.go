package cli

import "testing"

// TestParseInstallCommand pins the command-string parser's classification
// (architecture §A.5). The parser is the highest-bypass-risk surface (§C.3,
// TB1) so its branches are nailed down explicitly here; the verdict-level
// behavior is covered by the parity corpus in hook_test.go.
func TestParseInstallCommand(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		action  ParseAction
		eco     string
		pkgName string
		version string
	}{
		// --- non-install: ignored ---
		{"plain-ls", "ls -la", ActionIgnore, "", "", ""},
		{"git-status", "git status", ActionIgnore, "", "", ""},
		{"npx-in-string", `python -c "the word npx is here"`, ActionIgnore, "", "", ""},
		{"echo-npx", "echo 'use npx for scripts'", ActionIgnore, "", "", ""},
		{"bare-npm-install", "npm install", ActionIgnore, "", "", ""}, // restore from lockfile

		// --- lockfile-frozen: allow by structure ---
		{"npm-ci", "npm ci", ActionAllow, "", "", ""},
		{"uv-frozen", "uv sync --frozen", ActionAllow, "", "", ""},
		{"poetry-install", "poetry install", ActionAllow, "", "", ""},
		{"poetry-no-lock", "poetry install --no-lock", ActionIgnore, "", "", ""}, // NOT frozen; no other matcher -> ignore

		// --- /lock file violations: block by structure ---
		{"pip-no-pin", "pip install requests", ActionBlock, "", "", ""},
		{"pip-r-no-hashes", "pip install -r requirements.txt", ActionBlock, "", "", ""},
		{"npm-no-saveexact", "npm install left-pad@1.3.0", ActionBlock, "", "", ""},

		// --- age-gated specs: routed to the engine ---
		{"npm-saveexact", "npm install --save-exact left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npm-scoped", "npm install -E @types/node@20.11.5", ActionGate, "npm", "@types/node", "20.11.5"},
		{"pip-pinned", "pip install requests==2.31.0", ActionGate, "pypi", "requests", "2.31.0"},
		{"uv-add", "uv add httpx==0.27.0", ActionGate, "pypi", "httpx", "0.27.0"},
		{"cargo-install", "cargo install ripgrep", ActionGate, "cargo", "ripgrep", ""},
		{"gem-install", "gem install rails", ActionGate, "gem", "rails", ""},
		{"go-get-pinned", "go get github.com/foo/bar@v1.2.3", ActionGate, "go", "github.com/foo/bar", "v1.2.3"},

		// --- docker ref splitting (must match splitVersion: last @ / last : ) ---
		{"docker-digest", "docker pull alpine@sha256:abc123def456", ActionGate, "docker", "alpine", "sha256:abc123def456"},
		{"docker-tag", "docker pull alpine:latest", ActionGate, "docker", "alpine", "latest"},
		{"docker-bare", "docker pull alpine", ActionGate, "docker", "alpine", ""},

		// --- github clone ---
		{"git-clone", "git clone https://github.com/golang/go.git", ActionGate, "github", "golang/go", ""},
		{"gh-clone", "gh repo clone golang/go", ActionGate, "github", "golang/go", ""},

		// --- mcp ---
		{"mcp-add", "claude mcp add some-server", ActionGate, "mcp", "some-server", ""},

		// --- structural blocks ---
		{"go-latest", "go install github.com/foo/bar@latest", ActionBlock, "", "", ""},
		{"winget", "winget install Foo.Bar", ActionBlock, "", "", ""},
		{"brew", "brew install jq", ActionBlock, "", "", ""},
		{"apt", "apt install curl", ActionBlock, "", "", ""},

		// --- ephemeral exec ---
		{"npx-bare-pkg", "npx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npx-y-flag", "npx -y left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npx-p-space", "npx -p left-pad@1.3.0 left-pad", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npx-package-eq", "npx --package=left-pad@1.3.0 left-pad", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npm-exec", "npm exec left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npm-x-alias", "npm x left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"pnpm-dlx", "pnpm dlx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"yarn-dlx", "yarn dlx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"bun-x", "bun x left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"bunx", "bunx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npx-local-file", "npx ./scripts/tool.js", ActionIgnore, "", "", ""},
		{"npx-dash-separator", "npx left-pad@1.3.0 -- --inner-flag value", ActionGate, "npm", "left-pad", "1.3.0"},

		// --- command-position: verb after && / ; still fires ---
		{"npx-after-and", "ls && npx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
		{"npx-after-semi", "ls ; npx left-pad@1.3.0", ActionGate, "npm", "left-pad", "1.3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr := ParseInstallCommand(tc.cmd)
			if pr.Action != tc.action {
				t.Fatalf("%q action = %d, want %d (reason=%q)", tc.cmd, pr.Action, tc.action, pr.Reason)
			}
			if tc.action == ActionGate {
				if pr.Eco != tc.eco || pr.Name != tc.pkgName || pr.Version != tc.version {
					t.Fatalf("%q gate = (%q,%q,%q), want (%q,%q,%q)", tc.cmd, pr.Eco, pr.Name, pr.Version, tc.eco, tc.pkgName, tc.version)
				}
			}
		})
	}
}

// TestParseUnparseableFailsClosed: a recognized install VERB whose artifact
// name cannot be extracted must yield an ActionBlock (fail-closed), never an
// allow. This is the §A.5/§C.3 bypass-resistance principle.
func TestParseUnparseableFailsClosed(t *testing.T) {
	// `claude mcp add` with no server name -> structural block.
	if pr := ParseInstallCommand("claude mcp add"); pr.Action != ActionBlock {
		t.Fatalf("`claude mcp add` (no server) = %d, want ActionBlock", pr.Action)
	}
	// A gate-builder fed an empty name fails closed (unit-level guard).
	if pr := gateResult("npm", "   ", ""); pr.Action != ActionBlock {
		t.Fatalf("gateResult with blank name = %d, want ActionBlock", pr.Action)
	}
}

// TestStripShellWrapper: a `bash -c '...'` wrapper is peeled so the inner
// command is analyzed.
func TestStripShellWrapper(t *testing.T) {
	got := stripShellWrapper(`bash -c 'npm ci'`)
	if got != "npm ci'" { // trailing quote remains (matches reference hook's single-side strip)
		t.Fatalf("stripShellWrapper = %q, want %q", got, "npm ci'")
	}
	if pr := ParseInstallCommand(`bash -c "npm ci"`); pr.Action != ActionAllow {
		t.Fatalf("wrapped `npm ci` = %d, want ActionAllow", pr.Action)
	}
}
