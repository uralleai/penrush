package redact

import (
	"strings"
	"testing"
)

// Golden corpus per FR-011 acceptance criteria and Judge D-5 SA.3 examples.
// Each case is (input command, expected redacted output). The FR's own AC
// example is case "pip-index-url".
func TestGoldens(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "pip-index-url", // FR-011 acceptance criterion, verbatim shape
			in:   `pip install --index-url https://user:s3cret@private.example/simple pkg`,
			want: `pip install --index-url https://user:[REDACTED]@private.example/simple pkg`,
		},
		{
			name: "pip-extra-index-url",
			in:   `pip install --extra-index-url https://bot:tok123@pypi.corp.io/simple somepkg==1.0.0`,
			want: `pip install --extra-index-url https://bot:[REDACTED]@pypi.corp.io/simple somepkg==1.0.0`,
		},
		{
			name: "git-clone-pat-userinfo", // Judge SA.3: git clone https://user:pat@github.com/...
			in:   `git clone https://uri:ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456@github.com/org/private-repo.git`,
			want: `git clone https://uri:[REDACTED]@github.com/org/private-repo.git`,
		},
		{
			name: "git-clone-bare-token-userinfo",
			in:   `git clone https://ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456@github.com/org/repo.git`,
			want: `git clone https://[REDACTED]@github.com/org/repo.git`,
		},
		{
			name: "npm-registry-token-url",
			in:   `npm install --registry=https://ci:npm_aBcDeFgHiJkLmNoPqRsTuV@registry.corp.io/ left-pad`,
			want: `npm install --registry=https://ci:[REDACTED]@registry.corp.io/ left-pad`,
		},
		{
			name: "bearer-header",
			in:   `curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" https://api.example/x`,
			want: `curl -H "Authorization: Bearer [REDACTED]" https://api.example/x`,
		},
		{
			name: "github-fine-grained-pat-bare",
			in:   `gh auth login --with-token github_pat_11ABCDEFG0123456789_abcdefghij`,
			want: `gh auth login --with-token [REDACTED]`,
		},
		{
			name: "flag-token-space",
			in:   `sometool --token hunter2hunter2 install thing`,
			want: `sometool --token [REDACTED] install thing`,
		},
		{
			name: "flag-password-equals",
			in:   `docker login --password=s3cretPW registry.example`,
			want: `docker login --password=[REDACTED] registry.example`,
		},
		{
			name: "env-assignment",
			in:   `NPM_TOKEN=npm_aBcDeFgHiJkLmNoPqRsT npm publish`,
			want: `NPM_TOKEN=[REDACTED] npm publish`,
		},
		{
			name: "pypi-token-bare", // caught by the pypi- prefix rule even though -p is not a redacted flag
			in:   `twine upload -u __token__ -p pypi-AgEIcHlwaS5vcmcCJGFiY2RlZg dist/*`,
			want: `twine upload -u __token__ -p [REDACTED] dist/*`,
		},
		{
			name: "pypi-token-prefix-rule",
			in:   `export X=pypi-AgEIcHlwaS5vcmcCJGFiY2RlZg`,
			want: `export X=[REDACTED]`,
		},
		{
			name: "aws-access-key",
			in:   `aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE`,
			want: `aws configure set aws_access_key_id [REDACTED]`,
		},
		{
			name: "clean-command-unchanged", // no false positives on the common path
			in:   `npm install --save-exact left-pad@1.3.0`,
			want: `npm install --save-exact left-pad@1.3.0`,
		},
		{
			name: "clean-scoped-npm-unchanged", // @scope must not be treated as userinfo
			in:   `npm install --save-exact @types/node@20.11.5`,
			want: `npm install --save-exact @types/node@20.11.5`,
		},
		{
			name: "clean-git-https-unchanged",
			in:   `git clone https://github.com/golang/go.git`,
			want: `git clone https://github.com/golang/go.git`,
		},
		{
			name: "go-install-unchanged",
			in:   `go install golang.org/x/tools/cmd/stringer@v0.21.0`,
			want: `go install golang.org/x/tools/cmd/stringer@v0.21.0`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if got != tc.want {
				t.Errorf("redact mismatch\n in:   %s\n got:  %s\n want: %s", tc.in, got, tc.want)
			}
		})
	}
}

// The pypi -p case above documents a known limitation (single-letter -p is
// too false-positive-prone to redact globally). This test pins that the
// *token prefix* rule still catches a pypi- token anywhere it appears with
// the standard prefix length.
func TestPyPITokenPrefixCaught(t *testing.T) {
	in := `twine upload --password pypi-AgEIcHlwaS5vcmcCJGFiY2RlZg dist/*`
	got := String(in)
	if strings.Contains(got, "pypi-AgEIcHlwaS5vcmcCJGFiY2RlZg") {
		t.Fatalf("pypi token survived redaction: %s", got)
	}
}

// Property: redaction is idempotent — redacting an already-redacted string
// changes nothing.
func TestIdempotent(t *testing.T) {
	in := `pip install --index-url https://user:s3cret@private.example/simple pkg`
	once := String(in)
	twice := String(once)
	if once != twice {
		t.Fatalf("not idempotent:\n once:  %s\n twice: %s", once, twice)
	}
}
