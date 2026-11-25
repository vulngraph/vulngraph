package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeownersOwner(t *testing.T) {
	const file = `
# Global default
*                @acme/platform

# Docs anywhere
docs/            @acme/docs
*.md             @alice  # inline comment
/infra/          @acme/infra
/infra/legacy/
apps/*/deploy.yaml @acme/deployers
/terraform/**/prod.tf @acme/prod-owners
config?.yml      @acme/config
[abc].txt        @acme/never
`
	co := ParseCodeowners(file)
	tests := []struct {
		name, path, owner, pattern string
		ok                         bool
	}{
		{"catch-all for an unmatched file", "src/main.go", "@acme/platform", "*", true},
		{"empty path asks for the repo default", "", "@acme/platform", "*", true},
		{"unanchored dir matches at depth", "pkg/docs/readme.txt", "@acme/docs", "docs/", true},
		{"extension glob, last rule wins over docs/", "docs/guide.md", "@alice", "*.md", true},
		{"anchored dir", "infra/vpc/main.tf", "@acme/infra", "/infra/", true},
		{"anchored dir does not match deeper copy", "x/infra/main.tf", "@acme/platform", "*", true},
		{"ownerless rule un-owns its paths", "infra/legacy/old.tf", "", "/infra/legacy/", false},
		{"single-segment star", "apps/web/deploy.yaml", "@acme/deployers", "apps/*/deploy.yaml", true},
		{"single-segment star does not cross dirs", "apps/web/x/deploy.yaml", "@acme/platform", "*", true},
		{"double star across dirs", "terraform/a/b/prod.tf", "@acme/prod-owners", "/terraform/**/prod.tf", true},
		{"double star zero dirs", "terraform/prod.tf", "@acme/prod-owners", "/terraform/**/prod.tf", true},
		{"question mark", "config1.yml", "@acme/config", "config?.yml", true},
		{"leading slash on the path is ignored", "/infra/x.tf", "@acme/infra", "/infra/", true},
		{"character classes are skipped, not guessed", "a.txt", "@acme/platform", "*", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, pattern, ok := co.Owner(tt.path)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.owner, owner)
			assert.Equal(t, tt.pattern, pattern)
		})
	}
}

func TestCodeownersOwner_NoCatchAllLeavesRepoDefaultUnanswered(t *testing.T) {
	co := ParseCodeowners("/infra/ @acme/infra\n")
	_, _, ok := co.Owner("")
	assert.False(t, ok)
	_, _, ok = co.Owner("README.md")
	assert.False(t, ok)
}

func TestCodeownersOwner_Empty(t *testing.T) {
	_, _, ok := ParseCodeowners("").Owner("a/b")
	assert.False(t, ok)
}

// GitHub's documented pattern semantics, one pattern at a time: "docs/*"
// owns files directly in docs/ only, "/*" owns root-level files only (it is not
// a repo-wide default), "/docs/**" and "/docs/" own everything beneath.
func TestCodeownersPatternSemantics(t *testing.T) {
	tests := []struct {
		pattern, path string
		match         bool
	}{
		{"docs/*", "docs/getting-started.md", true},
		{"docs/*", "docs/build-app/troubleshooting.md", false},
		{"docs/*", "x/docs/getting-started.md", false},
		{"/*", "README.md", true},
		{"/*", "src/main.go", false},
		{"/docs/**", "docs/a/b/c.md", true},
		{"/docs/**", "docs/c.md", true},
		{"/docs/", "docs/a/b.md", true},
		{"/docs/", "x/docs/b.md", false},
		{"apps/", "deep/apps/x/y.go", true},
		{"**/logs", "deeply/nested/logs/x.log", true},
		{"**/logs", "logs/x.log", true},
		{"/build/logs/", "build/logs/sub/x.log", true},
		{"/build/logs/", "x/build/logs/a", false},
		{"*", "a/b/c.txt", true},
		{"*.js", "a/b/c.js", true},
		{"*.js", "a/b/c.ts", false},
		{"/apps/github", "apps/github/x/y.rb", true},
		{"apps/*/deploy.yaml", "apps/web/deploy.yaml", true},
		{"apps/*/deploy.yaml", "apps/web/x/deploy.yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+" "+tt.path, func(t *testing.T) {
			co := ParseCodeowners(tt.pattern + " @o")
			_, _, ok := co.Owner(tt.path)
			assert.Equal(t, tt.match, ok)
		})
	}
}

func TestCodeownersOwner_RootStarIsNotRepoDefault(t *testing.T) {
	_, _, ok := ParseCodeowners("/* @acme/root-files\n").Owner("")
	assert.False(t, ok, "/* owns root-level files only, not the whole repo")
	for _, p := range []string{"*", "**", "/**"} {
		_, _, ok := ParseCodeowners(p + " @acme/all\n").Owner("")
		assert.True(t, ok, p)
	}
}
