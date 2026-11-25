package asset

import (
	"regexp"
	"strings"
)

// MetaCodeowners is the github_repo metadata key carrying the repo's CODEOWNERS
// rules, as stamped by the GitHub collector (comments and blank lines removed).
// Absent means the file was not found or not readable — not "nobody owns it".
const MetaCodeowners = "codeowners"

// MetaCodeownersFile is the github_repo metadata key set only when the sweep
// read the repo: "absent" when no CODEOWNERS file exists at any location,
// "present" when one was read.
const MetaCodeownersFile = "codeowners_file"

// CodeownersRule is one CODEOWNERS line: a path pattern and its owners, in file
// order.
type CodeownersRule struct {
	Pattern string
	Owners  []string
	re      *regexp.Regexp
}

// Codeowners is a parsed CODEOWNERS file. As on GitHub, the LAST matching rule
// wins, so rules are kept in file order.
type Codeowners []CodeownersRule

// ParseCodeowners parses CODEOWNERS text. Lines that are blank, comments, or
// carry a pattern this matcher cannot express are skipped rather than guessed
// at: an unparseable rule must not claim paths it was never meant to own. A rule
// with a pattern but no owners is kept — on GitHub it deliberately UN-owns the
// paths it matches, overriding an earlier rule.
func ParseCodeowners(text string) Codeowners {
	var out Codeowners
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		re, ok := codeownersPatternRegexp(fields[0])
		if !ok {
			continue
		}
		out = append(out, CodeownersRule{Pattern: fields[0], Owners: fields[1:], re: re})
	}
	return out
}

// Owner returns the first owner of the last rule matching path (repo-relative,
// forward slashes, with or without a leading "/"), and the rule's pattern. An
// empty path asks for the repo-wide default: only a catch-all rule ("*", "**",
// "/**") answers it; "/*" owns root-level files only, so it does not. ok is
// false when no rule matches or the winning rule has no owners.
func (c Codeowners) Owner(path string) (owner, pattern string, ok bool) {
	path = strings.TrimPrefix(strings.TrimSpace(path), "/")
	for i := len(c) - 1; i >= 0; i-- {
		r := c[i]
		if path == "" {
			if !isCatchAll(r.Pattern) {
				continue
			}
		} else if !r.re.MatchString(path) {
			continue
		}
		if len(r.Owners) == 0 {
			return "", r.Pattern, false
		}
		return r.Owners[0], r.Pattern, true
	}
	return "", "", false
}

func isCatchAll(p string) bool { return p == "*" || p == "**" || p == "/**" }

// codeownersPatternRegexp translates a CODEOWNERS (gitignore-style) pattern
// into an anchored regexp over a repo-relative path:
//
//   - a leading "/" or any slash before the last character anchors the pattern
//     to the repo root; otherwise it matches at any depth
//   - a trailing "/" matches everything beneath that directory
//   - "*" matches within one path segment, "**" across segments, "?" one char
//   - a pattern naming a directory also matches every file beneath it, EXCEPT
//     one ending in "/*": GitHub documents "docs/*" as matching
//     docs/getting-started.md but not docs/build-app/troubleshooting.md, so the
//     star names files directly in that directory, never a directory's contents
//
// Character classes and "!" negation are not supported by GitHub CODEOWNERS
// either; they are reported as unparseable.
func codeownersPatternRegexp(p string) (*regexp.Regexp, bool) {
	if p == "" || strings.ContainsAny(p, "[]!\\") {
		return nil, false
	}
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	directChildren := p == "*" || strings.HasSuffix(p, "/*")
	anchored := strings.HasPrefix(p, "/") || strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "**" {
		return regexp.MustCompile(`^.*$`), true
	}

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				i++
				if i+1 < len(p) && p[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	switch {
	case dirOnly:
		b.WriteString("/.*$")
	case directChildren && anchored:
		b.WriteString("$")
	default:
		b.WriteString("(?:/.*)?$")
	}
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, false
	}
	return re, true
}
