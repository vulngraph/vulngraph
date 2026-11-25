package aws

// cloudwatch_filter_pattern.go — parsing CloudWatch Logs JSON metric-filter
// patterns, for the CIS AWS 5.x alarm chains (cloudwatch_alarms.go).
//
// A pattern is `{ term (&& | ||) term ... }` with parentheses, where a term is
// `$.field op value` or `$.field NOT EXISTS` / `IS NULL` / `EXISTS`. It is
// parsed and expanded to disjunctive normal form: a list of AND-groups, any
// one of which matching an event makes the filter fire. Matching on the
// groups, not on substrings, is what tells `CreateRoute` from
// `CreateRouteTable`, `A || B` from the never-firing `A && B`, and a filter
// narrowed by an extra `&& $.userIdentity.arn = bob` from one that is not.

import (
	"errors"
	"strings"
)

// filterTerm is one comparison, with the value's quotes removed.
type filterTerm struct{ field, op, value string }

// maxFilterGroups bounds the DNF expansion: a pattern whose expansion grows
// past it is treated as unparseable rather than evaluated partially.
const maxFilterGroups = 4096

var errFilterSyntax = errors.New("metric filter pattern: unsupported syntax")

// filterGroups parses a JSON metric-filter pattern into its AND-groups.
func filterGroups(pattern string) ([][]filterTerm, error) {
	p := strings.TrimSpace(pattern)
	if !strings.HasPrefix(p, "{") || !strings.HasSuffix(p, "}") {
		return nil, errFilterSyntax
	}
	ps := &patternParser{src: p[1 : len(p)-1]}
	groups, err := ps.or()
	if err != nil {
		return nil, err
	}
	if ps.skipSpace(); ps.pos != len(ps.src) {
		return nil, errFilterSyntax
	}
	return groups, nil
}

type patternParser struct {
	src string
	pos int
}

func (p *patternParser) skipSpace() {
	for p.pos < len(p.src) && strings.ContainsRune(" \t\r\n", rune(p.src[p.pos])) {
		p.pos++
	}
}

func (p *patternParser) consume(tok string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.src[p.pos:], tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

// or := and ('||' and)* — the union of the operands' groups.
func (p *patternParser) or() ([][]filterTerm, error) {
	groups, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.consume("||") {
		more, err := p.and()
		if err != nil {
			return nil, err
		}
		groups = append(groups, more...)
		if len(groups) > maxFilterGroups {
			return nil, errFilterSyntax
		}
	}
	return groups, nil
}

// and := unary ('&&' unary)* — the cross product of the operands' groups.
func (p *patternParser) and() ([][]filterTerm, error) {
	groups, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.consume("&&") {
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		if len(groups)*len(right) > maxFilterGroups {
			return nil, errFilterSyntax
		}
		var product [][]filterTerm
		for _, l := range groups {
			for _, r := range right {
				g := append(append([]filterTerm{}, l...), r...)
				product = append(product, g)
			}
		}
		groups = product
	}
	return groups, nil
}

func (p *patternParser) unary() ([][]filterTerm, error) {
	if p.consume("(") {
		groups, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.consume(")") {
			return nil, errFilterSyntax
		}
		return groups, nil
	}
	t, err := p.term()
	if err != nil {
		return nil, err
	}
	return [][]filterTerm{{t}}, nil
}

// term := '$.' selector (op value | NOT EXISTS | IS NULL | EXISTS)
func (p *patternParser) term() (filterTerm, error) {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], "$.") {
		return filterTerm{}, errFilterSyntax
	}
	start := p.pos
	for p.pos < len(p.src) && !strings.ContainsRune(" \t\r\n=!<>()&|", rune(p.src[p.pos])) {
		p.pos++
	}
	t := filterTerm{field: p.src[start:p.pos]}
	for _, kw := range []string{"NOT EXISTS", "IS NULL", "EXISTS"} {
		if p.consume(kw) {
			t.op = kw
			return t, nil
		}
	}
	for _, op := range []string{"!=", "<=", ">=", "=", "<", ">"} {
		if p.consume(op) {
			t.op = op
			break
		}
	}
	if t.op == "" {
		return filterTerm{}, errFilterSyntax
	}
	v, err := p.value()
	if err != nil {
		return filterTerm{}, err
	}
	t.value = v
	return t, nil
}

// value is a double-quoted string or a bare token.
func (p *patternParser) value() (string, error) {
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == '"' {
		end := strings.IndexByte(p.src[p.pos+1:], '"')
		if end < 0 {
			return "", errFilterSyntax
		}
		v := p.src[p.pos+1 : p.pos+1+end]
		p.pos += end + 2
		return v, nil
	}
	start := p.pos
	for p.pos < len(p.src) && !strings.ContainsRune(" \t\r\n()&|", rune(p.src[p.pos])) {
		p.pos++
	}
	if p.pos == start {
		return "", errFilterSyntax
	}
	return p.src[start:p.pos], nil
}

// mustTerms parses the package's own literal terms (the CIS definitions).
func mustTerms(src ...string) []filterTerm {
	out := make([]filterTerm, len(src))
	for i, s := range src {
		g, err := filterGroups("{ " + s + " }")
		if err != nil || len(g) != 1 || len(g[0]) != 1 {
			panic("cloudwatch_filter_pattern: bad literal term " + s)
		}
		out[i] = g[0][0]
	}
	return out
}
