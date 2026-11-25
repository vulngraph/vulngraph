package gcp

import (
	"errors"
	"regexp"
	"strings"
)

// The CIS GCP change alerts (2.5-2.12) are judged semantically. A filter
// covers a change when it MATCHES every audit-log entry the change produces.
// Each change is a set of representative entries (logAlerts). Each candidate
// filter is parsed (Cloud Logging query language: comparisons, bare terms,
// NOT / -, OR, AND, implicit AND, parentheses; OR binds tighter than AND)
// and evaluated against them. So a NOT(...), a method AND-ed where CIS ORs
// it, or an extra narrowing AND clause (severity>=ERROR, a single project)
// fails to match some entry and does not cover. A filter that does not parse
// does not cover.

// logEntry is a representative audit-log entry: lower-cased field paths to
// values. "_text" holds payload text only a bare search term reaches.
type logEntry map[string]string

// logAlert is one CIS change-alerting control and the entries its alert
// must catch.
type logAlert struct {
	Name    string
	Entries []logEntry
}

// entries builds one entry per method name on a shared base.
func entries(base logEntry, methods ...string) []logEntry {
	out := make([]logEntry, 0, len(methods))
	for _, m := range methods {
		e := logEntry{"protopayload.methodname": m}
		for k, v := range base {
			e[k] = v
		}
		out = append(out, e)
	}
	return out
}

func with(base logEntry, extra logEntry) logEntry {
	e := logEntry{}
	for k, v := range base {
		e[k] = v
	}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

// projectIAM is a Resource Manager SetIamPolicy entry on a project.
var projectIAM = logEntry{
	"protopayload.servicename": "cloudresourcemanager.googleapis.com",
	"protopayload.methodname":  "SetIamPolicy",
	"resource.type":            "project",
}

// logAlerts is the pattern table: the entries each CIS GCP Foundation v5
// recommended filter exists to catch, with the method names the APIs log.
var logAlerts = []logAlert{
	{"project_ownership_changes", []logEntry{
		with(projectIAM, logEntry{"_text": "ProjectOwnership"}),
		with(projectIAM, logEntry{"_text": "projectOwnerInvitee"}),
		with(projectIAM, logEntry{
			"protopayload.servicedata.policydelta.bindingdeltas.action": "REMOVE",
			"protopayload.servicedata.policydelta.bindingdeltas.role":   "roles/owner",
		}),
		with(projectIAM, logEntry{
			"protopayload.servicedata.policydelta.bindingdeltas.action": "ADD",
			"protopayload.servicedata.policydelta.bindingdeltas.role":   "roles/owner",
		}),
	}},
	{"audit_config_changes", []logEntry{
		with(projectIAM, logEntry{"protopayload.servicedata.policydelta.auditconfigdeltas": "[{action: ADD}]"}),
	}},
	{"custom_role_changes", entries(logEntry{"resource.type": "iam_role", "protopayload.servicename": "iam.googleapis.com"},
		"google.iam.admin.v1.CreateRole", "google.iam.admin.v1.DeleteRole", "google.iam.admin.v1.UpdateRole")},
	{"firewall_changes", entries(logEntry{"resource.type": "gce_firewall_rule", "protopayload.servicename": "compute.googleapis.com"},
		"v1.compute.firewalls.patch", "v1.compute.firewalls.insert", "v1.compute.firewalls.delete")},
	{"route_changes", entries(logEntry{"resource.type": "gce_route", "protopayload.servicename": "compute.googleapis.com"},
		"v1.compute.routes.delete", "v1.compute.routes.insert")},
	{"network_changes", entries(logEntry{"resource.type": "gce_network", "protopayload.servicename": "compute.googleapis.com"},
		"v1.compute.networks.insert", "v1.compute.networks.patch", "v1.compute.networks.delete",
		"v1.compute.networks.removePeering", "v1.compute.networks.addPeering")},
	{"storage_iam_changes", entries(logEntry{"resource.type": "gcs_bucket", "protopayload.servicename": "storage.googleapis.com"},
		"storage.setIamPermissions")},
	{"sql_config_changes", entries(logEntry{"resource.type": "cloudsql_database", "protopayload.servicename": "cloudsql.googleapis.com"},
		"cloudsql.instances.update")},
}

// computeConfigAlert is the Compute Engine configuration-change alert: a
// filter must match the audit entries of instance, disk, network, firewall
// and route changes. It is kept out of logAlerts, which is the CIS list.
var computeConfigAlert = logAlert{Name: "compute_config_changes", Entries: []logEntry{
	{"resource.type": "gce_instance", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.instances.insert"},
	{"resource.type": "gce_instance", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.instances.delete"},
	{"resource.type": "gce_disk", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.disks.insert"},
	{"resource.type": "gce_network", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.networks.patch"},
	{"resource.type": "gce_firewall_rule", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.firewalls.patch"},
	{"resource.type": "gce_route", "protopayload.servicename": "compute.googleapis.com", "protopayload.methodname": "v1.compute.routes.insert"},
}}

// filterCovers reports whether a Logging filter matches every entry of the
// change.
func filterCovers(filter string, a logAlert) bool {
	expr, err := parseLogFilter(filter)
	if err != nil {
		return false
	}
	for _, e := range a.Entries {
		if !expr.match(e) {
			return false
		}
	}
	return true
}

// logExpr is a parsed filter node.
type logExpr interface{ match(logEntry) bool }

type (
	andExpr  struct{ l, r logExpr }
	orExpr   struct{ l, r logExpr }
	notExpr  struct{ e logExpr }
	termExpr struct{ term string }
	cmpExpr  struct{ field, op, value string }
)

func (x andExpr) match(e logEntry) bool { return x.l.match(e) && x.r.match(e) }
func (x orExpr) match(e logEntry) bool  { return x.l.match(e) || x.r.match(e) }
func (x notExpr) match(e logEntry) bool { return !x.e.match(e) }

// A bare term searches every field (case-insensitively).
func (x termExpr) match(e logEntry) bool {
	t := strings.ToLower(x.term)
	for _, v := range e {
		if strings.Contains(strings.ToLower(v), t) {
			return true
		}
	}
	return false
}

func (x cmpExpr) match(e logEntry) bool {
	v, ok := e[strings.ToLower(x.field)]
	switch x.op {
	case "=":
		return ok && strings.EqualFold(v, x.value)
	case "!=":
		return !ok || !strings.EqualFold(v, x.value)
	case ":":
		return ok && (x.value == "*" || strings.Contains(strings.ToLower(v), strings.ToLower(x.value)))
	case "=~", "!~":
		re, err := regexp.Compile(x.value)
		if err != nil {
			return false
		}
		return ok && re.MatchString(v) == (x.op == "=~")
	}
	// Ordering comparisons (severity>=ERROR, timestamp>...) narrow on
	// fields the change's entries do not carry.
	return false
}

var errBadFilter = errors.New("unparsable logging filter")

type logToken struct {
	kind string // "(", ")", "op", "word", "str"
	text string
}

var logOperators = []string{"!=", ">=", "<=", "=~", "!~", "=", ":", ">", "<"}

func lexLogFilter(s string) ([]logToken, error) {
	var out []logToken
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(', ')':
			out = append(out, logToken{kind: string(c)})
			i++
		case '"', '\'':
			j := i + 1
			var b strings.Builder
			for ; j < len(s) && s[j] != c; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, errBadFilter
			}
			out = append(out, logToken{kind: "str", text: b.String()})
			i = j + 1
		default:
			if op := operatorAt(s[i:]); op != "" {
				out = append(out, logToken{kind: "op", text: op})
				i += len(op)
				continue
			}
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n\r()\"'", rune(s[j])) && operatorAt(s[j:]) == "" {
				j++
			}
			out = append(out, logToken{kind: "word", text: s[i:j]})
			i = j
		}
	}
	return out, nil
}

func operatorAt(s string) string {
	for _, op := range logOperators {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

type logParser struct {
	toks []logToken
	pos  int
}

func parseLogFilter(s string) (logExpr, error) {
	toks, err := lexLogFilter(s)
	if err != nil {
		return nil, err
	}
	p := &logParser{toks: toks}
	if len(toks) == 0 {
		return nil, errBadFilter
	}
	e, err := p.and()
	if err != nil || p.pos != len(p.toks) {
		return nil, errBadFilter
	}
	return e, nil
}

func (p *logParser) peek() (logToken, bool) {
	if p.pos >= len(p.toks) {
		return logToken{}, false
	}
	return p.toks[p.pos], true
}

func (p *logParser) keyword(k string) bool {
	t, ok := p.peek()
	return ok && t.kind == "word" && t.text == k
}

// and parses a sequence of OR-groups joined by AND or juxtaposition.
func (p *logParser) and() (logExpr, error) {
	left, err := p.or()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind == ")" {
			return left, nil
		}
		if p.keyword("AND") {
			p.pos++
		}
		right, err := p.or()
		if err != nil {
			return nil, err
		}
		left = andExpr{left, right}
	}
}

func (p *logParser) or() (logExpr, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.keyword("OR") {
		p.pos++
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		left = orExpr{left, right}
	}
	return left, nil
}

func (p *logParser) unary() (logExpr, error) {
	if p.keyword("NOT") {
		p.pos++
		e, err := p.unary()
		return notExpr{e}, err
	}
	if t, ok := p.peek(); ok && t.kind == "word" && strings.HasPrefix(t.text, "-") && len(t.text) > 1 {
		p.toks[p.pos].text = t.text[1:]
		e, err := p.unary()
		return notExpr{e}, err
	}
	return p.primary()
}

func (p *logParser) primary() (logExpr, error) {
	t, ok := p.peek()
	if !ok {
		return nil, errBadFilter
	}
	p.pos++
	switch t.kind {
	case "(":
		e, err := p.and()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c.kind != ")" {
			return nil, errBadFilter
		}
		p.pos++
		return e, nil
	case "word":
		if t.text == "AND" || t.text == "OR" {
			return nil, errBadFilter
		}
		if op, ok := p.peek(); ok && op.kind == "op" {
			p.pos++
			v, ok := p.peek()
			if !ok || (v.kind != "word" && v.kind != "str") {
				return nil, errBadFilter
			}
			p.pos++
			return cmpExpr{field: t.text, op: op.text, value: v.text}, nil
		}
		return termExpr{t.text}, nil
	case "str":
		return termExpr{t.text}, nil
	}
	return nil, errBadFilter
}
