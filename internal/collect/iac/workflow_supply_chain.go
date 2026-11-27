package iac

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// WorkflowSupplyChain contains declarations, never credential values or proof
// that a job ran. References are local to this workflow, not credential IDs.
type WorkflowSupplyChain struct {
	Path           string          `json:"path"`
	Triggers       []string        `json:"triggers"`
	Tokens         []WorkflowToken `json:"tokens"`
	Calls          []WorkflowCall  `json:"calls"`
	Cloud          []WorkflowCloud `json:"cloud"`
	CredentialRefs []string        `json:"credential_refs"`
}

type WorkflowToken struct {
	CredentialProvided bool              `json:"credential_provided"`
	Job                string            `json:"job"`
	Step               int               `json:"step"`
	AppID              string            `json:"app_id,omitempty"`
	ClientID           string            `json:"client_id,omitempty"`
	Owner              string            `json:"owner,omitempty"`
	Repositories       []string          `json:"repositories,omitempty"`
	Scope              string            `json:"scope"` // current, selected, installation, unknown
	Permissions        map[string]string `json:"permissions,omitempty"`
	PermissionScope    string            `json:"permission_scope"` // installation, selected, unknown
	CredentialRefs     []string          `json:"credential_refs,omitempty"`
	Condition          string            `json:"condition"` // unconditional, conditional, disabled
	PublicInput        bool              `json:"public_input"`
	UntrustedExecution bool              `json:"untrusted_execution"`
}

type WorkflowCall struct {
	Job       string `json:"job"`
	Target    string `json:"target"`
	Secrets   string `json:"secrets"` // inherit, explicit, none
	Condition string `json:"condition"`
}

type WorkflowCloud struct {
	Job                string `json:"job"`
	Provider           string `json:"provider"`
	Target             string `json:"target,omitempty"`
	Tenant             string `json:"tenant,omitempty"`
	Resolved           bool   `json:"resolved"`
	Condition          string `json:"condition"`
	PublicInput        bool   `json:"public_input"`
	UntrustedExecution bool   `json:"untrusted_execution"`
	OIDC               string `json:"oidc"` // requested, unknown
}

type supplyStep struct {
	Uses string         `yaml:"uses"`
	If   string         `yaml:"if"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
}

type supplyJob struct {
	Environment any          `yaml:"environment"`
	If          string       `yaml:"if"`
	Uses        string       `yaml:"uses"`
	Secrets     any          `yaml:"secrets"`
	Permissions any          `yaml:"permissions"`
	Steps       []supplyStep `yaml:"steps"`
}

var credentialRefRE = regexp.MustCompile(`(?i)\bsecrets(?:\.([a-z_][a-z0-9_]*)|\[['"]([a-z_][a-z0-9_]*)['"]\])`)
var numericAppRE = regexp.MustCompile(`^[0-9]+$`)
var clientAppRE = regexp.MustCompile(`^Iv[A-Za-z0-9.]+$`)
var repoNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var azureIDRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseWorkflowSupplyChain deliberately has no general expression evaluator.
// Unknown expressions, environment protection and conditional execution stay
// explicit. It recognizes exact action names, not prefix lookalikes.
func ParseWorkflowSupplyChain(path string, content []byte, repository string) (WorkflowSupplyChain, error) {
	var doc struct {
		On          yaml.Node            `yaml:"on"`
		Permissions any                  `yaml:"permissions"`
		Jobs        map[string]supplyJob `yaml:"jobs"`
	}
	out := WorkflowSupplyChain{Path: path}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return out, fmt.Errorf("workflow parse: %w", err)
	}
	if doc.Jobs == nil {
		return out, fmt.Errorf("workflow parse: missing jobs")
	}
	out.Triggers = workflowTriggers(doc.On)
	out.CredentialRefs = credentialRefs(string(content))
	owner, _, _ := strings.Cut(repository, "/")
	publicInput := false
	for _, trigger := range out.Triggers {
		switch trigger {
		case "pull_request_target", "pull_request", "issue_comment", "issues", "workflow_run", "repository_dispatch":
			publicInput = true
		}
	}
	jobs := make([]string, 0, len(doc.Jobs))
	for id := range doc.Jobs {
		jobs = append(jobs, id)
	}
	sort.Strings(jobs)
	for _, id := range jobs {
		job := doc.Jobs[id]
		if job.Uses != "" {
			secretMode := "none"
			if job.Secrets != nil {
				secretMode = "explicit"
			}
			if job.Secrets == "inherit" {
				secretMode = "inherit"
			}
			target := job.Uses
			if strings.Contains(target, "${{") {
				target = "unresolved"
			}
			out.Calls = append(out.Calls, WorkflowCall{Job: id, Target: target, Secrets: secretMode, Condition: executionCondition(job.If)})
		}
		untrusted := untrustedJob(job)
		for i, step := range job.Steps {
			action, _, pinned := strings.Cut(strings.ToLower(step.Uses), "@")
			if !pinned {
				continue
			}
			condition := executionCondition(job.If, step.If)
			if job.Environment != nil && condition == "unconditional" {
				condition = "conditional"
			}
			switch action {
			case "actions/create-github-app-token":
				t := WorkflowToken{Job: id, Step: i, Scope: "current", Owner: owner, PermissionScope: "installation", Condition: condition, PublicInput: publicInput, UntrustedExecution: untrusted, Permissions: map[string]string{}}
				app := scalarArg(step.With, "app-id")
				client := scalarArg(step.With, "client-id")
				if numericAppRE.MatchString(app) {
					t.AppID = app
				}
				if client == "" && clientAppRE.MatchString(app) {
					client = app
				}
				if clientAppRE.MatchString(client) {
					t.ClientID = client
				}
				requestedOwner := scalarArg(step.With, "owner")
				if requestedOwner == "${{ github.repository_owner }}" {
					requestedOwner = owner
				}
				if requestedOwner != "" {
					t.Owner = requestedOwner
					t.Scope = "installation"
				}
				if !repoNameRE.MatchString(t.Owner) {
					t.Owner = ""
					t.Scope = "unknown"
				}
				repositories := scalarArg(step.With, "repositories")
				if repositories != "" {
					t.Scope = "selected"
					for _, name := range strings.FieldsFunc(repositories, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
						name = strings.TrimSpace(name)
						if !repoNameRE.MatchString(name) {
							t.Scope = "unknown"
							t.Repositories = nil
							break
						}
						t.Repositories = append(t.Repositories, name)
					}
					if t.Owner == "" {
						t.Scope = "unknown"
					}
				}
				if scalarArg(step.With, "enterprise") != "" || scalarArg(step.With, "github-api-url") != "" {
					t.Scope = "unknown"
				}
				for key, value := range step.With {
					if !strings.HasPrefix(key, "permission-") {
						continue
					}
					if t.PermissionScope != "unknown" {
						t.PermissionScope = "selected"
					}
					level, ok := value.(string)
					if !ok || (level != "read" && level != "write" && level != "admin" && level != "none") {
						t.PermissionScope = "unknown"
						continue
					}
					t.Permissions[strings.ReplaceAll(strings.TrimPrefix(key, "permission-"), "-", "_")] = level
				}
				t.CredentialRefs = credentialRefs(scalarArg(step.With, "private-key"))
				t.CredentialProvided = scalarArg(step.With, "private-key") != ""
				out.Tokens = append(out.Tokens, t)
			case "aws-actions/configure-aws-credentials", "google-github-actions/auth", "azure/login":
				d := WorkflowCloud{Job: id, Condition: condition, PublicInput: publicInput, UntrustedExecution: untrusted, OIDC: "unknown"}
				switch action {
				case "aws-actions/configure-aws-credentials":
					d.Provider = "aws"
					d.Target = resolvedOrEmpty(scalarArg(step.With, "role-to-assume"))
					d.Resolved = strings.HasPrefix(d.Target, "arn:") && strings.Contains(d.Target, ":role/")
				case "google-github-actions/auth":
					d.Provider = "gcp"
					d.Target = resolvedOrEmpty(scalarArg(step.With, "service_account"))
					d.Resolved = strings.Contains(d.Target, "@") && strings.HasSuffix(d.Target, ".gserviceaccount.com")
				case "azure/login":
					d.Provider = "azure"
					d.Target = resolvedOrEmpty(scalarArg(step.With, "client-id"))
					d.Tenant = resolvedOrEmpty(scalarArg(step.With, "tenant-id"))
					d.Resolved = azureIDRE.MatchString(d.Target) && azureIDRE.MatchString(d.Tenant)
				}
				if !d.Resolved {
					d.Target = ""
					d.Tenant = ""
				}
				permissions := doc.Permissions
				if job.Permissions != nil {
					permissions = job.Permissions
				}
				if p, ok := permissions.(map[string]any); ok && p["id-token"] == "write" {
					d.OIDC = "requested"
				}
				out.Cloud = append(out.Cloud, d)
			}
		}
	}
	return out, nil
}

func scalarArg(values map[string]any, key string) string {
	switch v := values[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case int:
		return strconv.Itoa(v)
	case uint64:
		return strconv.FormatUint(v, 10)
	}
	return ""
}

func executionCondition(conditions ...string) string {
	result := "unconditional"
	for _, condition := range conditions {
		condition = strings.TrimSpace(condition)
		if condition == "false" || condition == "${{ false }}" {
			return "disabled"
		}
		if condition != "" && condition != "true" && condition != "${{ true }}" {
			result = "conditional"
		}
	}
	return result
}

func credentialRefs(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range credentialRefRE.FindAllStringSubmatch(content, -1) {
		name := m[1] + m[2]
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func workflowTriggers(n yaml.Node) []string {
	var out []string
	switch n.Kind {
	case yaml.ScalarNode:
		out = append(out, n.Value)
	case yaml.SequenceNode:
		for _, v := range n.Content {
			out = append(out, v.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
	}
	sort.Strings(out)
	return out
}

func untrustedJob(job supplyJob) bool {
	checkedOutUntrusted := false
	for _, step := range job.Steps {
		if executionCondition(step.If) == "disabled" {
			continue
		}
		action, _, _ := strings.Cut(strings.ToLower(step.Uses), "@")
		if action == "actions/checkout" {
			ref := scalarArg(step.With, "ref")
			checkedOutUntrusted = strings.Contains(ref, "github.event.pull_request.head") || strings.Contains(ref, "github.head_ref")
		}
		if step.Run != "" && (checkedOutUntrusted || untrustedExpression(step.Run)) {
			return true
		}
		if strings.HasPrefix(step.Uses, "./") && checkedOutUntrusted {
			return true
		}
	}
	return false
}

func untrustedExpression(s string) bool {
	for _, field := range []string{"github.event.pull_request.title", "github.event.pull_request.body", "github.event.issue.title", "github.event.issue.body", "github.event.comment.body", "github.event.client_payload"} {
		if strings.Contains(s, "${{") && strings.Contains(s, field) {
			return true
		}
	}
	return false
}
