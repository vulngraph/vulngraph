package github

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type workflowSnapshot struct {
	Workflows []iac.WorkflowSupplyChain `json:"workflows"`
	Coverage  string                    `json:"coverage"`
}
type workflowInventory struct {
	Assets   []asset.Asset
	Edges    []asset.Edge
	Findings []finding.Finding
	Metadata map[string]map[string]string
	Complete bool
}

func (c *Collector) collectWorkflowVisibility(ctx context.Context, baseURL, token string, repos []repo, prior map[string]map[string]string, apps appInventory) workflowInventory {
	return c.collectWorkflowVisibilityIndexed(ctx, baseURL, token, repos, prior, newAppScopeIndex(apps.Snapshot, repos))
}

func (c *Collector) collectWorkflowVisibilityIndexed(ctx context.Context, baseURL, token string, repos []repo, prior map[string]map[string]string, index appScopeIndex) workflowInventory {
	out := workflowInventory{Metadata: map[string]map[string]string{}, Complete: true}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workflowConcurrency)
	for _, r := range repos {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			out.Complete = false
			return out
		}
		wg.Add(1)
		go func(r repo) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					out.Complete = false
					mu.Unlock()
					log.FromContext(ctx).Error().Interface("panic", rec).Msg("workflow visibility scan failed")
				}
			}()
			snapshot := workflowSnapshot{Coverage: "complete"}
			if r.Archived {
				snapshot.Coverage = "unknown"
			} else if r.DefaultBranch == "" {
				snapshot.Coverage = "unknown"
			} else {
				paths, ok := c.workflowTree(ctx, baseURL, token, r)
				if !ok {
					snapshot.Coverage = "unknown"
				}
				for _, path := range paths {
					content, ok := c.workflowFile(ctx, baseURL, token, r, path)
					if !ok {
						snapshot.Coverage = "unknown"
						continue
					}
					parsed, err := iac.ParseWorkflowSupplyChain(path, []byte(content), r.FullName)
					if err != nil {
						snapshot.Coverage = "unknown"
						continue
					}
					snapshot.Workflows = append(snapshot.Workflows, parsed)
				}
			}
			if snapshot.Coverage != "complete" {
				// Merge successfully read files with old declarations; missing files in an
				// incomplete scan are not evidence that credentials or workflows vanished.
				var old workflowSnapshot
				_ = json.Unmarshal([]byte(prior[r.FullName]["workflow_snapshot"]), &old)
				paths := map[string]bool{}
				for _, w := range snapshot.Workflows {
					paths[w.Path] = true
				}
				for _, w := range old.Workflows {
					if !paths[w.Path] {
						snapshot.Workflows = append(snapshot.Workflows, w)
					}
				}
			}
			sort.Slice(snapshot.Workflows, func(i, j int) bool { return snapshot.Workflows[i].Path < snapshot.Workflows[j].Path })
			assets, edges, findings := projectWorkflowVisibility(baseURL, r, snapshot, index)
			mu.Lock()
			defer mu.Unlock()
			out.Assets = append(out.Assets, assets...)
			out.Edges = append(out.Edges, edges...)
			out.Findings = append(out.Findings, findings...)
			out.Metadata[r.FullName] = map[string]string{"workflow_coverage": snapshot.Coverage, "workflow_snapshot": jsonString(snapshot)}
			if snapshot.Coverage != "complete" {
				out.Complete = false
			}
		}(r)
	}
	wg.Wait()
	return out
}

type appScopeIndex struct {
	GrantKeys     map[int64]string
	Installations map[string][]appInstallation
	Repositories  map[string]repo
	PrivateCounts map[int64]int
	Members       map[int64]map[string]bool
}

func newAppScopeIndex(snapshot appSnapshot, repos []repo) appScopeIndex {
	idx := appScopeIndex{GrantKeys: map[int64]string{}, Installations: map[string][]appInstallation{}, Repositories: map[string]repo{}, PrivateCounts: map[int64]int{}, Members: map[int64]map[string]bool{}}
	clients := map[int64]string{}
	for _, a := range snapshot.Apps {
		clients[a.ID] = a.ClientID
	}
	for _, r := range repos {
		idx.Repositories[strings.ToLower(r.FullName)] = r
	}
	for _, i := range snapshot.Installations {
		idx.GrantKeys[i.ID] = installationGrantKey(i)
		key := strconv.FormatInt(i.AppID, 10) + "@" + strings.ToLower(i.Account.Login)
		idx.Installations[key] = append(idx.Installations[key], i)
		if client := clients[i.AppID]; client != "" {
			key = client + "@" + strings.ToLower(i.Account.Login)
			idx.Installations[key] = append(idx.Installations[key], i)
		}
		idx.Members[i.ID] = map[string]bool{}
		for _, member := range i.Members {
			member = strings.ToLower(member)
			idx.Members[i.ID][member] = true
			if idx.Repositories[member].Visibility == "private" {
				idx.PrivateCounts[i.ID]++
			}
		}
	}
	return idx
}

func projectWorkflowVisibility(baseURL string, r repo, snapshot workflowSnapshot, idx appScopeIndex) ([]asset.Asset, []asset.Edge, []finding.Finding) {
	var assets []asset.Asset
	var edges []asset.Edge
	var findings []finding.Finding
	now := time.Now()
	for _, w := range snapshot.Workflows {
		// Versions isolate changed declarations from old edges during retirement.
		wid := visibilityID(baseURL, "workflow", r.FullName+":"+w.Path+":"+digest(jsonString(w)))
		meta := map[string]string{"repo": r.FullName, "workflow_path": w.Path, "coverage": snapshot.Coverage, "triggers": jsonString(w.Triggers), "credential_references": jsonString(w.CredentialRefs), "reusable_workflows": jsonString(w.Calls), "cloud_declarations": jsonString(w.Cloud), "evidence": "declaration", "execution": "unverified"}
		for _, d := range w.Cloud {
			if d.Provider == "azure" {
				meta["azure_identity_coverage"] = "unknown_client_id_to_principal_mapping"
			}
		}
		assets = append(assets, visibilityAsset(wid, "github_workflow", r.FullName+"/"+w.Path, meta, now))
		edges = append(edges, visibilityEdge(r.FullName, "github_repo", wid, "github_workflow", "github_workflow", "declaration", snapshot.Coverage))
		for _, call := range w.Calls {
			refID := wid + ":call:" + call.Job
			assets = append(assets, visibilityAsset(refID, "github_workflow_reference", call.Target, map[string]string{"repo": r.FullName, "target": call.Target, "secrets": call.Secrets, "condition": call.Condition, "coverage": snapshot.Coverage, "resolution": "declaration_only"}, now))
			edges = append(edges, visibilityEdge(wid, "github_workflow", refID, "github_workflow_reference", "github_workflow_call", "declaration", snapshot.Coverage))
		}
		for _, t := range w.Tokens {
			id := tokenScopeID(wid, t, idx)
			tm := map[string]string{"repo": r.FullName, "workflow_path": w.Path, "job": t.Job, "app_id": t.AppID, "client_id": t.ClientID, "owner": t.Owner, "scope": t.Scope, "repositories": jsonString(t.Repositories), "requested_permissions": jsonString(t.Permissions), "permission_scope": t.PermissionScope, "credential_references": jsonString(t.CredentialRefs), "condition": t.Condition, "coverage": snapshot.Coverage, "resolution": "unknown", "evidence": "declaration", "execution": "unverified"}
			tokenEdges, privateCount, resolution, effective := resolveTokenScope(baseURL, r, t, id, idx, snapshot.Coverage)
			tm["resolution"] = resolution
			tm["effective_permissions"] = jsonString(effective)
			assets = append(assets, visibilityAsset(id, "github_app_token_scope", t.Job+" App token", tm, now))
			declarationEdge := visibilityEdge(wid, "github_workflow", id, "github_app_token_scope", "github_workflow_token", "declaration", snapshot.Coverage)
			declarationEdge.Properties["condition"] = t.Condition
			declarationEdge.Properties["scope"] = t.Scope
			edges = append(edges, declarationEdge)
			for i := range tokenEdges {
				tokenEdges[i].Properties["condition"] = t.Condition
				tokenEdges[i].Properties["scope"] = t.Scope
			}
			edges = append(edges, tokenEdges...)
			if knownRepoVisibility(r.Visibility) && t.PublicInput && t.UntrustedExecution && t.CredentialProvided && t.Condition != "disabled" && snapshot.Coverage == "complete" {
				f := workflowPathFinding(id, "github_app_token_scope", r, w.Path, "github-app-key-untrusted-job", "Untrusted job may expose an App private key despite token narrowing", t.Condition, now)
				f.Metadata["requested_scope"] = t.Scope
				f.Metadata["app_identity"] = t.AppID
				f.Metadata["key_identity"] = "unverified"
				f.Description = "The same job declares an App private-key input and potential untrusted execution. A narrowed installation token does not narrow the private key used to mint it. Key validity, process isolation, runtime conditions and successful credential exposure are unverified. Secret-reference names are not shared-credential identities."
				findings = append(findings, f)
			}
			if knownRepoVisibility(r.Visibility) && t.PublicInput && t.UntrustedExecution && t.Condition != "disabled" && snapshot.Coverage == "complete" && privateCount > 0 && repositoryContentAccess(effective) {
				findings = append(findings, workflowPathFinding(id, "github_app_token_scope", r, w.Path, "github-app-public-input-private-access", fmt.Sprintf("Untrusted-input workflow may expose App access to %d other observed private repositories", privateCount), t.Condition, now))
			}
		}
		for _, d := range w.Cloud {
			if knownRepoVisibility(r.Visibility) && d.PublicInput && d.UntrustedExecution && d.Condition != "disabled" && snapshot.Coverage == "complete" && d.Resolved {
				f := workflowPathFinding(wid, "github_workflow", r, w.Path, "github-workflow-public-input-cloud-"+d.Provider, "Untrusted-input workflow declares access to a cloud identity", d.Condition, now)
				f.Metadata["provider"] = d.Provider
				f.Metadata["target"] = d.Target
				f.Metadata["oidc"] = d.OIDC
				findings = append(findings, f)
			}
			// Keep the existing AWS/GCP join inputs, but retain unknown declarations
			// and execution conditions on the workflow node above.
			if !d.Resolved || d.Condition == "disabled" {
				continue
			}
			decl := iac.DeclaredCIAccess{Provider: d.Provider, WorkflowPath: w.Path, Resolved: true}
			if d.Provider == "aws" {
				decl.TargetARN = d.Target
			}
			if d.Provider == "gcp" {
				decl.TargetSA = d.Target
			}
			if d.Provider == "aws" || d.Provider == "gcp" {
				projected := iac.ProjectDeclaredCIAccess([]iac.DeclaredCIAccess{decl}, r.FullName, now)
				for i := range projected {
					projected[i].Metadata["workflow_id"] = wid
					projected[i].Metadata["condition"] = d.Condition
					projected[i].Metadata["coverage"] = snapshot.Coverage
					projected[i].ID += ":" + digest(wid+d.Job)
					projected[i].Metadata["evidence"] = "declaration"
				}
				assets = append(assets, projected...)
			}
		}
	}
	return assets, edges, findings
}

func resolveObservedTokenScope(baseURL string, r repo, t iac.WorkflowToken, id string, idx appScopeIndex) ([]asset.Edge, int, string, map[string]string) {
	if t.Condition == "disabled" {
		return nil, 0, "disabled", nil
	}
	app := t.AppID
	if t.ClientID != "" {
		app = t.ClientID
	}
	if app == "" || t.Owner == "" || t.Scope == "unknown" || t.PermissionScope == "unknown" {
		return nil, 0, "unknown", nil
	}
	matches := idx.Installations[app+"@"+strings.ToLower(t.Owner)]
	if len(matches) != 1 {
		return nil, 0, "unknown", nil
	}
	install := matches[0]
	if install.SuspendedAt != nil {
		return nil, 0, "suspended", nil
	}
	effective := install.Permissions
	if t.PermissionScope == "selected" {
		effective = map[string]string{}
		for permission, level := range t.Permissions {
			grant := install.Permissions[permission]
			if level == "none" {
				continue
			}
			if permissionRank(grant) < permissionRank(level) || permissionRank(grant) < 1 {
				return nil, 0, "exceeds_grant", nil
			}
			effective[permission] = level
		}
	}
	if t.Scope == "installation" {
		count := idx.PrivateCounts[install.ID]
		if r.Visibility == "private" && idx.Members[install.ID][strings.ToLower(r.FullName)] {
			count--
		}
		edge := visibilityEdge(id, "github_app_token_scope", visibilityID(baseURL, "grant", idx.GrantKeys[install.ID]), "github_app_grant", "github_token_grant", "potential_path", install.Membership)
		edge.Properties["permissions"] = jsonString(effective)
		return []asset.Edge{edge}, count, "installation", effective
	}
	targets := []string{r.FullName}
	if t.Scope == "selected" {
		targets = nil
		for _, name := range t.Repositories {
			targets = append(targets, t.Owner+"/"+name)
		}
	}
	if len(targets) > 500 {
		return nil, 0, "unknown", effective
	}
	var edges []asset.Edge
	privateCount := 0
	resolution := "resolved"
	seen := map[string]bool{}
	for _, target := range targets {
		key := strings.ToLower(target)
		if seen[key] {
			continue
		}
		seen[key] = true
		targetRepo, exists := idx.Repositories[key]
		if !exists || !idx.Members[install.ID][key] {
			resolution = "membership_unknown"
			continue
		}
		if targetRepo.Visibility == "private" && !strings.EqualFold(targetRepo.FullName, r.FullName) {
			privateCount++
		}
		edge := visibilityEdge(id, "github_app_token_scope", targetRepo.FullName, "github_repo", "github_token_repository", "potential_path", install.Membership)
		edge.Properties["permissions"] = jsonString(effective)
		edges = append(edges, edge)
	}
	return edges, privateCount, resolution, effective
}
func repositoryContentAccess(permissions map[string]string) bool {
	return permissions["contents"] == "read" || permissions["contents"] == "write" || permissions["administration"] == "write"
}
func workflowPathFinding(id, typ string, r repo, path, check, title, condition string, now time.Time) finding.Finding {
	severity := finding.SeverityHigh
	if r.Visibility != "public" {
		severity = finding.SeverityMedium
	}
	return finding.Finding{ID: check + ":" + id, Source: "supply_chain", Type: "potential_attack_path", Severity: severity, Title: title, ResourceID: id, ResourceType: typ, ResourceName: r.FullName, Region: "global", CheckID: check, DetectedAt: now,
		Description: "Static workflow declarations combine a public-input trigger, a potential untrusted execution step, and credential access. Credential validity, execution order, environment approvals, runtime conditions and successful execution are unverified. This is a potential path, not confirmed compromise.",
		Remediation: "Isolate untrusted execution from credential-bearing jobs; use the narrowest repository and permission scope, and verify runtime conditions and environment protections.",
		Metadata:    map[string]string{"repo": r.FullName, "source_visibility": r.Visibility, "workflow_path": path, "condition": condition, "evidence": "potential_path", "execution": "unverified"}}
}

func resolveTokenScope(baseURL string, r repo, t iac.WorkflowToken, id string, idx appScopeIndex, coverage string) ([]asset.Edge, int, string, map[string]string) {
	edges, count, resolution, permissions := resolveObservedTokenScope(baseURL, r, t, id, idx)
	app := t.AppID
	if t.ClientID != "" {
		app = t.ClientID
	}
	matches := idx.Installations[app+"@"+strings.ToLower(t.Owner)]
	if len(matches) == 1 && (matches[0].Coverage != "observed" || coverage != "complete" || matches[0].Membership == "unknown" || matches[0].Membership == "partial") {
		for i := range edges {
			edges[i].Properties["coverage"] = "unknown"
		}
		return edges, 0, "unknown", nil
	}
	return edges, count, resolution, permissions
}

func tokenScopeID(workflowID string, t iac.WorkflowToken, idx appScopeIndex) string {
	app := t.AppID
	if t.ClientID != "" {
		app = t.ClientID
	}
	version := "unresolved"
	if matches := idx.Installations[app+"@"+strings.ToLower(t.Owner)]; len(matches) == 1 {
		version = idx.GrantKeys[matches[0].ID]
	}
	return workflowID + ":token:" + t.Job + ":" + strconv.Itoa(t.Step) + ":" + digest(version)
}

func knownRepoVisibility(v string) bool { return v == "public" || v == "private" || v == "internal" }

func permissionRank(level string) int {
	switch level {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	case "none":
		return 0
	default:
		return -1
	}
}
