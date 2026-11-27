package github

import (
	"encoding/json"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
)

// workflowClosures closes only paths that a successful new observation rules
// out. Absence from a failed API read, an unknown identity, or inaccessible
// selected membership is never remediation evidence.
func workflowClosures(baseURL string, repos []repo, prior map[string]map[string]string, current workflowInventory, apps appInventory) []collect.FindingClosure {
	idx := newAppScopeIndex(apps.Snapshot, repos)
	var priorApps appSnapshot
	_ = json.Unmarshal([]byte(prior[apps.ID]["snapshot"]), &priorApps)
	oldIdx := newAppScopeIndex(priorApps, repos)
	active := map[string]bool{}
	for _, f := range current.Findings {
		active[f.ID] = true
	}
	var closures []collect.FindingClosure
	for _, r := range repos {
		var old, now workflowSnapshot
		if json.Unmarshal([]byte(prior[r.FullName]["workflow_snapshot"]), &old) != nil {
			continue
		}
		if json.Unmarshal([]byte(current.Metadata[r.FullName]["workflow_snapshot"]), &now) != nil || now.Coverage != "complete" {
			continue
		}
		currentPaths := map[string]iac.WorkflowSupplyChain{}
		for _, w := range now.Workflows {
			currentPaths[w.Path] = w
		}
		for _, w := range old.Workflows {
			oldID := visibilityID(baseURL, "workflow", r.FullName+":"+w.Path+":"+digest(jsonString(w)))
			replacement, exists := currentPaths[w.Path]
			for _, token := range w.Tokens {
				id := "github-app-public-input-private-access:" + tokenScopeID(oldID, token, oldIdx)
				if active[id] {
					continue
				}
				safe := !exists
				if exists {
					matched := false
					for _, next := range replacement.Tokens {
						if next.Job == token.Job && next.Step == token.Step {
							matched = true
							safe = safe || tokenPathRuledOut(baseURL, r, next, idx, apps.Snapshot.Coverage)
						}
					}
					safe = safe || !matched
				}
				if safe {
					closures = append(closures, pathClosure(id))
				}
			}
			for _, token := range w.Tokens {
				id := "github-app-key-untrusted-job:" + tokenScopeID(oldID, token, oldIdx)
				if active[id] {
					continue
				}
				safe := !exists
				if exists {
					risky := false
					for _, next := range replacement.Tokens {
						if next.Job == token.Job && next.Step == token.Step && next.CredentialProvided && next.PublicInput && next.UntrustedExecution && next.Condition != "disabled" {
							risky = true
						}
					}
					safe = safe || !risky
				}
				if safe && token.CredentialProvided {
					closures = append(closures, pathClosure(id))
				}
			}
			for _, cloud := range w.Cloud {
				id := "github-workflow-public-input-cloud-" + cloud.Provider + ":" + oldID
				if active[id] {
					continue
				}
				safe := !exists
				if exists {
					potential := false
					for _, next := range replacement.Cloud {
						if next.Provider == cloud.Provider && next.PublicInput && next.UntrustedExecution && next.Condition != "disabled" {
							potential = true
						}
					}
					safe = safe || !potential
				}
				if safe {
					closures = append(closures, pathClosure(id))
				}
			}
		}
	}
	return closures
}

func tokenPathRuledOut(baseURL string, r repo, t iac.WorkflowToken, idx appScopeIndex, coverage string) bool {
	if !t.PublicInput || !t.UntrustedExecution || t.Condition == "disabled" {
		return true
	}
	_, count, resolution, permissions := resolveTokenScope(baseURL, r, t, "", idx, "complete")
	if resolution == "suspended" || resolution == "exceeds_grant" {
		return true
	}
	if resolution == "resolved" {
		return count == 0 || !repositoryContentAccess(permissions)
	}
	if resolution == "installation" {
		if !repositoryContentAccess(permissions) {
			return true
		}
		app := t.AppID
		if t.ClientID != "" {
			app = t.ClientID
		}
		matches := idx.Installations[app+"@"+strings.ToLower(t.Owner)]
		return count == 0 && len(matches) == 1 && matches[0].Membership == "complete"
	}
	// A complete authoritative installation inventory can prove an installation
	// removed, but an unresolved expression cannot identify which one was used.
	if coverage == "complete" && t.AppID != "" && t.Owner != "" && t.Scope != "unknown" {
		return len(idx.Installations[t.AppID+"@"+strings.ToLower(t.Owner)]) == 0
	}
	return false
}
func pathClosure(id string) collect.FindingClosure {
	return collect.FindingClosure{ID: id, Source: "supply_chain", Reason: finding.ReasonFixed, Note: "Complete GitHub observation rules out the previously reported potential path; no execution was asserted."}
}
