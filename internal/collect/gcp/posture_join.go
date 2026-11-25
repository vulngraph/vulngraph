package gcp

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// The joins below run once every family has collected, because each grades
// one asset from another family's data. Each leaves its key absent when the
// asset it needs was not observed this sweep — an unread service account,
// subnet or certificate is unknown, never clean — unless a violation was
// already seen, which stands on its own.

// projectAccountID is the project's cloud_account anchor ID (iam_project.go).
func projectAccountID(projectID string) string { return "gcp:" + projectID }

// mergeProjectSettings adds project-wide settings to the project's ONE
// cloud_account asset, so a project-level control yields one finding. The
// IAM family normally creates that asset; when it did not, a bare one is
// created — the IAM keys stay absent and read as unknown.
func mergeProjectSettings(assets []asset.Asset, projectID string, md map[string]string, now time.Time) []asset.Asset {
	if len(md) == 0 {
		return assets
	}
	id := projectAccountID(projectID)
	for i := range assets {
		if assets[i].ID == id && assets[i].Type == "cloud_account" {
			if assets[i].Metadata == nil {
				assets[i].Metadata = map[string]string{}
			}
			maps.Copy(assets[i].Metadata, md)
			return assets
		}
	}
	base := map[string]string{"account_id": projectID, "provider": "gcp"}
	maps.Copy(base, md)
	return append(assets, asset.Asset{
		ID: id, Name: projectID, Type: "cloud_account", Provider: asset.ProviderGCP, Region: "global",
		AccountID: projectID, Metadata: base, DiscoveredAt: now, LastSeen: now,
	})
}

// gkeNodeRoleAdmin reports whether a role makes a node service account
// over-privileged for CIS GKE 5.2.1: a basic role, or any admin role. Every
// pod on the node can mint the account's token from the metadata server.
func gkeNodeRoleAdmin(role string) bool {
	return role == "roles/owner" || role == "roles/editor" || strings.Contains(strings.ToLower(role), "admin")
}

// annotateGKENodeSAs grades each cluster's dedicated node service accounts
// by the roles the IAM family resolved for them (node_pools_privileged_sa).
// A node account from another project, or one the IAM family did not read,
// is unknown.
func annotateGKENodeSAs(assets []asset.Asset) {
	roles := map[string]string{}
	for _, a := range assets {
		if a.Type == "gcp_service_account" {
			if r, ok := a.Metadata["roles"]; ok {
				roles[a.Name] = r
			}
		}
	}
	for i := range assets {
		a := &assets[i]
		pairs, ok := a.Metadata["node_pool_service_accounts"]
		if a.Type != "gke_cluster" || !ok {
			continue
		}
		var bad []string
		unknown := false
		for _, pair := range splitList(pairs) {
			pool, email, _ := strings.Cut(pair, "=")
			r, seen := roles[email]
			if !seen {
				unknown = true
				continue
			}
			if slices.ContainsFunc(splitList(r), gkeNodeRoleAdmin) {
				bad = append(bad, pool)
			}
		}
		if len(bad) > 0 || !unknown {
			a.Metadata["node_pools_privileged_sa"] = strings.Join(bad, ",")
		}
	}
}

// annotateProxyCerts names the self-managed certificates each TLS target
// proxy serves (CIS GKE 5.6.7), from the certificate inventory.
func annotateProxyCerts(assets []asset.Asset) {
	certType := map[string]string{}
	names := map[string]string{}
	for _, a := range assets {
		if a.Type == "gcp_ssl_certificate" && a.Metadata["self_link"] != "" {
			certType[a.Metadata["self_link"]] = a.Metadata["type"]
			names[a.Metadata["self_link"]] = lastSegment(a.Metadata["self_link"])
		}
	}
	for i := range assets {
		a := &assets[i]
		links, ok := a.Metadata["certificate_links"]
		if a.Type != "gcp_target_proxy" || !ok {
			continue
		}
		var self []string
		unknown := false
		for _, l := range splitList(links) {
			t, seen := certType[l]
			switch {
			case !seen:
				unknown = true
			case t == "SELF_MANAGED":
				self = append(self, names[l])
			}
		}
		if len(self) > 0 || !unknown {
			a.Metadata["self_managed_certificates"] = strings.Join(self, ",")
		}
	}
}

// googleProxyRanges are the only sources CIS GCP 3.12 lets reach instances
// behind IAP: the Google Cloud load balancer and health-check ranges, and
// IAP's TCP-forwarding range.
var googleProxyRanges = []string{"35.191.0.0/16", "130.211.0.0/22", "35.235.240.0/20"}

// annotateIAPBypass lists, for each IAP-protected backend service, the
// enabled ingress allow rules that admit its instances from anywhere other
// than Google's proxy ranges — a path to the backend that skips IAP's
// authentication. firewallsKnown is whether the firewall family read every
// rule; an instance missing from the sweep makes the answer unknown.
func annotateIAPBypass(assets []asset.Asset, firewallsKnown bool) {
	instances := map[string]asset.Asset{}
	var rules []asset.Asset
	for _, a := range assets {
		switch a.Type {
		case "gce_instance":
			instances[a.ID] = a
		case "gcp_firewall":
			rules = append(rules, a)
		}
	}
	for i := range assets {
		a := &assets[i]
		members, ok := a.Metadata["iap_backend_instances"]
		if a.Type != "gcp_backend_service" || !ok {
			continue
		}
		bad := map[string]bool{}
		unknown := !firewallsKnown
		for _, id := range splitList(members) {
			in, seen := instances[id]
			if !seen {
				unknown = true
				continue
			}
			for _, r := range rules {
				if firewallAdmitsBypass(r, in) {
					bad[r.Name] = true
				}
			}
		}
		if len(bad) > 0 || !unknown {
			a.Metadata["iap_bypass_firewall_rules"] = strings.Join(sortedKeys(bad), ",")
		}
	}
}

// firewallAdmitsBypass reports whether an enabled ingress allow rule applies
// to the instance and admits a source other than Google's proxy ranges:
// another range, a source tag or a source service account (a rule naming
// neither ranges nor tags selects its sources by service account).
func firewallAdmitsBypass(fw, in asset.Asset) bool {
	m := fw.Metadata
	if m["disabled"] != "false" || m["direction"] != "INGRESS" || m["allowed"] == "" ||
		m["network"] != in.Metadata["network"] {
		return false
	}
	tags, sas := splitList(m["target_tags"]), splitList(m["target_sas"])
	instTags := splitList(in.Metadata["network_tags"])
	instSA := strings.TrimPrefix(in.Metadata["exec_role"], "serviceAccount:")
	applies := (len(tags) == 0 && len(sas) == 0) ||
		slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(instTags, t) }) ||
		slices.Contains(sas, instSA)
	if !applies {
		return false
	}
	ranges := splitList(m["source_ranges"])
	if len(ranges) == 0 || m["source_tags"] != "" {
		return true
	}
	return slices.ContainsFunc(ranges, func(r string) bool { return !slices.Contains(googleProxyRanges, r) })
}

// splitList splits a comma-joined metadata list, dropping empty entries.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// annotateGKENodes marks a GKE node VM gke_node_pool_graded=true when its
// cluster was read whole this sweep and the cluster carries the node-pool
// service-account and private-nodes verdicts — the per-cluster findings
// that let the per-VM default-SA and public-IP checks step aside. A node
// whose cluster listing failed or missed zones, or whose pool settings came
// back unread, gets no mark and is graded like any other VM.
func annotateGKENodes(assets []asset.Asset, gkeComplete bool) {
	if !gkeComplete {
		return
	}
	type cluster struct{ location string }
	graded := map[string][]cluster{}
	for _, a := range assets {
		if a.Type != "gke_cluster" {
			continue
		}
		_, sa := a.Metadata["node_pools_default_sa"]
		_, priv := a.Metadata["node_pools_public_nodes"]
		if sa && priv {
			graded[a.Name] = append(graded[a.Name], cluster{location: a.Region})
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "gce_instance" {
			continue
		}
		if _, node := a.Tags["goog-gke-node"]; !node {
			continue
		}
		for _, c := range graded[a.Tags["goog-k8s-cluster-name"]] {
			// A zonal cluster's location is the node's zone; a regional
			// cluster's is the zone's region.
			if a.Region == c.location || strings.HasPrefix(a.Region, c.location+"-") {
				a.Metadata["gke_node_pool_graded"] = "true"
				break
			}
		}
	}
}
