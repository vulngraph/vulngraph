package compliance

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// This file is a Go statement of what inventorySamples computes in
// ClickHouse, so the service tests group assets as the real read does. It
// mirrors the SQL; the SQL itself runs only in repo_integration_test.go.

// sampleByEvidence returns, per distinct (provider, type, reduced evidence),
// the first asset of the input carrying it, reduced.
func sampleByEvidence(spec EvidenceSpec, assets []asset.Asset) []asset.Asset {
	seen := map[string]bool{}
	var out []asset.Asset
	for _, a := range assets {
		r := reduceEvidence(spec, a)
		k := evidenceGroupKey(r)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

func evidenceGroupKey(a asset.Asset) string {
	keys := make([]string, 0, len(a.Metadata))
	for k := range a.Metadata {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([][2]string, len(keys))
	for i, k := range keys {
		pairs[i] = [2]string{k, a.Metadata[k]}
	}
	b, _ := json.Marshal(pairs)
	return string(a.Provider) + "\x00" + a.Type + "\x00" + string(b)
}

// reduceEvidence is the SQL's projection and multiIf, branch for branch.
func reduceEvidence(spec EvidenceSpec, a asset.Asset) asset.Asset {
	raw := map[string]string{}
	for _, k := range spec.Keys {
		if v, ok := a.Metadata[k]; ok {
			raw[k] = v
		}
	}
	out := asset.Asset{Provider: a.Provider, Type: a.Type, Metadata: make(map[string]string, len(raw))}
	for k, v := range raw {
		switch {
		case k == "permissions":
			if v != "" {
				v = "observed"
			}
			out.Metadata[k] = v
		case slices.Contains(spec.ValueKeys, k):
			out.Metadata[k] = v
		case probed(spec, a, raw, k):
			out.Metadata[k] = v
		case a.Provider == asset.ProviderAWS && a.Type == "security_group" && (k == "ingress" || k == "egress"):
			if sgRulesDecodableMirror(v) {
				v = "[]"
			}
			out.Metadata[k] = v
		default:
			out.Metadata[k] = ""
		}
	}
	return out
}

func probed(spec EvidenceSpec, a asset.Asset, present map[string]string, k string) bool {
	for _, p := range spec.Probes {
		if p.Provider != string(a.Provider) || (p.Type != "" && p.Type != a.Type) || !slices.Contains(p.Keys, k) {
			continue
		}
		for _, pk := range p.Keys {
			if _, ok := present[pk]; !ok {
				return true
			}
		}
	}
	return false
}

// sgRulesDecodableMirror is sgRulesDecodable: an empty value, or a JSON array
// of objects with distinct, exactly-spelled sgIngressRule keys of the right
// JSON types.
func sgRulesDecodableMirror(v string) bool {
	if v == "" {
		return true
	}
	if !json.Valid([]byte(v)) || !strings.HasPrefix(strings.TrimSpace(v), "[") {
		return false
	}
	var rules []json.RawMessage
	if err := json.Unmarshal([]byte(v), &rules); err != nil {
		return false
	}
	for _, r := range rules {
		if !sgRuleShapeOK(r) {
			return false
		}
	}
	return true
}

func sgRuleShapeOK(r json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(r))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		key, _ := tok.(string)
		if seen[key] {
			return false
		}
		seen[key] = true
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return false
		}
		s := string(val)
		switch key {
		case "protocol":
			if s != "null" && !strings.HasPrefix(s, `"`) {
				return false
			}
		case "from_port", "to_port":
			if _, err := strconv.ParseInt(s, 10, 32); s != "null" && err != nil {
				return false
			}
		case "cidrs":
			if s == "null" {
				continue
			}
			var elems []json.RawMessage
			if !strings.HasPrefix(s, "[") || json.Unmarshal(val, &elems) != nil {
				return false
			}
			for _, e := range elems {
				if string(e) != "null" && !strings.HasPrefix(string(e), `"`) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
