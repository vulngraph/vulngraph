package compliance

import (
	"context"
	"errors"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func controlStateOf(t *testing.T, cov Coverage, id string) string {
	t.Helper()
	for _, st := range cov.Controls {
		if st.Control.ID == id {
			return st.State
		}
	}
	t.Fatalf("control %s missing", id)
	return ""
}

// A cloud with a configured connector is in scope whether or not it has
// produced inventory yet — the requirements rollup's rule. Its checks are not
// assessed (unknown), never out of scope, so a two-cloud control cannot pass
// on the other cloud alone.
func TestCompute_ConfiguredCloudWithoutInventoryIsNotAssessed(t *testing.T) {
	reg := checks.Default()
	awsDNS := evaluableSample(t, "dns-cname-takeover-risk")
	compute := func(conns *fakeConnectors, samples ...asset.Asset) Coverage {
		t.Helper()
		cov, err := NewService(fakeFindings{}, &fakeInventory{samples: samples}, reg, conns).Compute(context.Background())
		require.NoError(t, err)
		return cov
	}
	gcp := conn(connector.TypeGCP, &syncedAt)
	disabled := gcp
	disabled.Enabled = false

	cov := compute(&fakeConnectors{}, awsDNS)
	require.Equal(t, StatePassing, controlStateOf(t, cov, "SEC-DNS-1.1"), "no GCP connector or inventory: out of scope")

	cov = compute(&fakeConnectors{conns: []connector.Connector{gcp}}, awsDNS)
	require.Equal(t, StatePartial, controlStateOf(t, cov, "SEC-DNS-1.1"), "GCP is configured: its check is unknown, not out of scope")
	require.Equal(t, StateNotAssessed, controlStateOf(t, cov, "CIS-GCP-4.1"))
	require.Equal(t, StateNotAssessed, controlStateOf(t, cov, "SOC2-CC6.3-GCP"), "CIEM scope follows the same rule")

	cov = compute(&fakeConnectors{conns: []connector.Connector{disabled}}, awsDNS)
	require.Equal(t, StatePassing, controlStateOf(t, cov, "SEC-DNS-1.1"), "a disabled connector configures nothing, as in the rollup")
}

func TestCompute_ConnectorSourceErrorIsAnError(t *testing.T) {
	_, err := NewService(fakeFindings{}, fullInventory(), checks.Default(), &fakeConnectors{err: errors.New("pg down")}).Compute(context.Background())
	require.ErrorContains(t, err, "pg down", "unreadable connectors must not read as 'nothing configured'")

	_, err = NewService(fakeFindings{}, fullInventory(), checks.Default(), nil).Compute(context.Background())
	require.Error(t, err, "no connector source: scope is unknown")
}

// The inventory read is projected onto every key evaluability reads — each
// mapped check's RequiredKeys and what ciem.Graded reads — so samples split
// on those values and the assessment cannot depend on which member of a
// group ClickHouse read first.
func TestCompute_SamplesProjectOntoEvidenceKeys(t *testing.T) {
	inv := fullInventory()
	_, err := NewService(fakeFindings{}, inv, checks.Default(), &fakeConnectors{}).Compute(context.Background())
	require.NoError(t, err)
	reg := checks.Default()
	for _, c := range controls {
		for _, id := range c.CheckIDs {
			if chk, ok := reg.ByID(id); ok {
				for _, k := range chk.RequiredKeys {
					require.Contains(t, inv.spec.Keys, k, id)
				}
			}
		}
	}
	for _, k := range ciemEvidenceKeys {
		require.Contains(t, inv.spec.Keys, k)
	}
	require.IsIncreasing(t, inv.spec.Keys, "sorted and deduplicated")
}

// sgRuleLists are AWS security group rule lists on both sides of
// sgRulesDecodable: ones it collapses and ones it must leave raw.
var sgRuleLists = []string{
	"", "[]", "null", "[null]", "{not json",
	`[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`,
	`[{"protocol":"-1","from_port":0,"to_port":0,"cidrs":["10.0.0.0/8",null]}]`,
	`[{"from_port":"22"}]`, `[{"From_Port":22}]`, `[{"from_port":1.5}]`,
	`[{"from_port":99999999999}]`, `[{"cidrs":[1]}]`, `[{"cidrs":"0.0.0.0/0"}]`,
	`[{"from_port":22,"from_port":"x"}]`, `[1]`, `{}`,
}

// evidenceCorpus is, for every mapped registry check, assets of its type with
// every subset of its RequiredKeys present under several value assignments,
// plus CIEM principals across tiers and permission-key presence: the shapes
// whose evaluability the sample reduction must preserve.
func evidenceCorpus() []asset.Asset {
	reg := checks.Default()
	var out []asset.Asset
	seen := map[string]bool{}
	for _, c := range controls {
		for _, id := range c.CheckIDs {
			chk, ok := reg.ByID(id)
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			typ := chk.AssetType
			if typ == "" {
				typ = "k8s_role_binding"
			}
			values := append(append([]string{}, chk.ProbeValues...), "observed", "")
			if slices.Contains(chk.RequiredKeys, "ingress") {
				values = append(values, sgRuleLists...)
			}
			n := len(chk.RequiredKeys)
			for mask := 0; mask < 1<<n; mask++ {
				for vi := range values {
					md := map[string]string{}
					for ki, k := range chk.RequiredKeys {
						if mask&(1<<ki) != 0 {
							md[k] = values[(vi+ki)%len(values)]
						}
					}
					out = append(out, asset.Asset{Provider: chk.Provider, Type: typ, Metadata: md})
				}
			}
		}
	}
	for _, sc := range ciemScopes {
		for _, typ := range sc.types {
			for _, tier := range []string{"", ciem.TierUnknown, ciem.TierStandard, "admin"} {
				for mask := 0; mask < 8; mask++ {
					md := map[string]string{}
					if tier != "" {
						md[ciem.MetaPrivilegeTier] = tier
					}
					for ki, k := range []string{"policies", "permissions", "role_grants"} {
						if mask&(1<<ki) != 0 {
							md[k] = `[{"doc":` + strconv.Itoa(mask) + `}]`
						}
					}
					out = append(out, asset.Asset{Provider: sc.provider, Type: typ, Metadata: md})
				}
			}
		}
	}
	return out
}

func allMappedIDs() []string {
	var ids []string
	for _, c := range controls {
		ids = append(ids, c.CheckIDs...)
	}
	return ids
}

// The sample reduction keeps exactly what evaluability reads: on every corpus
// asset, every mapped check's Evaluable and ciem.Graded answer the same on the
// reduced asset as on the raw one. So grouping on the reduced evidence puts
// only identically-answering assets together, whichever is read first.
func TestReduceEvidence_PreservesEvaluability(t *testing.T) {
	reg := checks.Default()
	svc := NewService(fakeFindings{}, &fakeInventory{}, reg, &fakeConnectors{})
	spec := svc.evidenceSpec(allMappedIDs())
	for _, a := range evidenceCorpus() {
		r := reduceEvidence(spec, a)
		require.Equalf(t, ciem.Graded(a), ciem.Graded(r), "Graded on %v → %v", a.Metadata, r.Metadata)
		for _, id := range allMappedIDs() {
			chk, ok := reg.ByID(id)
			if !ok || !chk.AppliesTo(a) {
				continue
			}
			require.Equalf(t, chk.Evaluable(a), chk.Evaluable(r), "%s on %s/%s %v → %v", id, a.Provider, a.Type, a.Metadata, r.Metadata)
		}
	}
}

// The reduction is what keeps the read small: values nothing reads collapse.
func TestSampleByEvidence_CollapsesValuesEvaluabilityDoesNotRead(t *testing.T) {
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	spec := svc.evidenceSpec(allMappedIDs())
	for _, k := range ciemEvidenceValueKeys {
		require.Contains(t, spec.ValueKeys, k)
	}
	require.NotContains(t, spec.ValueKeys, "policies", "AWS grading still needs policy presence only")
	var probeKeys []string
	for _, p := range spec.Probes {
		require.Greater(t, len(p.Keys), 1, "single-key checks need no probe set")
		probeKeys = append(probeKeys, p.Keys...)
	}
	require.Contains(t, probeKeys, "association_id")
	require.NotContains(t, probeKeys, "ingress")

	var sgs, users, eips, unassociated []asset.Asset
	for i := 0; i < 50; i++ {
		n := strconv.Itoa(i)
		sgs = append(sgs, asset.Asset{Provider: asset.ProviderAWS, Type: "security_group", Metadata: map[string]string{
			"ingress": `[{"protocol":"tcp","from_port":` + n + `,"to_port":` + n + `,"cidrs":["10.0.0.` + n + `/32"]}]`,
		}})
		users = append(users, asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user", Metadata: map[string]string{
			ciem.MetaPrivilegeTier: ciem.TierStandard, "policies": `[{"arn":"` + n + `"}]`,
		}})
		eips = append(eips, asset.Asset{Provider: asset.ProviderAWS, Type: "elastic_ip", Metadata: map[string]string{
			"association_id": "eipassoc-" + n, "instance_id": "i-" + n, "network_interface_id": "eni-" + n,
		}})
		unassociated = append(unassociated, asset.Asset{Provider: asset.ProviderAWS, Type: "elastic_ip", Metadata: map[string]string{
			"instance_id": "i-" + n, "network_interface_id": "eni-" + n,
		}})
	}
	require.Len(t, sampleByEvidence(spec, sgs), 1, "decodable rule lists are one shape")
	require.Len(t, sampleByEvidence(spec, users), 1, "policy documents are read for presence only")
	require.Len(t, sampleByEvidence(spec, eips), 1, "a fully-present probe set is not probed")
	require.Len(t, sampleByEvidence(spec, unassociated), 50, "a partly-present probe set is probed over the present values")
	bad := append(append([]asset.Asset{}, sgs...), asset.Asset{Provider: asset.ProviderAWS, Type: "security_group", Metadata: map[string]string{"ingress": "{not json"}})
	require.Len(t, sampleByEvidence(spec, bad), 2, "an undecodable rule list is its own shape")
}

// keySetSamples is the old grouping: one arbitrary member per key set.
func keySetSamples(assets []asset.Asset) []asset.Asset {
	seen := map[string]bool{}
	var out []asset.Asset
	for _, a := range assets {
		keys := make([]string, 0, len(a.Metadata))
		for k := range a.Metadata {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		k := string(a.Provider) + "/" + a.Type + "/" + strings.Join(keys, ",")
		if !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}

func allStates(t *testing.T, inv *fakeInventory) map[string]string {
	t.Helper()
	cov, err := NewService(fakeFindings{}, inv, checks.Default(), &fakeConnectors{}).Compute(context.Background())
	require.NoError(t, err)
	out := map[string]string{}
	for _, st := range cov.Controls {
		out[st.Control.ID] = st.State
	}
	return out
}

// The assessment is the same in every read order. The fake groups as the
// real read does and keeps the first member of each group, so a grouping
// that let members disagree would show here — and the old one (any member
// per key set) does, which is what this test is for.
func TestCompute_AssessmentIsReadOrderIndependent(t *testing.T) {
	corpus := evidenceCorpus()
	rng := rand.New(rand.NewPCG(1, 2))
	shuffled := func() []asset.Asset {
		out := append([]asset.Asset(nil), corpus...)
		rng.Shuffle(len(out), func(a, b int) { out[a], out[b] = out[b], out[a] })
		return out
	}

	want := allStates(t, &fakeInventory{samples: corpus})
	for i := 0; i < 20; i++ {
		order := shuffled()
		require.Equalf(t, want, allStates(t, &fakeInventory{samples: order}), "order %d", i)
	}

	oldWant := allStates(t, &fakeInventory{samples: keySetSamples(corpus)})
	diverged := false
	for i := 0; i < 20 && !diverged; i++ {
		got := allStates(t, &fakeInventory{samples: keySetSamples(shuffled())})
		diverged = !maps.Equal(oldWant, got)
	}
	require.True(t, diverged, "the corpus must catch key-set-only grouping's order dependence")
}
