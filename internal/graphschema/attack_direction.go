package graphschema

// AttackDirection is the direction an ATTACKER moves along an edge type —
// what a blast-radius walk ("if this node is compromised, what can the attacker
// reach?") follows. It is related to, but not the same as, DirectionFor, which
// is the direction RISK SCORE flows:
//
//   - DirBoth edges (can_assume, connected_via_sg, …) are walked both ways.
//     For connected_via_sg that makes member→SG→member an UPPER BOUND, not a
//     claim of reachability: two members can talk only if an ingress rule on
//     the target's SG admits the source's (sg_allows_from), and a blast radius
//     shown to the person approving a change must not under-count.
//   - DirReverse edges whose destination is the ORIGIN of the danger are walked
//     dst→src: sg_allows_from records "src permits ingress FROM dst", so an
//     attacker on dst moves to src; exposed_to_internet points at the internet
//     sentinel, which is where the attacker comes from, not where they go.
//   - DirReverse edges of the capability/contents shape keep src→dst: risk
//     flows dst→src (a readable secret makes the role worth attacking), but a
//     compromised role still reaches the secret, not the other way round.
//
// Both the Ladybug walk (internal/app/graphstore) and the ClickHouse fallback
// (internal/app/asset) use this one classification, so the two paths agree.
// TestAttackDirectionClassifiesEveryReverseType fails when a new DirReverse
// type is added without being placed in one of the two sets.
func AttackDirection(edgeType string) Direction {
	switch {
	case attackReverseTypes[edgeType]:
		return DirReverse
	case DirectionFor(edgeType) == DirBoth:
		return DirBoth
	default:
		return DirForward
	}
}

var (
	attackReverseTypes = map[string]bool{
		"exposed_to_internet": true,
		"sg_allows_from":      true,
	}
	attackForwardDespiteReverse = map[string]bool{
		"accesses_secret": true,
		"protected_by":    true,
		"has_policy":      true,
		"allows_action":   true,
		"runs_package":    true,
		"runs_image":      true,
		"runs_container":  true,
		"depends_on":      true,
		"contains_data":   true,
	}
)
