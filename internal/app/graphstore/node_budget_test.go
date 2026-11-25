package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The worker's memory budget is three numbers: a deployment's cgroup limit and
// GOMEMLIMIT, and NodeBudget here. Nothing in the pod compares them:
// GOMEMLIMIT at roughly 80% of the limit plus several GiB of non-Go resident
// memory adds up to more than the limit, and the kernel kills the pod by
// arithmetic no runtime check sees. The budget alert compares node count to
// NodeBudget at runtime; this test ties NodeBudget to the memory it claims to
// fit inside. It fails when someone raises NodeBudget without raising the
// limit, or lowers the limit without re-deriving the budget.
//
// referenceLimitMiB/referenceGoMemLimitMiB are an example sizing of
// worker.resources.limits.memory / worker.goMemLimit for a large graph, for
// illustration: the chart ships small defaults (deploy/README.md "Sizing"), so
// the configuration NodeBudget is derived from is recorded here.
const (
	referenceLimitMiB      = 20480
	referenceGoMemLimitMiB = 8192

	// refNonGoKiBPerNode is the per-node sizing rule of thumb: about 23 KiB of
	// non-Go peak resident memory per graph node. It is a planning assumption,
	// not a measurement of any one install; re-derive it from your own graph
	// when sizing. Non-Go is container_memory_rss minus
	// (go_memstats_sys_bytes − go_memstats_heap_released_bytes): subtracting
	// released heap matters, since go_sys alone counts pages the runtime has
	// already returned to the kernel. Size from the PEAK over a pod's whole life,
	// not a sample: the rebuild peak is several times the median and recurs.
	refNonGoKiBPerNode = 23

	// nonGoHeadroomNumerator/Denominator is the fraction of the room above Go's
	// ceiling that the projected non-Go peak may occupy: 4/5, i.e. the alert must
	// fire with 20% of the room still unspent. The margin exists because the
	// per-node figure is a straight average and the tail is what kills.
	nonGoHeadroomNumerator   = 4
	nonGoHeadroomDenominator = 5
)

// TestNodeBudgetFitsTheDeployedMemoryLimit is the guard, pure integer
// arithmetic over the reference configuration: NodeBudget, projected through the
// per-node rule of thumb, must fit inside 4/5 of the room the cgroup limit
// leaves above Go's whole allowance. GOMEMLIMIT bounds only Go; the kernel kills
// on the sum, and Go fills whatever ceiling it is given (go_sys runs right up to
// the ceiling), so the ceiling, not the live heap, is what the non-Go term is
// added to.
func TestNodeBudgetFitsTheDeployedMemoryLimit(t *testing.T) {
	limitMiB := referenceLimitMiB
	goMemLimitMiB := referenceGoMemLimitMiB

	// Room the cgroup leaves for everything that is not Go's sanctioned heap.
	roomMiB := limitMiB - goMemLimitMiB
	require.Positivef(t, roomMiB,
		"GOMEMLIMIT %dMiB is at or above the %dMiB cgroup limit: the limit cannot prevent the kill it is set for",
		goMemLimitMiB, limitMiB)

	// NodeBudget * KiB/node * denominator <= room(KiB) * numerator.
	projectedKiB := int64(NodeBudget) * refNonGoKiBPerNode
	require.LessOrEqualf(t,
		projectedKiB*nonGoHeadroomDenominator,
		int64(roomMiB)*1024*nonGoHeadroomNumerator,
		"NodeBudget %d projects a non-Go peak of ~%dMiB at %d KiB/node, which does not fit inside %d/%d of the %dMiB "+
			"the %dMiB cgroup limit leaves above GOMEMLIMIT %dMiB. Either lower NodeBudget or raise the limit "+
			"(raising goMemLimit makes it worse, because Go fills whatever it is allowed); they must move together.",
		NodeBudget, projectedKiB/1024, refNonGoKiBPerNode,
		nonGoHeadroomNumerator, nonGoHeadroomDenominator, roomMiB, limitMiB, goMemLimitMiB)
}
