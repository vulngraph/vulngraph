package graphschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttackDirectionClassifiesEveryReverseType(t *testing.T) {
	for _, e := range EdgeTypes {
		if e.Dir != DirReverse {
			require.False(t, attackForwardDespiteReverse[e.Type] || attackReverseTypes[e.Type],
				"%s is not DirReverse in the registry; drop it from the attack direction sets", e.Type)
			continue
		}
		require.True(t, attackReverseTypes[e.Type] != attackForwardDespiteReverse[e.Type],
			"DirReverse edge type %s must be in exactly one of attackReverseTypes / attackForwardDespiteReverse", e.Type)
	}
}

func TestAttackDirection(t *testing.T) {
	require.Equal(t, DirReverse, AttackDirection("sg_allows_from"))
	require.Equal(t, DirReverse, AttackDirection("exposed_to_internet"))
	require.Equal(t, DirForward, AttackDirection("accesses_secret"))
	require.Equal(t, DirBoth, AttackDirection("connected_via_sg"))
}
