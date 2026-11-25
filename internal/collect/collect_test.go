package collect

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

type stubCollector struct{}

func (stubCollector) Collect(context.Context, map[string]string) (Result, error) {
	return Result{}, nil
}

func TestRegistry_ForRegistered(t *testing.T) {
	r := NewRegistry()
	r.Register(connector.TypeGitHub, stubCollector{})

	got, err := r.For(connector.TypeGitHub)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestRegistry_ForUnregistered(t *testing.T) {
	r := NewRegistry()
	_, err := r.For(connector.TypeAWS)
	require.ErrorContains(t, err, `no collector registered for type "aws"`)
}

// MarkComplete is the only writer of CompletedEnumerations, so it is also the
// only place a malformed completeness claim can be rejected. Each of these is a
// claim that cannot be attributed to anything, and an unattributable claim must
// not read as coverage — a future enforce mode would take it as licence to
// delete whatever it could not place.
func TestMarkComplete_RejectsUnattributableClaims(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		types []string
		n     int
	}{
		{"no scope", "", []string{"ec2_instance"}, 3},
		{"no types", "eu-west-1/ec2:instances", nil, 3},
		{"empty type", "eu-west-1/ec2:instances", []string{"ec2_instance", ""}, 3},
		{"negative count", "eu-west-1/ec2:instances", []string{"ec2_instance"}, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r Result
			r.MarkComplete(tc.scope, tc.types, tc.n)
			require.Empty(t, r.CompletedEnumerations)
		})
	}
}

// Zero is a real, useful reading: a scope that enumerated everything and found
// nothing is exactly the case where every stored asset under it is a deletion
// candidate, so it must not be confused with "did not report".
func TestMarkComplete_ZeroCountIsARealEnumeration(t *testing.T) {
	var r Result
	r.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, 0)
	require.Equal(t, []ScopeEnumeration{
		{Scope: "eu-west-1/ec2:instances", Types: []string{"ec2_instance"}, Count: 0},
	}, r.CompletedEnumerations)
}

// Partial and CompletedEnumerations describe different granularities and must
// coexist: the whole point is that one failed family no longer erases what the
// other twenty scopes proved.
func TestMarkComplete_CoexistsWithPartial(t *testing.T) {
	r := Result{Partial: true}
	r.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, 7)
	require.True(t, r.Partial)
	require.Len(t, r.CompletedEnumerations, 1)
}
