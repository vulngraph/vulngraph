package compliance

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// GET /api/compliance is shaped by CoverageResponse, not the domain type, and
// the contract's arrays stay arrays when the domain carries nil slices.
func TestCoverageResponse_MapsEveryFieldAndKeepsListsLists(t *testing.T) {
	cov := Coverage{
		Total: 2, Passing: 1, Failing: 1, Partial: 0, NotAssessed: 0,
		Controls: []Status{
			{Control: Control{ID: "1.1", Title: "Root MFA", CheckIDs: []string{"aws_root_mfa"}, Frameworks: []string{FrameworkCIS}}, State: StatePassing, Passing: true},
			{Control: Control{ID: "1.2", Title: "No checks yet"}, State: StateFailing},
		},
		Frameworks: []FrameworkCoverage{{Framework: FrameworkCIS, Total: 2, Passing: 1, Failing: 1}},
	}

	raw, err := json.Marshal(coverageResponse(cov))
	require.NoError(t, err)
	require.JSONEq(t, `{
		"total": 2, "passing": 1, "failing": 1, "partial": 0, "not_assessed": 0,
		"controls": [
			{"control": {"id": "1.1", "title": "Root MFA", "check_ids": ["aws_root_mfa"], "frameworks": ["CIS"]}, "state": "passing", "passing": true},
			{"control": {"id": "1.2", "title": "No checks yet", "check_ids": [], "frameworks": []}, "state": "failing", "passing": false}
		],
		"frameworks": [{"framework": "CIS", "total": 2, "passing": 1, "failing": 1, "partial": 0, "not_assessed": 0}]
	}`, string(raw))

	raw, err = json.Marshal(coverageResponse(Coverage{}))
	require.NoError(t, err)
	require.JSONEq(t, `{"total":0,"passing":0,"failing":0,"partial":0,"not_assessed":0,"controls":[],"frameworks":[]}`, string(raw))
}
