package google

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Directory API users.list body is the fixture: the 2-Step Verification
// fields become keys only when the response carried them.
func TestUserMetadata_TwoStepVerification(t *testing.T) {
	var page struct {
		Users []wsUser `json:"users"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"users": [
	  {"id": "1", "primaryEmail": "a@corp.example", "isEnrolledIn2Sv": true, "isEnforcedIn2Sv": false},
	  {"id": "2", "primaryEmail": "b@corp.example", "isEnrolledIn2Sv": false, "isEnforcedIn2Sv": false},
	  {"id": "3", "primaryEmail": "c@corp.example"}
	]}`), &page))
	a := userMetadata(page.Users[0], "false", "false")
	require.Equal(t, "true", a["two_step_enrolled"])
	require.Equal(t, "false", a["two_step_enforced"])
	require.Equal(t, "false", userMetadata(page.Users[1], "false", "false")["two_step_enrolled"])
	c := userMetadata(page.Users[2], "false", "false")
	require.NotContains(t, c, "two_step_enrolled", "an omitted field is unknown, not unenrolled")
	require.NotContains(t, c, "two_step_enforced")
}
