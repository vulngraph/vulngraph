package mcp

import "testing"

func TestLiveRole(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]string
		wantRole, wantID string
	}{
		{
			name:     "collector role when no readonly role",
			cfg:      map[string]string{"role_arn": "arn:aws:iam::1:role/collector", "external_id": "x"},
			wantRole: "arn:aws:iam::1:role/collector", wantID: "x",
		},
		{
			name:     "readonly role preferred, inherits shared external_id",
			cfg:      map[string]string{"role_arn": "arn:aws:iam::1:role/collector", "external_id": "x", "readonly_role_arn": "arn:aws:iam::1:role/viewonly"},
			wantRole: "arn:aws:iam::1:role/viewonly", wantID: "x",
		},
		{
			name:     "readonly role with its own external_id",
			cfg:      map[string]string{"role_arn": "arn:aws:iam::1:role/collector", "external_id": "x", "readonly_role_arn": "arn:aws:iam::1:role/viewonly", "readonly_external_id": "y"},
			wantRole: "arn:aws:iam::1:role/viewonly", wantID: "y",
		},
		{
			name:     "static-key connector has no role",
			cfg:      map[string]string{"aws_access_key_id": "AKIA", "aws_secret_access_key": "s"},
			wantRole: "", wantID: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role, id := liveRole(tc.cfg)
			if role != tc.wantRole || id != tc.wantID {
				t.Fatalf("liveRole = (%q, %q), want (%q, %q)", role, id, tc.wantRole, tc.wantID)
			}
		})
	}
}
