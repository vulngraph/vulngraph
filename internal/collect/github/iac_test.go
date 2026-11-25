package github

import "testing"

func TestIsTestFixturePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"root main.tf path", "main.tf", false},
		{"nested real deploy path", "deploy/terraform/security_groups.tf", false},
		{"real terraform dir", "terraform/s3.tf", false},
		// A scanner-fixtures repo's own test/test_project/main.tf, e.g.
		// aws_s3_bucket.vulnerable_bucket / aws_security_group.vulnerable_sg.
		{"test fixture path", "test/test_project/main.tf", true},
		{"tests dir", "tests/main.tf", true},
		{"testdata dir", "testdata/example.tf", true},
		{"example dir", "example/main.tf", true},
		{"examples dir", "examples/basic/main.tf", true},
		{"fixture dir", "fixture/main.tf", true},
		{"fixtures dir", "fixtures/main.tf", true},
		{"terraform module cache", "modules/.terraform/modules/vpc/main.tf", true},
		{"uppercase segment matches case-insensitively", "Test/main.tf", true},
		// Must not false-positive on directories that merely contain the
		// substring but aren't a whole path segment match.
		{"substring latest not test", "latest/main.tf", false},
		{"substring contest not test", "contest-entries/main.tf", false},
		{"substring attestation not test", "attestation/main.tf", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTestFixturePath(tt.path); got != tt.want {
				t.Errorf("isTestFixturePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
