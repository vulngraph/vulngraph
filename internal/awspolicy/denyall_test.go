package awspolicy

import "testing"

func TestHasUnconditionalDenyAll(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{"explicit deny all, array Statement, string fields", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, true},
		{"explicit deny all, array Statement, array fields", `{"Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"]}]}`, true},
		// The single-statement object form (no array wrapper) is legal AWS JSON —
		// this is the case that previously only one of the two duplicate
		// implementations handled; the shared implementation must handle it too.
		{"explicit deny all, single-object Statement", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`, true},
		{"scoped action deny is not deny-all", `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, false},
		{"scoped resource deny is not deny-all", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"arn:aws:s3:::one-bucket"}]}`, false},
		{"allow wildcard is not a deny", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, false},
		// A conditional deny-all only blocks when the condition holds — it is not
		// an unconditional deny and must not be detected as one.
		{"MFA-conditional deny-all is not unconditional deny-all", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`, false},
		{"empty", "", false},
		{"unparseable", "{not json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasUnconditionalDenyAll(tt.doc); got != tt.want {
				t.Errorf("HasUnconditionalDenyAll(%q) = %v, want %v", tt.doc, got, tt.want)
			}
		})
	}
}
