package iac

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// S3Backend is one `backend "s3" { ... }` block parsed out of a Terraform
// root module's `terraform {}` block. Only bucket+key are kept —
// they are the join key against a live s3_bucket asset; other backend
// arguments (region, dynamodb_table, encrypt, ...) carry no correlation value
// here and are ignored.
type S3Backend struct {
	Bucket string
	Key    string
}

// StateResource is one managed resource instance recovered from a Terraform
// state file. ARN/ID are the only fields — see ParseTFState for why
// that's a hard constraint, not a convenience.
type StateResource struct {
	Address string // "<type>.<name>", e.g. "aws_iam_role.app"
	ARN     string
	ID      string
}

var (
	// backendBlockRe finds an s3 backend block and captures its body so the
	// bucket/key regexes below can be run against just that body — this
	// keeps a non-s3 backend (gcs, azurerm, ...) from ever matching.
	backendBlockRe  = regexp.MustCompile(`backend\s+"s3"\s*\{([^}]*)\}`)
	backendBucketRe = regexp.MustCompile(`(?m)^\s*bucket\s*=\s*"([^"]*)"`)
	backendKeyRe    = regexp.MustCompile(`(?m)^\s*key\s*=\s*"([^"]*)"`)

	// resourceBlockRe matches a managed `resource "TYPE" "NAME" {` header.
	// Anchored on the `resource` keyword (not `data`) so data blocks never
	// match — a lightweight regex scan rather than pulling in an HCL library.
	resourceBlockRe = regexp.MustCompile(`(?m)^\s*resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"\s*\{`)
)

// ParseTFBackend scans a .tf file's source for `terraform { backend "s3" {
// bucket = "..." key = "..." } }` blocks and returns the bucket/key pairs
// found. A file with no backend block, or a backend of a type other than s3,
// yields an empty slice.
func ParseTFBackend(tf []byte) []S3Backend {
	var out []S3Backend
	for _, m := range backendBlockRe.FindAllStringSubmatch(string(tf), -1) {
		body := m[1]
		bucketM := backendBucketRe.FindStringSubmatch(body)
		keyM := backendKeyRe.FindStringSubmatch(body)
		if bucketM == nil || keyM == nil {
			continue
		}
		out = append(out, S3Backend{Bucket: bucketM[1], Key: keyM[1]})
	}
	return out
}

// ParseTFResourceAddresses scans a .tf file's source for managed `resource
// "TYPE" "NAME" { ... }` blocks and returns their addresses ("TYPE.NAME").
// `data "TYPE" "NAME"` blocks are deliberately excluded — they declare a
// read, not a managed resource, and never appear in a plan/state's resource
// address space the way this parser's output is meant to join against.
func ParseTFResourceAddresses(tf []byte) []string {
	var out []string
	for _, m := range resourceBlockRe.FindAllStringSubmatch(string(tf), -1) {
		out = append(out, m[1]+"."+m[2])
	}
	return out
}

// tfStateFile is the narrow decode target for a Terraform state JSON file.
// Deliberately minimal: attributes has ONLY the two fields ParseTFState is
// permitted to read. Terraform state routinely embeds plaintext secrets
// (DB passwords, access keys, tokens) in a resource instance's attributes
// map; decoding into a map[string]any here would pull every one of those
// values into memory as usable data. Decoding into this struct instead means
// encoding/json silently discards any attribute key other than "arn"/"id" —
// a secret is never even unmarshaled into a typed field, let alone read or
// re-emitted. Do not widen this struct.
type tfStateFile struct {
	Resources []struct {
		Mode      string `json:"mode"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Instances []struct {
			Attributes struct {
				ARN string `json:"arn"`
				ID  string `json:"id"`
			} `json:"attributes"`
		} `json:"instances"`
	} `json:"resources"`
}

// ParseTFState parses a Terraform state file and returns one StateResource
// per managed resource instance (mode:"data" resources are skipped — they
// describe a read, not something Terraform owns). Every attribute other than
// arn/id is discarded by construction: see tfStateFile. A state that is not
// valid JSON is an error, never an empty state: the caller must not read it as
// "manages nothing".
func ParseTFState(state []byte) ([]StateResource, error) {
	var f tfStateFile
	if err := json.Unmarshal(state, &f); err != nil {
		return nil, fmt.Errorf("ParseTFState: %w", err)
	}
	var out []StateResource
	for _, r := range f.Resources {
		if r.Mode != "managed" {
			continue
		}
		address := r.Type + "." + r.Name
		for _, inst := range r.Instances {
			out = append(out, StateResource{
				Address: address,
				ARN:     inst.Attributes.ARN,
				ID:      inst.Attributes.ID,
			})
		}
	}
	return out, nil
}
