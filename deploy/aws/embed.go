// Package awsdeploy embeds graph's AWS CloudFormation templates so the binary
// can serve them to the aws_org setup screen (ADR 091).
package awsdeploy

import "embed"

// Templates holds every *.yaml template in this directory.
//
//go:embed *.yaml
var Templates embed.FS
