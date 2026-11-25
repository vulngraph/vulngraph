package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// Registry-level scanning (ecr:GetRegistryScanningConfiguration, one call per
// region) decides whether most repositories are scanned at all: enhanced
// scanning with Amazon Inspector, and basic scanning rules, are configured on
// the registry, not on the repository's scanOnPush flag. Reading scanOnPush
// alone, aws-ecr-scanning-disabled would read every repository covered by a
// registry rule as unscanned.

// registryScanning is a region's registry scanning configuration.
type registryScanning struct {
	scanType string // BASIC or ENHANCED
	rules    []ecrtypes.RegistryScanningRule
}

func readRegistryScanning(ctx context.Context, client ecrAPI) (*registryScanning, error) {
	out, err := client.GetRegistryScanningConfiguration(ctx, &ecr.GetRegistryScanningConfigurationInput{})
	if err != nil {
		return nil, fmt.Errorf("readRegistryScanning: %w", err)
	}
	if out.ScanningConfiguration == nil {
		return nil, fmt.Errorf("readRegistryScanning: response carried no scanning configuration")
	}
	return &registryScanning{
		scanType: string(out.ScanningConfiguration.ScanType),
		rules:    out.ScanningConfiguration.Rules,
	}, nil
}

// ruleFor returns the scan frequency a registry rule applies to the
// repository ("SCAN_ON_PUSH", "CONTINUOUS_SCAN"), or "none" when no rule
// that actually scans matches it. Continuous wins over on-push.
func (r *registryScanning) ruleFor(repo string) string {
	best := "none"
	for _, rule := range r.rules {
		if rule.ScanFrequency == ecrtypes.ScanFrequencyManual || rule.ScanFrequency == "" {
			continue
		}
		for _, f := range rule.RepositoryFilters {
			if !wildcardMatch(awssdk.ToString(f.Filter), repo) {
				continue
			}
			if rule.ScanFrequency == ecrtypes.ScanFrequencyContinuousScan {
				return string(rule.ScanFrequency)
			}
			best = string(rule.ScanFrequency)
		}
	}
	return best
}

// wildcardMatch matches ECR's WILDCARD repository filters, where '*' matches
// any run of characters (including '/', unlike path.Match).
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
