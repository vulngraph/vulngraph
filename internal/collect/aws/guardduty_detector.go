package aws

// guardduty_detector.go — the GuardDuty detector and its protection plans on
// aws_region_settings (FSBP GuardDuty.1, GuardDuty.5-13). guardduty.go pulls
// the detector's findings; this records whether the detector exists and what
// it watches.

import (
	"context"
	"fmt"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

type guardDutyDetectorAPI interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// guardDutyFeatureKeys maps a protection plan to its key. A feature the
// detector does not list (not offered in the region) leaves its key absent.
var guardDutyFeatureKeys = map[gdtypes.DetectorFeatureResult]string{
	gdtypes.DetectorFeatureResultS3DataEvents:         "guardduty_s3_protection",
	gdtypes.DetectorFeatureResultEksAuditLogs:         "guardduty_eks_audit_logs",
	gdtypes.DetectorFeatureResultLambdaNetworkLogs:    "guardduty_lambda_protection",
	gdtypes.DetectorFeatureResultEbsMalwareProtection: "guardduty_malware_protection",
	gdtypes.DetectorFeatureResultRdsLoginEvents:       "guardduty_rds_protection",
	gdtypes.DetectorFeatureResultRuntimeMonitoring:    "guardduty_runtime_monitoring",
}

// readGuardDutyDetector records guardduty_enabled and, only for an enabled
// detector, each protection plan: a disabled detector is the one root cause,
// and ten feature findings per region would repeat it.
//
// The runtime agents (GuardDuty.7/12/13: EKS, ECS Fargate and EC2 automated
// agent management) are recorded only while Runtime Monitoring itself is on,
// for the same reason. EKS also counts the older EKS_RUNTIME_MONITORING
// feature, which accounts that have not migrated still carry.
func (c detectionClients) readGuardDutyDetector(ctx context.Context, meta map[string]string) error {
	list, err := c.guardduty.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return fmt.Errorf("readGuardDutyDetector: list: %w", err)
	}
	if len(list.DetectorIds) == 0 {
		// One detector per account per region; a further page cannot hold one
		// when this page is empty.
		meta["guardduty_enabled"] = "false"
		return nil
	}
	det, err := c.guardduty.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: awssdk.String(list.DetectorIds[0])})
	if err != nil {
		return fmt.Errorf("readGuardDutyDetector: get: %w", err)
	}
	enabled := det.Status == gdtypes.DetectorStatusEnabled
	meta["guardduty_enabled"] = strconv.FormatBool(enabled)
	if !enabled {
		return nil
	}
	var runtime, legacyEKS *gdtypes.DetectorFeatureConfigurationResult
	for i, f := range det.Features {
		if key, ok := guardDutyFeatureKeys[f.Name]; ok {
			meta[key] = strconv.FormatBool(f.Status == gdtypes.FeatureStatusEnabled)
		}
		switch f.Name {
		case gdtypes.DetectorFeatureResultRuntimeMonitoring:
			runtime = &det.Features[i]
		case gdtypes.DetectorFeatureResultEksRuntimeMonitoring:
			legacyEKS = &det.Features[i]
		}
	}
	eks := agentManaged(runtime, gdtypes.FeatureAdditionalConfigurationEksAddonManagement) ||
		agentManaged(legacyEKS, gdtypes.FeatureAdditionalConfigurationEksAddonManagement)
	if runtime != nil && runtime.Status == gdtypes.FeatureStatusEnabled {
		meta["guardduty_ecs_runtime"] = strconv.FormatBool(agentManaged(runtime, gdtypes.FeatureAdditionalConfigurationEcsFargateAgentManagement))
		meta["guardduty_ec2_runtime"] = strconv.FormatBool(agentManaged(runtime, gdtypes.FeatureAdditionalConfigurationEc2AgentManagement))
		meta["guardduty_eks_runtime"] = strconv.FormatBool(eks)
	} else if legacyEKS != nil && legacyEKS.Status == gdtypes.FeatureStatusEnabled {
		meta["guardduty_eks_runtime"] = strconv.FormatBool(eks)
	}
	return nil
}

// agentManaged reports whether the feature is enabled with the given
// automated agent configuration enabled.
func agentManaged(f *gdtypes.DetectorFeatureConfigurationResult, agent gdtypes.FeatureAdditionalConfiguration) bool {
	if f == nil || f.Status != gdtypes.FeatureStatusEnabled {
		return false
	}
	for _, ac := range f.AdditionalConfiguration {
		if ac.Name == agent {
			return ac.Status == gdtypes.FeatureStatusEnabled
		}
	}
	return false
}
