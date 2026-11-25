package aws

// region_detection.go — the regional detection services on aws_region_settings:
// AWS Config (CIS AWS 4.3, FSBP Config.1), Security Hub (CIS 5.16), IAM
// Access Analyzer (CIS 2.18), Macie (CIS 3.1.3, FSBP Macie.1/2), Inspector
// (FSBP Inspector.1-4) and the GuardDuty detector (guardduty_detector.go).
//
// Each is "is service X on in this region": one key set per region, so one
// finding per region rather than one per resource it would watch. A service
// that is off is an observation only where AWS says so explicitly (no
// recorder, no detector, a not-subscribed error); any other failure leaves
// the keys absent.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/smithy-go"
)

type configRecorderAPI interface {
	DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
	DescribeDeliveryChannels(context.Context, *configservice.DescribeDeliveryChannelsInput, ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error)
}

type securityHubAPI interface {
	DescribeHub(context.Context, *securityhub.DescribeHubInput, ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

type accessAnalyzerAPI interface {
	ListAnalyzers(context.Context, *accessanalyzer.ListAnalyzersInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
}

type macieAPI interface {
	GetMacieSession(context.Context, *macie2.GetMacieSessionInput, ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error)
	GetAutomatedDiscoveryConfiguration(context.Context, *macie2.GetAutomatedDiscoveryConfigurationInput, ...func(*macie2.Options)) (*macie2.GetAutomatedDiscoveryConfigurationOutput, error)
}

type inspectorAPI interface {
	BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error)
}

// detectionClients are the region's detection-service clients.
type detectionClients struct {
	config    configRecorderAPI
	hub       securityHubAPI
	analyzer  accessAnalyzerAPI
	macie     macieAPI
	guardduty guardDutyDetectorAPI
	inspector inspectorAPI
}

func newDetectionClients(cfg awssdk.Config) detectionClients {
	return detectionClients{
		config:    configservice.NewFromConfig(cfg),
		hub:       securityhub.NewFromConfig(cfg),
		analyzer:  accessanalyzer.NewFromConfig(cfg),
		macie:     macie2.NewFromConfig(cfg),
		guardduty: guardduty.NewFromConfig(cfg),
		inspector: inspector2.NewFromConfig(cfg),
	}
}

// read runs every detection-service read, merging their keys and returning
// every error. The reads are independent: one denied service costs only its
// own keys.
func (c detectionClients) read(ctx context.Context) (map[string]string, []error) {
	meta := map[string]string{}
	var errs []error
	for _, r := range []func(context.Context, map[string]string) error{
		c.readConfig, c.readSecurityHub, c.readAccessAnalyzer, c.readMacie, c.readGuardDutyDetector, c.readInspector,
	} {
		if err := r(ctx, meta); err != nil {
			errs = append(errs, err)
		}
	}
	return meta, errs
}

// serviceLinkedConfigRole is the path of AWS Config's service-linked role,
// which FSBP Config.1 requires the recorder to use.
const serviceLinkedConfigRole = ":role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

// readConfig records the region's customer configuration recorder. Service-
// linked recorders other services create for themselves (ServicePrincipal
// set, e.g. Security Hub's internal one) are not the account's recorder and
// give the account no configuration history, so they are skipped. A region
// with no customer recorder is the observation config_recorder=absent.
func (c detectionClients) readConfig(ctx context.Context, meta map[string]string) error {
	out, err := c.config.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return fmt.Errorf("readConfig: recorders: %w", err)
	}
	var rec *cfgtypes.ConfigurationRecorder
	for i := range out.ConfigurationRecorders {
		if awssdk.ToString(out.ConfigurationRecorders[i].ServicePrincipal) == "" {
			rec = &out.ConfigurationRecorders[i]
			break
		}
	}
	if rec == nil {
		meta["config_recorder"] = "absent"
		return nil
	}
	meta["config_recorder"] = "present"
	meta["config_all_supported"] = strconv.FormatBool(rec.RecordingGroup != nil && rec.RecordingGroup.AllSupported)
	meta["config_service_linked_role"] = strconv.FormatBool(strings.HasSuffix(awssdk.ToString(rec.RoleARN), serviceLinkedConfigRole))

	var errs []error
	st, err := c.config.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{
		ConfigurationRecorderNames: []string{awssdk.ToString(rec.Name)},
	})
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("readConfig: recorder status: %w", err))
	case len(st.ConfigurationRecordersStatus) == 1:
		s := st.ConfigurationRecordersStatus[0]
		meta["config_recording"] = strconv.FormatBool(s.Recording)
		if s.LastStatus != "" {
			meta["config_last_status"] = string(s.LastStatus)
		}
	}
	ch, err := c.config.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{})
	if err != nil {
		errs = append(errs, fmt.Errorf("readConfig: delivery channels: %w", err))
	} else {
		meta["config_delivery_channel"] = strconv.FormatBool(len(ch.DeliveryChannels) > 0)
	}
	return errors.Join(errs...)
}

// readSecurityHub: DescribeHub answers InvalidAccessException ("not
// subscribed to AWS Security Hub") for a region where it is off.
func (c detectionClients) readSecurityHub(ctx context.Context, meta map[string]string) error {
	_, err := c.hub.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	switch {
	case err == nil:
		meta["securityhub_enabled"] = "true"
	case awsErrCode(err) == "InvalidAccessException":
		meta["securityhub_enabled"] = "false"
	default:
		return fmt.Errorf("readSecurityHub: %w", err)
	}
	return nil
}

// readAccessAnalyzer records whether an ACTIVE external-access analyzer
// (ACCOUNT or ORGANIZATION; the unused- and internal-access types answer
// other questions) exists in the region. Every page must be read: a partial
// listing that found none proves nothing.
func (c detectionClients) readAccessAnalyzer(ctx context.Context, meta map[string]string) error {
	var next *string
	for {
		out, err := c.analyzer.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{NextToken: next})
		if err != nil {
			return fmt.Errorf("readAccessAnalyzer: %w", err)
		}
		for _, a := range out.Analyzers {
			if a.Status == aatypes.AnalyzerStatusActive && (a.Type == aatypes.TypeAccount || a.Type == aatypes.TypeOrganization) {
				meta["access_analyzer_active"] = "true"
				return nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			meta["access_analyzer_active"] = "false"
			return nil
		}
		next = out.NextToken
	}
}

// macieNotEnabled reports Macie's answer for a region where it was never
// enabled: an AccessDeniedException whose message says so. Any other
// AccessDenied is a missing permission and stays unknown.
func macieNotEnabled(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException" &&
		strings.Contains(apiErr.ErrorMessage(), "Macie is not enabled")
}

// readMacie records macie_status (ENABLED, PAUSED, or NOT_ENABLED) and, for
// an enabled session, whether automated sensitive data discovery is on.
func (c detectionClients) readMacie(ctx context.Context, meta map[string]string) error {
	s, err := c.macie.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
	switch {
	case err == nil && s != nil:
		meta["macie_status"] = string(s.Status)
	case macieNotEnabled(err):
		meta["macie_status"] = "NOT_ENABLED"
		return nil
	default:
		return fmt.Errorf("readMacie: session: %w", orEmpty(err))
	}
	if meta["macie_status"] != "ENABLED" {
		return nil
	}
	d, err := c.macie.GetAutomatedDiscoveryConfiguration(ctx, &macie2.GetAutomatedDiscoveryConfigurationInput{})
	if err != nil {
		return fmt.Errorf("readMacie: automated discovery: %w", err)
	}
	if d.Status != "" {
		meta["macie_automated_discovery"] = string(d.Status)
	}
	return nil
}

// inspectorOn is a scan type Inspector is running or starting.
func inspectorOn(s inspectortypes.Status) bool {
	return s == inspectortypes.StatusEnabled || s == inspectortypes.StatusEnabling
}

// readInspector records the account's Inspector status in the region and,
// only while Inspector is on, each scan type's status: with Inspector off the
// one inspector_status finding is the root cause, and four more per region
// would repeat it. Lambda code scanning runs on top of Lambda standard
// scanning, so it is recorded only while standard scanning is on.
func (c detectionClients) readInspector(ctx context.Context, meta map[string]string) error {
	out, err := c.inspector.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		return fmt.Errorf("readInspector: %w", err)
	}
	if len(out.Accounts) != 1 || out.Accounts[0].State == nil {
		return errors.New("readInspector: no account status in the answer")
	}
	acct := out.Accounts[0]
	meta["inspector_status"] = string(acct.State.Status)
	rs := acct.ResourceState
	if !inspectorOn(acct.State.Status) || rs == nil {
		return nil
	}
	set := func(key string, s *inspectortypes.State) {
		if s != nil && s.Status != "" {
			meta[key] = string(s.Status)
		}
	}
	set("inspector_ec2", rs.Ec2)
	set("inspector_ecr", rs.Ecr)
	set("inspector_lambda", rs.Lambda)
	if rs.Lambda != nil && inspectorOn(rs.Lambda.Status) {
		set("inspector_lambda_code", rs.LambdaCode)
	}
	return nil
}
