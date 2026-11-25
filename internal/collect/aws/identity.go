package aws

import (
	"context"
	"errors"
	"fmt"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/collect"
)

// stsAPI is the one STS call the collector makes itself (mockable in tests).
type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func defaultSTS(ctx context.Context, cfg map[string]string) (stsAPI, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("defaultSTS: %w", err)
	}
	return sts.NewFromConfig(awsCfg), nil
}

// resolveAccount proves the connector's credentials work and names the account
// they reach, with ONE sts:GetCallerIdentity call before any collector runs.
//
// Without it an expired or revoked credential never surfaced: every collector
// swallowed its own failure as a best-effort skip, Collect returned nil, and
// the connector recorded a successful sync with zero assets. A credential AWS
// rejects here is wrapped as collect.ErrPermanent so the sync records an error
// and is not retried; any other failure (throttle, network) is returned plain
// so it retries.
//
// The account ID comes from the identity itself, which is the only source that
// works for every credential shape: a static-key connector (e.g. SSO-issued
// keys) has no role_arn to parse. aws_account_id and the role ARN are
// fallbacks for a nil identity client (unit tests) or an empty Account field.
func (c *Collector) resolveAccount(ctx context.Context, cfg map[string]string) (string, error) {
	fallback := cfg["aws_account_id"]
	if fallback == "" {
		fallback = arnAccount(cfg["role_arn"])
	}
	if c.newSTS == nil {
		return fallback, nil
	}
	client, err := c.newSTS(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("resolveAccount: %w", err)
	}
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if isCredentialErr(err) || isDenyErr(err) {
			return "", fmt.Errorf("%w: AWS rejected the connector's credentials (sts:GetCallerIdentity) — they are expired, revoked or not trusted by the role; re-issue them or fix the role trust policy: %v", collect.ErrPermanent, err)
		}
		return "", fmt.Errorf("resolveAccount: GetCallerIdentity: %w", err)
	}
	if out != nil {
		if acct := awssdk.ToString(out.Account); acct != "" {
			return acct, nil
		}
	}
	return fallback, nil
}

// awsErrCode returns the AWS API error code carried by err, or "".
func awsErrCode(err error) string {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	return apiErr.ErrorCode()
}

// isCredentialErr reports whether AWS rejected the credential itself — expired,
// revoked, malformed or unknown. No call made with it can succeed.
func isCredentialErr(err error) bool {
	switch awsErrCode(err) {
	case "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId",
		"UnrecognizedClientException", "SignatureDoesNotMatch",
		"InvalidAccessKeyId", "AuthFailure":
		return true
	}
	return false
}

// isDenyErr reports whether AWS authenticated the caller and refused the call:
// a missing IAM permission, or an SCP denying the action or the region.
func isDenyErr(err error) bool {
	switch awsErrCode(err) {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	}
	return false
}

// isPermanentAWSErr reports whether err is an AWS authorization failure that
// retrying cannot fix (bad credential or denied call, including a denied
// sts:AssumeRole). Transient errors (throttling, 5xx, timeouts) are not
// matched, so they still retry.
func isPermanentAWSErr(err error) bool {
	return isCredentialErr(err) || isDenyErr(err)
}

// sweepTally counts collector task outcomes across the whole sweep, so Collect
// can tell "some best-effort families failed" (Partial) apart from "AWS refused
// every single call" — a connector that cannot read anything is broken, and
// reporting it as a partial success hides that behind a green status.
type sweepTally struct {
	mu         sync.Mutex
	ran        int
	authFailed int
}

func (t *sweepTally) started() {
	t.mu.Lock()
	t.ran++
	t.mu.Unlock()
}

// withdraw takes back a started task that turned out to have nothing to read
// (a service AWS does not run in the region), so it neither proves the
// connector can read the account nor dilutes an every-call-refused verdict.
func (t *sweepTally) withdraw() {
	t.mu.Lock()
	t.ran--
	t.mu.Unlock()
}

func (t *sweepTally) failed(err error) {
	if !isPermanentAWSErr(err) {
		return
	}
	t.mu.Lock()
	t.authFailed++
	t.mu.Unlock()
}

// allRefused reports whether at least one task ran and every task failed with
// a credential or deny error.
func (t *sweepTally) allRefused() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ran > 0 && t.authFailed >= t.ran
}

// regionFailure is one regional task's error, held until the whole region has
// run so the region can be judged as a unit (see regionDenied).
type regionFailure struct {
	err  error
	what string
}

// regionDenied reports whether a region is closed to this connector as a whole
// — typically an SCP denying every action outside approved regions. It is true
// only when EVERY task in the region failed and every failure was a deny: one
// success, or one failure of any other kind (throttle, 5xx, panic), means the
// region is reachable and its failures are ordinary gaps that flag the sweep
// partial.
//
// A denied region is excluded from coverage rather than flagging the sweep
// partial. That is safe because nothing in it reached MarkComplete, so
// scope-aware reconciliation never treats its stored assets as deleted; flagging
// it partial instead would keep EVERY sweep partial forever and stop
// reconciliation for all the regions that were fully read.
func regionDenied(tasks int, failures []regionFailure) bool {
	if tasks == 0 || len(failures) < tasks {
		return false
	}
	for _, f := range failures {
		if !isDenyErr(f.err) {
			return false
		}
	}
	return true
}
