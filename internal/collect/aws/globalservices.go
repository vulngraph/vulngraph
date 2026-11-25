package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// collectGlobalServices runs the non-regional AWS collectors — Route53,
// IAM, Identity Center (SSO), SCPs, S3, CloudTrail and the account settings — and
// merges their output into result under resultMu. skip is collectAll's own
// best-effort-skip closure: a permission gap or transient error on one global
// service must not discard the entire account inventory or cancel the
// connector.
//
// The calls are independent of each other and run concurrently, fanned out
// like the regional collectors (regionConcurrency, aws.go): run sequentially,
// one slow global collector (e.g. a large Route53 zone set) could consume the
// account's whole remaining sync budget and starve the others. Running them
// concurrently makes the phase's wall-clock the slowest single collector, not
// their sum. Route53's own per-zone pagination is separately fanned out
// (route53ZoneConcurrency) for the same reason S3's per-bucket calls are
// (s3BucketConcurrency).
func collectGlobalServices(
	ctx context.Context,
	cfg map[string]string,
	accountID string,
	now time.Time,
	skip func(err error, region, what string),
	tally *sweepTally,
	resultMu *sync.Mutex,
	result *collect.Result,
) {
	type globalTask struct {
		name string
		fn   func()
	}
	// settings gathers the account-wide keys several tasks below contribute;
	// the asset is emitted once they have all finished.
	settings := newAccountSettings()
	var membership string
	tasks := []globalTask{
		{"route53", func() {
			dnsRecords, dnsEdges, partial, err := collectRoute53(ctx, cfg, accountID, now)
			if err != nil {
				skip(err, "", "route53")
				return
			}
			resultMu.Lock()
			result.Assets = append(result.Assets, dnsRecords...)
			result.Edges = append(result.Edges, dnsEdges...)
			if partial {
				result.Partial = true
			}
			resultMu.Unlock()
		}},
		{"iam", func() {
			iamAssets, iamEdges, err := collectIAM(ctx, cfg, accountID, now)
			if err != nil {
				skip(err, "", "iam")
				return
			}
			resultMu.Lock()
			result.Assets = append(result.Assets, iamAssets...)
			result.Edges = append(result.Edges, iamEdges...)
			resultMu.Unlock()
		}},
		// IAM Identity Center (SSO) — the human-access layer. Clean no-op on
		// any account without an Identity Center instance (returns nil, nil),
		// so it is safe on every connector; only the management/delegated-admin
		// account yields permission sets.
		{"identity center", func() {
			ssoAssets, ssoEdges, ssoProven, err := collectIdentityCenter(ctx, cfg, accountID, now)
			if ssoProven {
				// Recorded even when err != nil below: collectIdentityCenter can
				// prove the capability in one region and then fail in another
				// (each region is independent — see its doc comment), and the
				// proof must not be lost just because the sweep as a whole is
				// about to be marked Partial.
				resultMu.Lock()
				result.MarkCapabilityProven(capabilitySSOAdmin)
				resultMu.Unlock()
			}
			if err != nil {
				skip(err, "", "identity center")
				return
			}
			resultMu.Lock()
			result.Assets = append(result.Assets, ssoAssets...)
			result.Edges = append(result.Edges, ssoEdges...)
			resultMu.Unlock()
		}},
		// Management/delegated-admin connectors read the SCP hierarchy. Every
		// connector also retains its own membership witness, so a new org join
		// cannot reuse a stale standalone exemption from persisted inventory.
		{"scp", func() {
			scpAssets, observedMembership, err := collectSCPs(ctx, cfg, accountID, now)
			membership = observedMembership
			resultMu.Lock()
			result.Assets = append(result.Assets, scpAssets...)
			resultMu.Unlock()
			if err != nil {
				skip(err, "", "scp")
			}
		}},
		// Organizations posture (org_posture.go): the same management or
		// delegated-admin gate as the SCPs; a clean no-op everywhere else.
		{"organizations posture", func() {
			orgAssets, err := collectOrgPosture(ctx, cfg, now)
			if err != nil {
				skip(err, "", "organizations posture")
				return
			}
			resultMu.Lock()
			result.Assets = append(result.Assets, orgAssets...)
			resultMu.Unlock()
		}},
		{"s3", func() {
			s3Buckets, s3Edges, partial, acct, err := collectS3(ctx, cfg, accountID, now)
			settings.set(accountBPASettings(acct))
			if err != nil {
				skip(err, "", "s3")
				return
			}
			resultMu.Lock()
			result.Assets = append(result.Assets, s3Buckets...)
			result.Edges = append(result.Edges, s3Edges...)
			if partial {
				result.Partial = true
			}
			resultMu.Unlock()
		}},
		// CloudTrail audit trails — global service, best-effort. Absence or
		// misconfiguration (not logging, not multi-region) is a compliance gap.
		{"cloudtrail", func() {
			ctAssets, err := collectCloudTrail(ctx, cfg, "global", accountID, now)
			if err != nil {
				skip(err, "", "cloudtrail")
				return
			}
			settings.set(trailRollupSettings(ctAssets))
			settings.set(trailSelectorRollup(ctAssets))
			settings.set(collectCISAlarms(ctx, cfg, accountID, ctAssets))
			resultMu.Lock()
			result.Assets = append(result.Assets, ctAssets...)
			resultMu.Unlock()
		}},
		// Groups, every customer-managed policy, server certificates and the
		// Support role (iam_groups.go). What did read is kept even when another
		// part failed; the failure still flags the sweep partial.
		{"iam account-wide", func() {
			wide := collectIAMAccountWide(ctx, cfg, accountID, now)
			settings.set(wide.settings)
			resultMu.Lock()
			result.Assets = append(result.Assets, wide.assets...)
			resultMu.Unlock()
			if wide.err != nil {
				skip(wide.err, "", "iam account-wide")
			}
		}},
		// CloudFront distributions and the global WAFs that front them
		// (cloudfront.go, waf.go, waf_classic.go).
		{"cloudfront", globalAssets(ctx, cfg, accountID, now, "cloudfront", collectCloudFront, skip, resultMu, result)},
		{"wafv2 cloudfront", globalAssets(ctx, cfg, accountID, now, "wafv2 cloudfront", collectWAFv2CloudFront, skip, resultMu, result)},
		{"waf classic global", globalAssets(ctx, cfg, accountID, now, "waf classic global", collectWAFClassicGlobal, skip, resultMu, result)},
		// Account password policy and security contact (account_settings.go).
		{"account settings", func() {
			if err := collectAccountSettings(ctx, cfg, settings); err != nil {
				skip(err, "", "account settings")
			}
		}},
	}

	globalStarted := time.Now()
	var gwg sync.WaitGroup
	gsem := make(chan struct{}, len(tasks)) // all are independent — no need to throttle below their own count
	for _, task := range tasks {
		gwg.Add(1)
		gsem <- struct{}{}
		go func(task globalTask) {
			defer gwg.Done()
			defer func() { <-gsem }()
			defer func() {
				if rec := recover(); rec != nil {
					// Route through skip(), matching the regional collectors' own
					// panic guard (aws.go): a panic that only logged would leave
					// Partial false and this global service's absence would read
					// as legitimately empty rather than un-fetched.
					skip(fmt.Errorf("panic: %v", rec), "", task.name+" (global)")
				}
			}()
			tally.started()
			task.fn()
		}(task)
	}
	gwg.Wait()
	// The IAM crawl and the account-wide listing both emit customer-managed
	// iam_policy assets; keep one per policy.
	resultMu.Lock()
	result.Assets = dedupePolicyAssets(result.Assets)
	stampOrganizationMembership(result.Assets, accountID, membership)
	resultMu.Unlock()
	if accountID != "" {
		resultMu.Lock()
		result.Assets = append(result.Assets, settings.asset(accountID, now))
		resultMu.Unlock()
	}
	if globalElapsed := time.Since(globalStarted); globalElapsed > slowCollectorThreshold {
		log.FromContext(ctx).Warn().Str("account_id", accountID).
			Dur("elapsed", globalElapsed).
			Msg("global services collection took longer than expected")
	}
}

// globalAssets adapts an asset-only global collector into a task: a failure
// is a best-effort skip, a success appends its assets under resultMu.
func globalAssets(
	ctx context.Context,
	cfg map[string]string,
	accountID string,
	now time.Time,
	what string,
	fn func(context.Context, map[string]string, string, time.Time) ([]asset.Asset, error),
	skip func(err error, region, what string),
	resultMu *sync.Mutex,
	result *collect.Result,
) func() {
	return func() {
		more, err := fn(ctx, cfg, accountID, now)
		if err != nil {
			skip(err, "", what)
			return
		}
		resultMu.Lock()
		result.Assets = append(result.Assets, more...)
		resultMu.Unlock()
	}
}
