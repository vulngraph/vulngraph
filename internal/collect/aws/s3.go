package aws

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// s3BucketConcurrency bounds concurrent per-bucket describe calls (mirroring
// ssmInventoryConcurrency's reasoning): each bucket needs ~8 sequential AWS
// calls, and doing them serially can burn through the account's shared sync
// budget before every bucket is reached. Bounded fan-out fixes the wall-clock
// cost without risking AWS's (much higher) S3 rate limits.
const s3BucketConcurrency = 8

// s3API is the slice of the S3 client the collector uses (mockable in tests).
type s3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketWebsite(context.Context, *s3.GetBucketWebsiteInput, ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error)
	// GetBucketPolicy returns the policy document itself, for the TLS-only and
	// cross-account grades (s3_policy.go); GetBucketPolicyStatus only says
	// whether it is public.
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	// Ownership controls, ACL use and lifecycle rules (s3_exposure.go).
	GetBucketOwnershipControls(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	GetBucketLifecycleConfiguration(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
}

// collectS3 builds an S3 client and lists every bucket in the account. S3 is a
// global namespace (ListBuckets returns all buckets regardless of region), so
// it is collected once, not per region. The account-level Block Public Access
// setting is read once up front and folded into every bucket's grade, and
// returned so the account-settings asset can carry it.
func collectS3(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, accountBPA, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, nil, false, accountBPA{}, fmt.Errorf("collectS3: %w", err)
	}
	// ListBuckets and GetBucketLocation answer from any region; every OTHER
	// per-bucket call must be signed for the bucket's OWN region, which
	// collectS3Buckets does per call via regionOpt.
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	control := s3control.NewFromConfig(awsCfg)
	acct := fetchAccountBPA(ctx, control, accountID)
	if !acct.observed {
		log.FromContext(ctx).Warn().Str("account_id", accountID).
			Msg("s3: account-level Block Public Access unreadable (check s3:GetAccountPublicAccessBlock); buckets graded on their own settings only")
	}
	assets, edges, partial, err := collectS3Buckets(ctx, s3.NewFromConfig(awsCfg), acct, accountID, now)
	if err != nil {
		return nil, nil, false, acct, err
	}
	// Multi-Region Access Points are account-global like the buckets. A failed
	// listing loses only them, and flags the sweep partial so their absence
	// is not read as deletion.
	mraps, mrapErr := listMultiRegionAccessPoints(ctx, control, partitionFor(awsCfg.Region), accountID, now)
	if mrapErr != nil {
		log.FromContext(ctx).Warn().Err(mrapErr).Str("account_id", accountID).
			Msg("s3: Multi-Region Access Point listing failed (check s3:ListMultiRegionAccessPoints); sweep flagged partial")
		partial = true
	}
	return append(assets, mraps...), edges, partial, acct, nil
}

// regionOpt retargets a single S3 call at the bucket's own region. Every
// per-bucket call except ListBuckets/GetBucketLocation must be signed for the
// bucket's own region — S3 answers a cross-region request with a redirect the
// SDK does not follow — so every describe call needs this option.
//
// aws-sdk-go-v2 copies Client.options and applies these functions to the copy
// before resolving the endpoint, so setting Region here re-signs and
// re-routes that one call without a per-bucket or per-region client.
//
// An empty region means GetBucketLocation itself failed; the call then goes
// out unretargeted and, if the bucket is not in us-east-1, fails — leaving the
// setting unobserved rather than guessing the bucket's region.
func regionOpt(region string) func(*s3.Options) {
	return func(o *s3.Options) {
		if region != "" {
			o.Region = region
		}
	}
}

// normalizeBucketRegion maps a GetBucketLocation LocationConstraint onto a
// real region code. Two legacy answers are not region codes: an empty
// constraint means us-east-1 (S3 predates regions), and "EU" is the original
// alias for eu-west-1 — feeding either to the endpoint resolver verbatim
// would produce a nonexistent host.
func normalizeBucketRegion(constraint string) string {
	switch constraint {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return constraint
	}
}

// collectS3Buckets lists and describes every bucket. partial is true when a
// listed bucket was not emitted — the deadline hit before it was queued, or its
// describe panicked — so its absence must not read as a deletion.
func collectS3Buckets(ctx context.Context, client s3API, acct accountBPA, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	// Paginate to exhaustion: ListBuckets caps buckets per call and hands back a
	// ContinuationToken. A truncated page is not just incomplete inventory —
	// SyncWorker treats a non-partial result as proof of a complete
	// enumeration and resolves findings for every asset the sweep didn't
	// return, so a truncated page would read as "these buckets were deleted".
	// Any page error aborts the whole listing, so a successful return is a
	// completeness guarantee.
	var buckets []s3types.Bucket
	var token *string
	for {
		out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token})
		if err != nil {
			return nil, nil, false, fmt.Errorf("collectS3Buckets: list: %w", err)
		}
		buckets = append(buckets, out.Buckets...)
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			break
		}
		token = out.ContinuationToken
	}

	logger := log.FromContext(ctx)
	var (
		wg                sync.WaitGroup
		sem               = make(chan struct{}, s3BucketConcurrency)
		mu                sync.Mutex
		assets            []asset.Asset
		edges             []asset.Edge
		unresolvedRegions int
		lastRegionErr     error
		dropped           int // listed buckets never emitted (deadline or panic)
	)
	started := time.Now()
	totalBuckets := 0
	for _, b := range buckets {
		name := awssdk.ToString(b.Name)
		if name == "" {
			continue
		}
		totalBuckets++
		if ctx.Err() != nil {
			// Deadline/cancellation already hit; no point queuing more — but
			// every bucket not queued is unemitted, not deleted.
			mu.Lock()
			dropped++
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("bucket", name).
						Msg("s3 bucket collection panicked; bucket omitted, sweep flagged partial")
					mu.Lock()
					dropped++
					mu.Unlock()
				}
			}()

			region, regionErr := bucketRegion(ctx, client, name)
			// Every call below this line is signed for the bucket's own region.
			opt := regionOpt(region)
			// Each input is read once and shared by every grade below.
			own := readBucketBlock(ctx, client, name, opt)
			policy := readBucketPolicy(ctx, client, name, opt)
			acl := readBucketACL(ctx, client, name, opt)
			exp := bucketPublicAccess(ctx, client, name, opt, acct, own, policy, acl)
			publicAccess := exp.tier
			meta := map[string]string{
				"public_access": publicAccess,
			}
			// bpa_all_enabled: all four Block Public Access flags are on for
			// the bucket, counting the account's. Absent when the bucket's own
			// block was unreadable and the account's alone does not settle it.
			// bucket_bpa_all_enabled is the bucket's own four flags alone.
			// public_read / public_write split a confirmed exposure by what
			// it grants; each is absent unless every input it needs was read.
			for k, v := range map[string]string{
				"bpa_all_enabled":        exp.bpaAll,
				"bucket_bpa_all_enabled": own.allEnabled(),
				"public_read":            exp.publicRead,
				"public_write":           exp.publicWrite,
				"acl_non_owner_grants":   acl.nonOwnerGrants(),
			} {
				if v != "" {
					meta[k] = v
				}
			}
			if acl.ownershipObserved {
				meta["object_ownership"] = acl.ownership
			}
			if policy.observed {
				for k, v := range bucketPolicyFacts(policy.doc, name, accountID) {
					meta[k] = v
				}
			}
			if rules, observed := bucketLifecycleRules(ctx, client, name, opt); observed {
				meta["lifecycle_rules_enabled"] = rules
			}
			// `public` is derived from the GRADE, not from "the grade is
			// non-empty": PublicAccessNone (locked down) is an observed
			// not-public, and publicAccessUnknown (a coverage gap) omits the key
			// — "false" there would close a real public-bucket finding.
			if publicAccess != publicAccessUnknown {
				meta["public"] = fmt.Sprintf("%t", publicAccess == asset.PublicAccessConfirmed || publicAccess == asset.PublicAccessPossible)
			}
			if website, observed := bucketWebsiteEnabled(ctx, client, name, opt); observed {
				meta["website"] = website
			}
			// Every per-bucket setting below is OMITTED when its call failed. The
			// checks that read them (aws-s3-no-versioning, -mfa-delete-disabled,
			// -access-logging-disabled) and the DSPM encryption signal all test a
			// positive value, so an absent key is silence and a failed describe
			// cannot mint a finding. Present-and-empty means "read it, there is
			// none".
			if algo, observed := bucketEncryptionAlgorithm(ctx, client, name, opt); observed {
				meta["encryption"] = algo
			}
			if status, observed := bucketLoggingStatus(ctx, client, name, opt); observed {
				meta["logging"] = status
			}
			if versioning, mfaDelete, observed := bucketVersioningAndMFA(ctx, client, name, opt); observed {
				meta["versioning"] = versioning
				meta["mfa_delete"] = mfaDelete
			}
			a := asset.Asset{
				ID:           name, // S3 bucket names are globally unique
				Name:         name,
				Type:         "s3_bucket",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Domain:       name + ".s3.amazonaws.com",
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			}

			mu.Lock()
			defer mu.Unlock()
			assets = append(assets, a)
			// Only confirmed-public buckets are internet-reachable without credentials;
			// a merely-unblocked bucket must not create an internet attack-path edge.
			if publicAccess == asset.PublicAccessConfirmed {
				edges = append(edges, asset.Edge{
					SrcID: name, SrcType: "s3_bucket",
					DstID: "internet", DstType: "internet",
					EdgeType: "exposed_to_internet",
				})
			}
			if regionErr != nil {
				unresolvedRegions++
				lastRegionErr = regionErr
			}
		}(name)
	}
	wg.Wait()

	if unresolvedRegions > 0 {
		logger.Warn().Int("unresolved", unresolvedRegions).Int("buckets", totalBuckets).
			Str("account_id", accountID).Err(lastRegionErr).
			Dur("elapsed", time.Since(started)).
			Bool("ctx_deadline_exceeded", ctx.Err() != nil).
			Msg("s3: bucket region unresolved; every per-bucket setting (encryption/logging/versioning/mfa_delete/public_access/website) omitted for that bucket (check the collector role's s3:GetBucketLocation) — ctx_deadline_exceeded=true means the account has more buckets than fit in the shared sync budget even at s3BucketConcurrency-wide fan-out")
	}
	if dropped > 0 {
		logger.Warn().Int("dropped", dropped).Int("buckets", totalBuckets).Str("account_id", accountID).
			Bool("ctx_deadline_exceeded", ctx.Err() != nil).
			Msg("s3: some listed buckets were not emitted (deadline or panic); sweep flagged partial")
	}
	return assets, edges, dropped > 0, nil
}

// bucketRegion resolves a bucket's region, normalized to a real region code.
// On error the region is left blank rather than failing the whole collection —
// a blank region then leaves every per-bucket setting unobserved, since
// regionOpt cannot retarget a call it has no region for. The error is
// returned, not swallowed, so the caller can log why (a permission gap and a
// throttle otherwise look identical from the outside).
func bucketRegion(ctx context.Context, client s3API, bucket string) (string, error) {
	loc, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		return "", err
	}
	if loc == nil {
		return "", nil
	}
	return normalizeBucketRegion(string(loc.LocationConstraint)), nil
}

// publicAccessUnknown is the tier written when NONE of the three exposure calls
// answered — see graphstore.PublicAccessUnknown, which is the same string and the
// consumer of this value. Duplicated rather than imported: a collector must not
// import graphstore, and the asset package (where
// asset.PublicAccess{Confirmed,Possible,None} live) does not define it. graphstore's
// TestPublicAccessUnknownLiteral pins the pair.
const publicAccessUnknown = "unknown"

// bucketPublicAccess grades the bucket's public exposure. Confirmed means AWS
// itself says unauthenticated access is possible: the policy status is public,
// or the ACL grants to AllUsers/AuthenticatedUsers. Possible means nothing
// *prevents* exposure — the public-access-block is missing or not fully
// locked — but no public policy/ACL was observed. Every test is made against
// the EFFECTIVE block (bucket and account settings combined, see accountBPA):
// a public policy under RestrictPublicBuckets, or a public ACL under
// IgnorePublicAcls, exposes nothing.
//
// An API error grades as "unknown", never "possible": falling through to
// possible on an unreadable bucket would badge it as exposed on the strength
// of an AccessDenied, not an actual observation. An unreadable bucket is a
// coverage gap to fix, not an exposure to remediate — graphstore.assetPublic
// reports "unknown" as not-public so it can't inflate an exposure count, and
// the DSPM summary surfaces it as its own "exposure unobserved" population.
//
// NoSuchPublicAccessBlockConfiguration is not an error in this sense — it's
// AWS saying "read fine, there is no block" (same distinction
// isNoEncryptionConfigErr makes) — so that path still grades normally.
//
// Every input (the bucket's own block, its policy, its ACL) is read once by
// the caller and shared with the other grades; only the policy status is read
// here, and only when no block neutralizes it.
//
// Beyond the tier it returns the bpa_all_enabled verdict — whether all four
// Block Public Access flags are effectively on, which the benchmarks (CIS
// 3.1.4, FSBP S3.8) require even when the two neutralizing flags already make
// the bucket non-public — and the public read / public write split (FSBP
// S3.2/S3.3). "" means unknown for each.
func bucketPublicAccess(ctx context.Context, client s3API, bucket string, opt func(*s3.Options), acct accountBPA, own bucketBlock, policy bucketPolicyDoc, acl bucketACL) bucketExposure {
	// The effective block is the most restrictive combination of bucket and
	// account settings; a neutralizing one short-circuits everything else.
	eff := effectiveBlock(own.cfg, acct.cfg)
	exp := bucketExposure{}
	switch {
	case fullyBlocked(&eff):
		exp.bpaAll = "true"
	case own.observed && acct.observed:
		exp.bpaAll = "false"
	}
	// Ignoring public ACLs and restricting public policies neutralizes every
	// policy and ACL the bucket has, so the exposure calls are moot.
	if neutralized(eff) {
		exp.tier, exp.publicRead, exp.publicWrite = asset.PublicAccessNone, "false", "false"
		return exp
	}
	restrict, ignore := awssdk.ToBool(eff.RestrictPublicBuckets), awssdk.ToBool(eff.IgnorePublicAcls)
	ps, psErr := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: awssdk.String(bucket)}, opt)
	statusRead := psErr == nil && ps != nil && ps.PolicyStatus != nil
	statusPublic := statusRead && awssdk.ToBool(ps.PolicyStatus.IsPublic)

	switch {
	case statusPublic && !restrict, acl.hasPublicGrantee() && !ignore:
		exp.tier = asset.PublicAccessConfirmed
	case !own.observed && psErr != nil && !acl.aclObserved:
		// Nothing proved exposure and none of the three answers was observed:
		// we know nothing about this bucket.
		exp.tier = publicAccessUnknown
	default:
		exp.tier = asset.PublicAccessPossible
	}

	var policyRead, policyWrite bool
	policyKnown := true
	switch {
	case restrict, statusRead && !statusPublic, policy.observed && policy.doc == "":
	case statusPublic && policy.observed:
		policyRead, policyWrite, policyKnown = policyPublicGrants(policy.doc)
	default:
		policyKnown = false
	}
	aclRead, aclWrite := acl.publicGrants()
	if ignore {
		aclRead, aclWrite = false, false
	}
	known := policyKnown && (ignore || acl.aclObserved)
	exp.publicRead = splitVerdict(policyRead || aclRead, known)
	exp.publicWrite = splitVerdict(policyWrite || aclWrite, known)
	return exp
}

// bucketExposure is bucketPublicAccess's verdict; every field but tier is ""
// when unknown.
type bucketExposure struct {
	tier, bpaAll, publicRead, publicWrite string
}

// splitVerdict is "true" on any observed grant, "false" only when both the
// policy and the ACL were observed granting nothing.
func splitVerdict(granted, known bool) string {
	switch {
	case granted:
		return "true"
	case known:
		return "false"
	}
	return ""
}

// neutralized reports whether a block configuration makes any existing public
// ACL and public policy ineffective (IgnorePublicAcls + RestrictPublicBuckets),
// so nothing about the bucket can expose it.
func neutralized(c s3types.PublicAccessBlockConfiguration) bool {
	return awssdk.ToBool(c.IgnorePublicAcls) && awssdk.ToBool(c.RestrictPublicBuckets)
}

// isNoPublicAccessBlockErr reports whether err is S3's "this bucket has no
// public-access-block" answer rather than a permission or transport failure. That
// error IS an observation: it says the lockdown is absent, which is precisely the
// condition "possible" describes.
func isNoPublicAccessBlockErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration"
}

func fullyBlocked(c *s3types.PublicAccessBlockConfiguration) bool {
	return awssdk.ToBool(c.BlockPublicAcls) && awssdk.ToBool(c.IgnorePublicAcls) &&
		awssdk.ToBool(c.BlockPublicPolicy) && awssdk.ToBool(c.RestrictPublicBuckets)
}

// bucketLoggingStatus returns "enabled" or "disabled" for S3 server access
// logging. The bool is false when the call FAILED — the same distinction
// bucketEncryptionAlgorithm makes, for the same reason: GetBucketLogging
// answers 200 with an empty LoggingEnabled for a bucket with no logging, so
// every error here is AccessDenied, a throttle, or transport, and returning
// "disabled" for those would manufacture a finding out of a collection gap.
func bucketLoggingStatus(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) (string, bool) {
	out, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil || out == nil {
		return "", false
	}
	if out.LoggingEnabled == nil {
		return "disabled", true
	}
	return "enabled", true
}

// bucketVersioningAndMFA fetches versioning state once and returns both the
// versioning status string and the MFA delete status string. Both fields come
// from the same GetBucketVersioning call, so we avoid a second round-trip.
// versioning: "enabled" | "suspended" | "disabled"
// mfaDelete:  "Enabled" | "Disabled"
//
// observed is false when the call FAILED, and the caller then omits BOTH keys.
// As with logging, a never-versioned bucket is not an error case — the API
// answers 200 with an empty Status — so a blanket "disabled" fallback would
// dress up a permission or transport gap as a real finding.
func bucketVersioningAndMFA(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) (versioning, mfaDelete string, observed bool) {
	out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil || out == nil {
		return "", "", false
	}
	switch out.Status {
	case s3types.BucketVersioningStatusEnabled:
		versioning = "enabled"
	case s3types.BucketVersioningStatusSuspended:
		versioning = "suspended"
	default:
		versioning = "disabled"
	}
	if out.MFADelete == s3types.MFADeleteStatusEnabled {
		mfaDelete = "Enabled"
	} else {
		mfaDelete = "Disabled"
	}
	return versioning, mfaDelete, true
}

// bucketEncryptionAlgorithm returns the bucket's default SSE algorithm
// ("AES256" or "aws:kms"), or "" when the bucket was read and has no default
// encryption at all.
//
// The bool result is the whole point: it is false when the call FAILED, so
// the caller omits the key rather than writing "" for both "no encryption"
// and "AccessDenied/throttled" alike. AWS applies SSE-S3 to every new bucket
// by default, so a large "unencrypted" population is more likely a
// permission gap in the collector role than a real finding.
//
// The convention — key present-and-empty means observed-none, key absent means
// unobserved — is the one internal/checks reads via observedNone().
func bucketEncryptionAlgorithm(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) (string, bool) {
	out, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil {
		// ServerSideEncryptionConfigurationNotFoundError is AWS explicitly saying
		// "read fine, nothing configured" — that is an observation, not a gap.
		return "", isNoEncryptionConfigErr(err)
	}
	if out == nil || out.ServerSideEncryptionConfiguration == nil {
		return "", false
	}
	if len(out.ServerSideEncryptionConfiguration.Rules) == 0 {
		return "", true
	}
	rule := out.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil {
		return "", true
	}
	return string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm), true
}

// isNoEncryptionConfigErr reports whether err is S3's "this bucket has no
// default encryption" error rather than a permission or transport failure.
func isNoEncryptionConfigErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
}

// bucketWebsiteEnabled returns "true" if the bucket has a static-website
// configuration, or "" if S3 answered that it has none. observed is false for
// any other error, so a failed read is not reported as "no website".
func bucketWebsiteEnabled(ctx context.Context, client s3API, bucket string, opt func(*s3.Options)) (string, bool) {
	_, err := client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: awssdk.String(bucket)}, opt)
	if err != nil {
		return "", awsErrCode(err) == "NoSuchWebsiteConfiguration"
	}
	return "true", true
}
