package github

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const tfStateConcurrency = 8 // parallel repos scanned (matches collectIaC/collectWorkflows)

// maxTFBackendsPerRepo bounds how many state objects one repo may pull. A
// Terraform monorepo can legitimately declare dozens of root modules, each
// one S3 GetObject — so this is a fan-out guard, not a coverage policy.
// Truncation is logged with the skipped count: a silent cap reads as full
// coverage.
const maxTFBackendsPerRepo = 64

// tfStateReader fetches an object's bytes from a connector-scoped S3 bucket,
// bounded by the caller's size cap. mcp.LiveAWSCallerImpl.GetObject satisfies
// this structurally — it is passed in from cmd/graph/worker.go so this
// package never imports the AWS SDK. Cross-cloud calls go through a narrow
// interface like this one.
type tfStateReader interface {
	GetObject(ctx context.Context, connectorID, bucket, key string) ([]byte, error)
}

// connByAccount resolves an AWS account id to the id of an enabled connector
// that can read it. connector.Service.ConnectorByAccountID satisfies this as
// a method value.
type connByAccount func(ctx context.Context, accountID string) (connectorID string, ok bool, err error)

// bucketAccountResolver resolves a Terraform state bucket to the AWS account
// id that owns it, so each backend bucket is read from ITS OWN account rather
// than a single operator-configured one (multi-account). cmd/graph/worker.go
// wires this as a closure over asset.Service.ByIDs: the s3_bucket asset's ID is
// the bucket name and its AccountID field is populated by the AWS S3 collector.
type bucketAccountResolver func(ctx context.Context, bucket string) (accountID string, ok bool, err error)

// resolveBucketAccount looks up the account that owns bucket via resolver (when
// wired) and falls back to the operator-configured stateAccountID otherwise —
// the single-account behavior, for callers that do not wire the
// per-bucket seam and for buckets the resolver doesn't recognize (e.g. a
// bucket with no matching s3_bucket asset yet).
func resolveBucketAccount(ctx context.Context, resolver bucketAccountResolver, bucket, stateAccountID string) (string, bool) {
	if resolver != nil {
		if accountID, ok, err := resolver(ctx, bucket); err == nil && ok && accountID != "" {
			return accountID, true
		}
	}
	if stateAccountID != "" {
		return stateAccountID, true
	}
	return "", false
}

// collectTFState scans each non-archived repo's Terraform for a static `backend
// "s3"` block, reads the referenced state object, and projects the state
// resources the repo's own .tf actually declares into declared_tf_resource
// assets.
//
// Bucket→account resolution is PER BUCKET (multi-account): bucketAcct, when
// wired, resolves each backend bucket to the AWS account that owns it, so two
// repos whose state lives in different accounts each read from the right one.
// stateAccountID is the single operator-configured fallback used when
// bucketAcct is nil or doesn't recognize a bucket. A bucket resolved to
// neither is skipped (counted, not failed) — this is supplementary ownership
// signal, never load-bearing for the rest of GitHub collection.
//
// Best-effort per repo: no backend block, an unresolvable account, a
// GetObject failure (AccessDenied, missing object, oversize), or a panic just
// skips that repo — never sets Partial.
func (c *Collector) collectTFState(ctx context.Context, baseURL, token string, repos []repo, obj tfStateReader, bucketAcct bucketAccountResolver, conn connByAccount, stateAccountID string) ([]asset.Asset, []finding.Finding) {
	logger := log.FromContext(ctx)
	if obj == nil || conn == nil {
		return nil, nil
	}
	if bucketAcct == nil && stateAccountID == "" {
		return nil, nil
	}

	sem := make(chan struct{}, tfStateConcurrency)
	var mu sync.Mutex
	var all []asset.Asset
	var findings []finding.Finding
	var noBackend, noAccount, readFailed, parseFailed int
	var wg sync.WaitGroup

	for _, r := range repos {
		if r.Archived || r.DefaultBranch == "" {
			continue
		}
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Interface("panic", rec).Str("repo", r.FullName).Msg("tfstate ingest panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			files := c.tfStateFiles(ctx, baseURL, token, r)
			if len(files) == 0 {
				return
			}

			declared := map[string]struct{}{}
			var backends []iac.S3Backend
			seenBackend := map[string]bool{}
			for _, content := range files {
				b := []byte(content)
				for _, addr := range iac.ParseTFResourceAddresses(b) {
					declared[addr] = struct{}{}
				}
				for _, be := range iac.ParseTFBackend(b) {
					k := be.Bucket + "/" + be.Key
					if seenBackend[k] {
						continue
					}
					seenBackend[k] = true
					backends = append(backends, be)
				}
			}
			if len(backends) == 0 {
				mu.Lock()
				noBackend++
				mu.Unlock()
				return
			}
			if len(declared) == 0 {
				return
			}
			// EVERY root module has its own backend and its own state file, so a
			// monorepo has many: an IAM-config repo may carry one state.tf per team
			// directory, and an infra repo one backend.tf per environment. Reading
			// only the first one found would leave nearly all of them invisible,
			// and WHICH one survived would depend on GitHub's file ordering.
			// Sorted so the bound below truncates deterministically.
			sort.Slice(backends, func(i, j int) bool {
				if backends[i].Bucket != backends[j].Bucket {
					return backends[i].Bucket < backends[j].Bucket
				}
				return backends[i].Key < backends[j].Key
			})
			if len(backends) > maxTFBackendsPerRepo {
				logger.Warn().Str("repo", r.FullName).Int("backends", len(backends)).
					Int("cap", maxTFBackendsPerRepo).Int("skipped", len(backends)-maxTFBackendsPerRepo).
					Msg("tfstate: repo declares more backends than the per-repo cap; remainder not read")
				backends = backends[:maxTFBackendsPerRepo]
			}

			var kept []iac.StateResource
			for _, backend := range backends {
				accountID, ok := resolveBucketAccount(ctx, bucketAcct, backend.Bucket, stateAccountID)
				if !ok {
					mu.Lock()
					noAccount++
					mu.Unlock()
					logger.Debug().Str("repo", r.FullName).Str("bucket", backend.Bucket).Msg("tfstate: no account resolved for bucket; skipping backend")
					continue
				}
				connectorID, ok, err := conn(ctx, accountID)
				if err != nil {
					logger.Warn().Err(err).Str("account_id", accountID).Str("repo", r.FullName).Msg("tfstate: resolving connector for bucket account failed; skipping backend")
					continue
				}
				if !ok {
					logger.Warn().Str("account_id", accountID).Str("repo", r.FullName).Msg("tfstate: no enabled connector monitors the bucket's account; skipping backend")
					continue
				}

				state, err := obj.GetObject(ctx, connectorID, backend.Bucket, backend.Key)
				if err != nil {
					mu.Lock()
					readFailed++
					mu.Unlock()
					logger.Debug().Err(err).Str("repo", r.FullName).Str("bucket", backend.Bucket).Str("key", backend.Key).Msg("tfstate: state read failed; skipping backend")
					if f, ok := unreadableTFStateFinding(err, r.FullName, r.Name, accountID, backend.Bucket, backend.Key); ok {
						mu.Lock()
						findings = append(findings, f)
						mu.Unlock()
					}
					continue
				}

				// The attribution filter is repo-wide on purpose: a resource address is
				// kept if ANY .tf in the repo declares it, so a module's state joins
				// even though the address was read from a sibling directory's file.
				resources, err := iac.ParseTFState(state)
				if err != nil {
					mu.Lock()
					parseFailed++
					mu.Unlock()
					logger.Warn().Err(err).Str("repo", r.FullName).Str("bucket", backend.Bucket).Str("key", backend.Key).
						Msg("tfstate: state object is not valid Terraform state JSON; skipping backend")
					continue
				}
				for _, res := range resources {
					if _, ok := declared[res.Address]; ok {
						kept = append(kept, res)
					}
				}
			}
			if len(kept) == 0 {
				return
			}
			assets := iac.ProjectDeclaredTF(kept, r.FullName, time.Now())
			mu.Lock()
			all = append(all, assets...)
			mu.Unlock()
			logger.Info().Int("assets", len(assets)).Int("backends", len(backends)).Str("repo", r.FullName).Msg("tfstate ingest: projected declared_tf_resource")
		}()
	}
	wg.Wait()
	if noBackend > 0 || noAccount > 0 || readFailed > 0 || parseFailed > 0 {
		logger.Info().Int("no_backend", noBackend).Int("no_account", noAccount).Int("read_failed", readFailed).
			Int("parse_failed", parseFailed).Msg("tfstate ingest: coverage summary")
	}
	return all, findings
}

// unreadableTFStateFinding classifies a GetObject failure and, when it is
// specifically an AccessDenied (the opt-in state-read grant is absent), builds
// the info-severity unreadable_tf_state finding. The grant exposes state
// secrets to Vulngraph's role, so the finding presents it as a choice. Any other failure (region
// mismatch redirect, object missing, oversize, transient network) is not a
// grant gap — those are supplementary skip/count signal only, never a
// finding, so this returns ok=false for them.
//
// The ID is deterministic over repo+bucket+key so re-reading the same state
// object upserts the same finding row (ClickHouse ReplacingMergeTree) rather
// than duplicating, and the deletion-reconciliation lifecycle auto-resolves it the moment a
// later sync succeeds in reading the object — no new lifecycle code needed.
func unreadableTFStateFinding(err error, repoFullName, repoName, accountID, bucket, key string) (finding.Finding, bool) {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied" {
		return finding.Finding{}, false
	}
	remediation := fmt.Sprintf(
		"Optional. Terraform state files often hold plaintext secrets (database passwords, private keys, tokens), "+
			"and this grant lets the role Vulngraph assumes read the whole object. Leave it ungranted if you do not "+
			"want Terraform ownership for this repo. To enable it, grant the read role s3:GetObject on "+
			"arn:aws:s3:::%s/%s (GrantTerraformStateRead=true in the org templates grants it on buckets whose "+
			"name contains terraform-state or tfstate, owned by the role's own account; for a bucket in another "+
			"account, connect that account or point the connector's tfstate_aws_account_id at it).",
		bucket, key,
	)
	return finding.Finding{
		ID:       dbutil.DeterministicID("unreadable_tf_state", repoFullName, bucket, key),
		Source:   "iac_terraform",
		Type:     "unreadable_tf_state",
		Severity: finding.SeverityInfo,
		Title:    "Terraform state not readable — ownership mapping unavailable",
		Description: fmt.Sprintf(
			"Vulngraph cannot read this repo's Terraform state (bucket %s, account %s, key %s), so it cannot map "+
				"this repo's declared resources to live ones. %s",
			bucket, accountID, key, remediation,
		),
		ResourceType: "github_repo",
		ResourceID:   repoFullName,
		ResourceName: repoName,
		Region:       "global",
		CheckID:      "unreadable_tf_state",
		Remediation:  remediation,
		DetectedAt:   time.Now(),
	}, true
}
