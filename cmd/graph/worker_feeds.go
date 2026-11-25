package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/intel/epss"
	"github.com/vulngraph/vulngraph/internal/intel/kev"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/internal/intel/updateinfo"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/egress"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// The worker's default-on outbound feeds. Each constructor returns nil when its
// feed is switched off (jobs.FeedsFromEnv); the jobs package reads a nil dep as
// "feed off" and drops the periodic. The return types are the jobs interfaces,
// not the concrete clients, so a disabled feed is a true nil interface and not
// a typed nil that would read as wired.

// intelFeeds reads the feed switches and logs, once at startup, which feeds
// this pod will not fetch. An unrecognised switch value is an error.
func intelFeeds(ctx context.Context, getenv func(string) string) (jobs.Feeds, error) {
	feeds, err := jobs.FeedsFromEnv(getenv)
	if err != nil {
		return jobs.Feeds{}, fmt.Errorf("intelFeeds: %w", err)
	}
	offline, err := egress.Offline(getenv)
	if err != nil {
		return jobs.Feeds{}, fmt.Errorf("intelFeeds: %w", err)
	}
	if off := feeds.Disabled(); len(off) > 0 {
		log.FromContext(ctx).Warn().
			Bool("offline_mode", offline).
			Strs("disabled", off).
			Msg("worker: outbound intel feeds disabled — scoring runs without them (no KEV flag / EPSS points / OSV supply-chain or image CVEs / Amazon or Oracle Linux CVEs / CT phishing candidates, as applicable)")
	}
	return feeds, nil
}

func kevFetcher(f jobs.Feeds) jobs.KEVFetcher {
	if !f.KEV {
		return nil
	}
	return kev.NewFetcher()
}

func osvQuerier(f jobs.Feeds) jobs.OSVQuerier {
	if !f.OSV {
		return nil
	}
	return osv.NewClient()
}

func malFeedQuerier(f jobs.Feeds, token string) jobs.MalFeedQuerier {
	if !f.MalFeed {
		return nil
	}
	return osv.NewMalFeedClient(token)
}

// distroAdvisoryFetcher reads the Amazon Linux (ALAS) and Oracle Linux (ELSA)
// updateinfo feeds; nil when both INTEL_ALAS_DISABLED and INTEL_ELSA_DISABLED
// (or OFFLINE_MODE) are set.
func distroAdvisoryFetcher(f jobs.Feeds) jobs.DistroAdvisoryFetcher {
	if len(f.DistroAdvisorySources()) == 0 {
		return nil
	}
	return updateinfo.NewClient()
}

func epssFetcher(f jobs.Feeds) jobs.EPSSFetcher {
	if !f.EPSS {
		return nil
	}
	return epss.NewFetcher()
}

// domainMonitor is the intel service behind the domain-monitor job, which sends
// every monitored domain name to crt.sh. Nil unregisters the job; the serve pod
// still lists domains and candidates, nothing new is fetched.
func domainMonitor(f jobs.Feeds, pool *pgxpool.Pool, ch *db.CH, llmClient llm.Client) *intel.Service {
	if !f.DomainMonitor {
		return nil
	}
	return intel.NewService(intel.NewPGRepo(pool), intel.NewCHRepo(ch), llmClient)
}

// takeoverProbeEnv switches off the subdomain-takeover HTTP probe, which GETs
// hostnames taken from collected DNS records (usually third-party services a
// CNAME points at) to fingerprint unclaimed endpoints. An on/off switch
// (egress.Disabled).
const takeoverProbeEnv = "TAKEOVER_PROBE_DISABLED"

// takeoverProbeHTTP is the TakeoverProbe enrich source's HTTP client, or nil to
// switch the source off. Off, a takeover candidate keeps its DNS-only score: the
// probe can neither confirm nor refute it. An unrecognised switch value is an
// error.
func takeoverProbeHTTP(ctx context.Context, getenv func(string) string) (enrich.HTTPGetter, error) {
	off, err := egress.Disabled(getenv, takeoverProbeEnv)
	if err != nil {
		return nil, fmt.Errorf("takeoverProbeHTTP: %w", err)
	}
	if off {
		log.FromContext(ctx).Warn().Msg("worker: subdomain-takeover HTTP probe disabled — takeover candidates are scored on DNS evidence only")
		return nil, nil
	}
	return enrich.NewSafenetGetter(4*time.Second, 64*1024), nil
}
