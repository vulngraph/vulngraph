package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/db"
)

const demoDomain = "acme.example"

// demoCmd handles `graph demo seed`: it adds what the demo connector cannot
// carry, a monitored domain and the lookalike candidates that domain monitoring
// would have found. The AI verdicts are fixed sample text, not model output.
func demoCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) != 1 || args[0] != "seed" {
		return fmt.Errorf("usage: graph demo seed")
	}
	pool, err := db.NewPool(ctx, pgDSN(getenv), 2)
	if err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	defer pool.Close()
	ch, err := db.NewCH(ctx, chDSN(getenv), 1)
	if err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	defer func() { _ = ch.Close() }()

	if _, err := intel.NewPGRepo(pool).AddDomain(ctx, demoDomain); err != nil && !errors.Is(err, intel.ErrDomainExists) {
		return fmt.Errorf("demo: %w", err)
	}
	candidates := demoCandidates(time.Now().UTC())
	if err := intel.NewCHRepo(ch).BulkUpsertCandidates(ctx, candidates); err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	_, err = fmt.Fprintf(out, "monitoring %s with %d sample lookalike domains; add the Demo connector under Settings → Connectors for the Acme account\n",
		demoDomain, len(candidates))
	return err
}

// demoCandidates are three lookalikes of acme.example at the three outcomes the
// Domain Monitor page shows: two the triage keeps for a person and one it clears.
func demoCandidates(now time.Time) []intel.PhishingCandidate {
	c := func(domain string, score float32, issuer string, age time.Duration, status intel.CandidateStatus, phish bool, conf float32, why string) intel.PhishingCandidate {
		seen := now.Add(-age)
		return intel.PhishingCandidate{
			ID: intel.CandidateID(domain, demoDomain), Domain: domain, MonitoredDomain: demoDomain, Source: "crt_sh",
			SimilarityScore: score, Issuer: issuer, NotBefore: seen, NotAfter: seen.Add(90 * 24 * time.Hour),
			Status: status, AIIsPhishing: phish, AIConfidence: conf, AIReasoning: why,
			TriageSource: intel.TriageLLM, DetectedAt: seen,
		}
	}
	return []intel.PhishingCandidate{
		c("acrne.example", 0.95, "Let's Encrypt R11", 3*time.Hour, intel.StatusPending, true, 0.97,
			"'rn' reads as 'm' at a glance, so acrne.example renders as acme.example in most fonts. The certificate is hours old, "+
				"from a free CA, and the name has no DNS or registrar link to acme.example. This is the homoglyph pattern used for credential harvesting."),
		c("acme-login.example", 0.92, "Let's Encrypt R11", 2*24*time.Hour, intel.StatusPending, true, 0.94,
			"The brand label plus 'login' on a different registrable domain, with a certificate issued two days ago. "+
				"Brand-plus-login names are the most common phishing lure; nothing ties the domain to Acme."),
		c("acme-supplies.example", 0.70, "DigiCert EV TLS CA", 400*24*time.Hour, intel.StatusAutoDismissed, false, 0.08,
			"Shares only the word 'acme' with the monitored domain. The certificate is a long-lived EV certificate for an unrelated "+
				"office-supplies retailer, with a history that predates Acme's brand. Treated as a coincidence."),
	}
}
