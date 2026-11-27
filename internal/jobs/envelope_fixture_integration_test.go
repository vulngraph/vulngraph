//go:build integration

package jobs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// This substitutes collection at the Result boundary. It measures the real
// whole-result allocation and downstream pipeline, not cloud SDK/API overhead.
// Nothing pre-materializes all connectors in the benchmark driver.
type envelopeCollector struct {
	revision atomic.Int64
	mode     atomic.Int64 // 0 complete, 1 partial omission, 2 confirmed deletion
	trace    *envelopeTrace
	hold     time.Duration // modeled wait while a whole Result remains allocated
	scopes   []envelopeScope
}

func envelopeSizes(connectors, resources int) []int {
	sizes := make([]int, connectors)
	large := max(1, connectors/10)
	for i := range sizes {
		if i < large {
			sizes[i] = resources * 9 / 10 / large
		} else {
			sizes[i] = (resources - resources*9/10) / (connectors - large)
		}
	}
	assigned := 0
	for _, n := range sizes {
		assigned += n
	}
	for i := 0; assigned < resources; i, assigned = i+1, assigned+1 {
		sizes[i%connectors]++
	}
	return sizes
}

func envelopeID(connector, resource int) string {
	return fmt.Sprintf("envelope-%04d-%08d", connector, resource)
}

func envelopeAsset(connector, index, revision int, now time.Time, scope envelopeScope) asset.Asset {
	id := envelopeID(connector, index)
	payloadSize := 256
	if index%100 == 0 {
		payloadSize = 16384
	}
	a := asset.Asset{ID: id, Name: id, Type: "ec2_instance", Provider: asset.ProviderAWS,
		Region: "eu-west-1", AccountID: fmt.Sprintf("%012d", connector), LastSeen: now, DiscoveredAt: now,
		Tags: map[string]string{"env": "prod", "team": "envelope"},
		Metadata: map[string]string{"state": "running", "http_tokens": "required", "ssm_managed": "true",
			"public_access": asset.PublicAccessNone}}
	scope.observation(&a, index)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(a.ID)))
	a.Metadata["payload"] = strings.Repeat(hash, payloadSize/len(hash))
	if index%100 == 1 {
		a.Name += fmt.Sprintf("-revision-%d", revision)
	}
	return a
}

func (c *envelopeCollector) Collect(ctx context.Context, cfg map[string]string) (_ collect.Result, resultErr error) {
	index, err := strconv.Atoi(cfg["index"])
	if err != nil {
		return collect.Result{}, err
	}
	n, err := strconv.Atoi(cfg["resources"])
	if err != nil {
		return collect.Result{}, err
	}
	finish := c.trace.begin("collect", strconv.Itoa(index))
	defer func() { finish(resultErr) }()
	now := time.Now().UTC()
	scope := c.scopes[index]
	mode, revision := c.mode.Load(), int(c.revision.Load())
	out := collect.Result{Assets: make([]asset.Asset, 0, n), Edges: make([]asset.Edge, 0, n-1), Partial: mode == 1}
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return collect.Result{}, err
		}
		// Omit one known resource per connector for the lifecycle waves. A
		// partial observation must retain it; a complete one proves deletion.
		if mode != 0 && i == 1 {
			continue
		}
		a := envelopeAsset(index, i, revision, now, scope)
		out.Assets = append(out.Assets, a)
		if i > 0 {
			target, targetType, edgeType := scope.target()
			out.Edges = append(out.Edges, asset.Edge{SrcID: a.ID, DstID: target, SrcType: a.Type,
				DstType: targetType, EdgeType: edgeType})
		}
		if i%100 == 1 {
			severity := finding.SeverityHigh
			if revision > 0 {
				severity = finding.SeverityCritical
			}
			out.Findings = append(out.Findings, finding.Finding{ID: "finding-" + a.ID, Source: "envelope_provider", Type: "misconfiguration",
				Severity: severity, Title: "Synthetic observed configuration", ResourceID: a.ID, ResourceType: a.Type,
				Region: a.Region, CheckID: "envelope-configuration", DetectedAt: now})
		}
	}
	_, workloadType := scope.types()
	count := len(out.Assets) - 1
	if scope.Kind == "github" {
		count++
	}
	out.CompletedEnumerations = []collect.ScopeEnumeration{{Scope: scope.enumeration(), Types: []string{workloadType}, Count: count}}
	if c.hold > 0 {
		endHold := c.trace.begin("retained_result", strconv.Itoa(index))
		timer := time.NewTimer(c.hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			endHold(ctx.Err())
			return collect.Result{}, ctx.Err()
		case <-timer.C:
			endHold(nil)
		}
	}
	return out, nil
}
