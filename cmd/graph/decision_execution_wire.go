package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// decisionTargets reads what a decision proposes to change for the executor's
// approve-and-run: the decision row from respond's trail, the resource from
// its finding. The executor never names respond or finding types (layering).
type decisionTargets struct {
	decisions *respond.CHRepo
	findings  *finding.Service
}

func (a decisionTargets) DecisionTarget(ctx context.Context, decisionID string) (executor.DecisionTarget, error) {
	e, err := a.decisions.GetDecision(ctx, decisionID)
	if errors.Is(err, respond.ErrNotFound) {
		return executor.DecisionTarget{}, fmt.Errorf("decisionTargets: %w", executor.ErrDecisionNotFound)
	}
	if err != nil {
		return executor.DecisionTarget{}, fmt.Errorf("decisionTargets: %w", err)
	}
	d, err := respond.ParseDecisionDetails(e.Details)
	if err != nil {
		return executor.DecisionTarget{}, fmt.Errorf("decisionTargets: %w", err)
	}
	t := executor.DecisionTarget{
		DecisionID: decisionID, FindingID: e.TargetID, ActionClass: d.ActionClass,
		AwaitingHuman: d.Outcome.AwaitingHuman(),
	}
	found, err := a.findings.ByIDs(ctx, []string{e.TargetID})
	if err != nil {
		return executor.DecisionTarget{}, fmt.Errorf("decisionTargets: %w", err)
	}
	// A finding that no longer loads leaves the resource empty; the plan then
	// reads as guidance only rather than guessing a target.
	if len(found) > 0 {
		t.ResourceType, t.ResourceID, t.Region = found[0].ResourceType, found[0].ResourceID, found[0].Region
	}
	return t, nil
}

// decisionOutcomes hands a fix the executor actually ran to govern, which
// resolves the decision and records the real outcome.
type decisionOutcomes struct{ govern *govern.Service }

func (a decisionOutcomes) RecordExecuted(ctx context.Context, t executor.DecisionTarget, actor string) error {
	if err := a.govern.RecordExecution(ctx, govern.ExecutedFix{
		DecisionID: t.DecisionID, FindingID: t.FindingID, ActionClass: t.ActionClass, Actor: actor,
	}); err != nil {
		return fmt.Errorf("decisionOutcomes: %w", err)
	}
	return nil
}
