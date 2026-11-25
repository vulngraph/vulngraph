package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Help             *sarifMessage  `json:"help,omitempty"`
	Properties       sarifRuleProps `json:"properties"`
}

// sarifRuleProps carries GitHub's security-severity score (0-10), which is
// what turns critical and high into distinct levels in code scanning.
type sarifRuleProps struct {
	SecuritySeverity string `json:"security-severity"`
}

func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

type sarifMessage struct {
	Text string `json:"text"`
}

// sarifInvocation records whether collection finished: a partial scan must
// not upload as a clean one.
type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

// sarifRegion is required by GitHub code scanning; a cloud resource has no
// lines, so every result points at line 1 of its resource URI.
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

// sarifLevel maps a severity to SARIF's three result levels.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// renderSARIF writes the scan as SARIF 2.1.0. A cloud resource has no file
// path, so the resource ID is the artifact URI (and also the logical location).
func renderSARIF(w io.Writer, r scanResult) error {
	driver := sarifDriver{Name: "vulngraph", Rules: []sarifRule{}}
	seen := map[string]bool{}
	results := []sarifResult{}
	for _, f := range r.Findings {
		if !seen[f.CheckID] {
			seen[f.CheckID] = true
			rule := sarifRule{ID: f.CheckID, ShortDescription: sarifMessage{Text: f.Title}, Properties: sarifRuleProps{SecuritySeverity: securitySeverity(f.Severity)}}
			if f.Remediation != "" {
				rule.Help = &sarifMessage{Text: f.Remediation}
			}
			driver.Rules = append(driver.Rules, rule)
		}
		sum := sha256.Sum256([]byte(f.CheckID + "\x00" + f.ResourceID))
		results = append(results, sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Title + " (" + f.ResourceID + ")"},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: f.ResourceID}, Region: sarifRegion{StartLine: 1}},
				LogicalLocations: []sarifLogicalLocation{{Name: f.ResourceName, FullyQualifiedName: f.ResourceID, Kind: f.ResourceType}},
			}},
			PartialFingerprints: map[string]string{"checkResource/v1": hex.EncodeToString(sum[:16])},
		})
	}
	inv := sarifInvocation{ExecutionSuccessful: !r.Partial}
	if r.Partial {
		inv.Notifications = []sarifNotification{{Level: "warning", Message: sarifMessage{Text: partialWarning}}}
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Invocations: []sarifInvocation{inv}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	return nil
}
