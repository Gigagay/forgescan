package bandit

import (
	"encoding/json"
	"errors"

	"forgescan/scanner-runner/internal/model"
)

type banditResult struct {
	Results []struct {
		TestID        string `json:"test_id"`
		TestName      string `json:"test_name"`
		Filename      string `json:"filename"`
		LineNumber    int    `json:"line_number"`
		IssueText     string `json:"issue_text"`
		IssueSeverity string `json:"issue_severity"`
	} `json:"results"`
}

func Parse(raw string) ([]model.Finding, error) {
	var parsed banditResult
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, errors.New("invalid bandit json")
	}

	findings := []model.Finding{}
	for _, r := range parsed.Results {
		findings = append(findings, model.Finding{
			Scanner:     "bandit",
			RuleID:      r.TestID,
			Title:       r.TestName,
			Description: r.IssueText,
			Severity:    mapSeverity(r.IssueSeverity),
			File:        r.Filename,
			Line:        r.LineNumber,
			Confidence:  0.85,
		})
	}
	return findings, nil
}

func mapSeverity(s string) model.Severity {
	switch s {
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
