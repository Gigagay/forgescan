package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"forgescan/scanner-runner/internal/model"
	"forgescan/scanner-runner/internal/scanners/bandit"
)

// TestBanditParserRejectsGarbage ensures invalid JSON is rejected
func TestBanditParserRejectsGarbage(t *testing.T) {
	_, err := bandit.Parse("{{{{")
	if err == nil {
		t.Fatal("parser accepted invalid json")
	}
}

// TestBanditParserAcceptsValidJSON ensures valid input is parsed
func TestBanditParserAcceptsValidJSON(t *testing.T) {
	validJSON := `{
		"results": [
			{
				"test_id": "B101",
				"test_name": "assert_used",
				"filename": "app.py",
				"line_number": 42,
				"issue_text": "Use of assert detected",
				"issue_severity": "HIGH"
			}
		]
	}`

	findings, err := bandit.Parse(validJSON)
	if err != nil {
		t.Fatalf("parser rejected valid json: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "B101" {
		t.Errorf("expected rule_id B101, got %s", f.RuleID)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.File != "app.py" {
		t.Errorf("expected file app.py, got %s", f.File)
	}
}

// TestBanditParserEmptyResults handles zero findings
func TestBanditParserEmptyResults(t *testing.T) {
	emptyJSON := `{"results": []}`

	findings, err := bandit.Parse(emptyJSON)
	if err != nil {
		t.Fatalf("parser failed on empty results: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// TestBanditSeverityMapping tests all severity conversions
func TestBanditSeverityMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected model.Severity
	}{
		{"HIGH", model.SeverityHigh},
		{"MEDIUM", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		{"UNKNOWN", model.SeverityLow}, // default
	}

	for _, tt := range tests {
		json := `{
			"results": [
				{
					"test_id": "B101",
					"test_name": "test",
					"filename": "test.py",
					"line_number": 1,
					"issue_text": "test",
					"issue_severity": "` + tt.input + `"
				}
			]
		}`

		findings, _ := bandit.Parse(json)
		if findings[0].Severity != tt.expected {
			t.Errorf("severity mapping failed: %s -> expected %s, got %s", tt.input, tt.expected, findings[0].Severity)
		}
	}
}

// TestFingerprintStability ensures same inputs always produce same output
func TestFingerprintStability(t *testing.T) {
	a := fingerprint("bandit", "B101", "a.py", 1, "assert used")
	b := fingerprint("bandit", "B101", "a.py", 1, "assert used")

	if a != b {
		t.Fatal("fingerprint not deterministic")
	}
}

// TestFingerprintDifferenceOnInput verifies different inputs produce different outputs
func TestFingerprintDifferenceOnInput(t *testing.T) {
	a := fingerprint("bandit", "B101", "a.py", 1, "assert used")
	b := fingerprint("bandit", "B102", "a.py", 1, "assert used") // different rule_id
	c := fingerprint("bandit", "B101", "b.py", 1, "assert used") // different file
	d := fingerprint("bandit", "B101", "a.py", 2, "assert used") // different line

	if a == b {
		t.Fatal("fingerprint not sensitive to rule_id change")
	}
	if a == c {
		t.Fatal("fingerprint not sensitive to file change")
	}
	if a == d {
		t.Fatal("fingerprint not sensitive to line change")
	}
}

// TestFingerprintNullHandling ensures null file/line are handled consistently
func TestFingerprintNullHandling(t *testing.T) {
	// Same hash when both are nil
	a := fingerprint("semgrep", "rules/XSS", "", 0, "XSS vulnerability")
	b := fingerprint("semgrep", "rules/XSS", "", 0, "XSS vulnerability")

	if a != b {
		t.Fatal("fingerprint inconsistent with empty file/line")
	}

	// Different from non-empty
	c := fingerprint("semgrep", "rules/XSS", "app.tsx", 123, "XSS vulnerability")
	if a == c {
		t.Fatal("fingerprint not sensitive to empty file/line")
	}
}

// TestFingerprintLength ensures SHA256 output (64 hex chars)
func TestFingerprintLength(t *testing.T) {
	f := fingerprint("bandit", "B101", "test.py", 1, "test")
	if len(f) != 64 {
		t.Fatalf("expected 64-char SHA256, got %d", len(f))
	}
}

// TestFingerprintFormat ensures valid hex
func TestFingerprintFormat(t *testing.T) {
	f := fingerprint("bandit", "B101", "test.py", 1, "test")
	_, err := hex.DecodeString(f)
	if err != nil {
		t.Fatalf("fingerprint not valid hex: %v", err)
	}
}

// TestFindingStruct ensures Finding type compiles with all required fields
func TestFindingStruct(t *testing.T) {
	f := model.Finding{
		Scanner:     "bandit",
		RuleID:      "B101",
		Title:       "assert used",
		Description: "Use of assert is not allowed",
		Severity:    model.SeverityHigh,
		File:        "app.py",
		Line:        42,
		Confidence:  0.85,
		Fingerprint: "abc123",
	}

	if f.Scanner != "bandit" {
		t.Error("Finding.Scanner field broken")
	}
	if f.Fingerprint != "abc123" {
		t.Error("Finding.Fingerprint field broken")
	}
}

// Helper: compute fingerprint for tests
func fingerprint(scanner, ruleID, file string, line int, title string) string {
	data := []byte(scanner + ":" + ruleID + ":" + file + ":" + string(rune(line)) + ":" + title)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
