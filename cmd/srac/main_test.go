package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunReportsAllCorrelationStates(t *testing.T) {
	dir := t.TempDir()
	trivyPath := writeTestFile(t, dir, "trivy.json", `{
  "SchemaVersion": 2,
  "FutureField": "ignored",
  "Results": [{
    "Target": "app",
    "Packages": [
      {"Name":"liba","Version":"1.0.0","PkgIdentifier":{"PURL":"pkg:generic/liba@1.0.0"}},
      {"Name":"dup-a","Version":"2.0.0","PkgIdentifier":{"PURL":"pkg:generic/dup@2.0.0"}},
      {"Name":"dup-b","Version":"2.0.0","PkgIdentifier":{"PURL":"pkg:generic/dup@2.0.0"}}
    ],
    "Vulnerabilities": [{"VulnerabilityID":"CVE-2026-0001","PkgName":"liba","InstalledVersion":"1.0.0","Severity":"HIGH"}]
  }]
}`)
	sracPath := writeTestFile(t, dir, "srac.json", `{
  "schemaVersion":"1.0","documentId":"SRAC-DEMO","unknown":"ignored",
  "assertions":[
    {"id":"A-1","component":{"purl":"pkg:generic/liba@1.0.0"},"safetyRelevance":"safety-relevant"},
    {"id":"A-2","component":{"purl":"pkg:generic/missing@1.0.0"},"safetyRelevance":"not-safety-relevant"},
    {"id":"A-3","component":{"purl":"pkg:generic/dup@2.0.0"},"safetyRelevance":"safety-relevant"},
    {"id":"A-4","component":{},"safetyRelevance":"safety-relevant"},
    {"id":"A-5","component":{"purl":"pkg:generic/liba@1.0.0"},"safetyRelevance":"safety-relevant","validUntil":"2025-01-01T00:00:00Z"}
  ]
}`)
	outPath := filepath.Join(dir, "out.json")
	if err := run(options{trivyPath: trivyPath, sracPath: sracPath, outputPath: outPath}, time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var got outputReport
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]int{"matched": 1, "unmatched": 1, "ambiguous": 1, "invalid": 1, "stale": 1} {
		if got.Summary[state] != want {
			t.Fatalf("%s=%d, want %d", state, got.Summary[state], want)
		}
	}
	if got.Correlations[0].Matches[0].Findings[0].ID != "CVE-2026-0001" {
		t.Fatalf("finding was not correlated: %#v", got.Correlations[0])
	}
}

func TestRunResolvesCycloneDXBOMRef(t *testing.T) {
	dir := t.TempDir()
	trivy := writeTestFile(t, dir, "trivy.json", `{"SchemaVersion":2,"Results":[{"Packages":[{"Name":"liba","Version":"1","PkgIdentifier":{"PURL":"pkg:generic/liba@1"}}]}]}`)
	srac := writeTestFile(t, dir, "srac.json", `{"documentId":"D","assertions":[{"id":"A","component":{"bomRef":"component-a"},"safetyRelevance":"safety-relevant"}]}`)
	sbom := writeTestFile(t, dir, "bom.json", `{"components":[{"bom-ref":"component-a","purl":"pkg:generic/liba@1"}]}`)
	out := filepath.Join(dir, "out.json")
	if err := run(options{trivyPath: trivy, sracPath: srac, sbomPath: sbom, outputPath: out}, time.Now()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), `"state": "matched"`) {
		t.Fatalf("unexpected output: %s", b)
	}
}

func TestRunFailsClosedOnDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	trivy := writeTestFile(t, dir, "trivy.json", `{"SchemaVersion":2}`)
	srac := writeTestFile(t, dir, "srac.json", `{"documentId":"D"}`)
	err := run(options{trivyPath: trivy, sracPath: srac, outputPath: filepath.Join(dir, "out.json"), expectedDigest: strings.Repeat("0", 64)}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestGeneratedReportUsesStableContract(t *testing.T) {
	dir := t.TempDir()
	trivy := writeTestFile(t, dir, "trivy.json", `{"SchemaVersion":2,"Results":[{"Packages":[{"Name":"liba","Version":"1","PkgIdentifier":{"PURL":"pkg:generic/liba@1"}}]}]}`)
	srac := writeTestFile(t, dir, "srac.json", `{"documentId":"D","assertions":[{"id":"A","component":{"purl":"pkg:generic/liba@1"},"safetyRelevance":"safety-relevant"}]}`)
	out := filepath.Join(dir, "out.json")
	if err := run(options{trivyPath: trivy, sracPath: srac, outputPath: out}, time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var got outputReport
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != reportSchema || got.ReportVersion != reportVersion {
		t.Fatalf("unexpected contract identity: %s %s", got.Schema, got.ReportVersion)
	}
	if got.Producer.Name != producerName || got.Producer.Version != version {
		t.Fatalf("unexpected producer: %#v", got.Producer)
	}
	if !got.AuthorityBoundary.ReadOnly || got.AuthorityBoundary.Mode != "external" {
		t.Fatalf("unexpected authority boundary: %#v", got.AuthorityBoundary)
	}
	for _, input := range got.Inputs {
		if strings.ContainsAny(input.Name, `/\\`) {
			t.Fatalf("input name is not portable: %q", input.Name)
		}
	}
	if got.Correlations[0].CorrelationRule.Type != correlationPURL {
		t.Fatalf("missing correlation rule: %#v", got.Correlations[0])
	}
	if err := validateReportFile(out); err != nil {
		t.Fatalf("generated report did not validate: %v", err)
	}
}

func TestConformanceFixtures(t *testing.T) {
	valid := []string{
		"valid-matched.json",
		"valid-unmatched.json",
		"valid-ambiguous.json",
		"valid-stale.json",
		"forward-compatible-unknown-field.json",
	}
	invalid := []string{
		"invalid-summary-count.json",
		"invalid-digest.json",
		"invalid-duplicate-assertion.json",
		"invalid-name-only-rule.json",
	}
	base := filepath.Join("..", "..", "testdata", "conformance")
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			if err := validateReportFile(filepath.Join(base, name)); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := validateReportFile(filepath.Join(base, name)); err == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func TestSchemaIsValidJSONAndIdentifiesContract(t *testing.T) {
	path := filepath.Join("..", "..", "schemas", "srac-correlation-report-1.0.schema.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema["$id"] != reportSchema {
		t.Fatalf("schema id is %v, want %s", schema["$id"], reportSchema)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
