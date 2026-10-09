package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	version           = "0.2.0"
	reportSchema      = "urn:srac:schema:correlation-report:1"
	reportVersion     = "1.0.0"
	producerName      = "trivy-plugin-srac"
	inputRoleTrivy    = "trivy-report"
	inputRoleSRAC     = "srac-document"
	inputRoleSBOM     = "sbom"
	correlationPURL   = "exact-purl"
	correlationBOMRef = "bom-ref-to-purl"
)

type options struct {
	trivyPath      string
	sracPath       string
	sbomPath       string
	outputPath     string
	expectedDigest string
}

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Packages        []trivyPackage       `json:"Packages"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyPackage struct {
	Name       string        `json:"Name"`
	Version    string        `json:"Version"`
	Identifier pkgIdentifier `json:"PkgIdentifier"`
}

type trivyVulnerability struct {
	VulnerabilityID  string        `json:"VulnerabilityID"`
	PkgName          string        `json:"PkgName"`
	InstalledVersion string        `json:"InstalledVersion"`
	Severity         string        `json:"Severity"`
	Identifier       pkgIdentifier `json:"PkgIdentifier"`
}

type pkgIdentifier struct {
	PURL string `json:"PURL"`
}

type sracDocument struct {
	DocumentID string          `json:"documentId"`
	Assertions []sracAssertion `json:"assertions"`
}

type sracAssertion struct {
	ID              string       `json:"id"`
	Component       componentRef `json:"component"`
	SafetyRelevance string       `json:"safetyRelevance"`
	Rationale       string       `json:"rationale,omitempty"`
	SourceURI       string       `json:"sourceUri,omitempty"`
	Evidence        []string     `json:"evidence,omitempty"`
	ReviewStatus    string       `json:"reviewStatus,omitempty"`
	ValidUntil      string       `json:"validUntil,omitempty"`
}

type componentRef struct {
	PURL   string `json:"purl,omitempty"`
	BOMRef string `json:"bomRef,omitempty"`
}

type cycloneDX struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components,omitempty"`
}

type packageIdentity struct {
	PURL     string    `json:"purl"`
	Name     string    `json:"name,omitempty"`
	Version  string    `json:"version,omitempty"`
	Targets  []string  `json:"targets,omitempty"`
	Findings []finding `json:"findings,omitempty"`
}

type finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
}

type correlation struct {
	AssertionID      string            `json:"assertionId"`
	State            string            `json:"state"`
	SafetyRelevance  string            `json:"safetyRelevance,omitempty"`
	ResolvedIdentity *resolvedIdentity `json:"resolvedIdentity,omitempty"`
	CorrelationRule  *correlationRule  `json:"correlationRule,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	Rationale        string            `json:"rationale,omitempty"`
	SourceURI        string            `json:"sourceUri,omitempty"`
	Evidence         []string          `json:"evidence,omitempty"`
	ReviewStatus     string            `json:"reviewStatus,omitempty"`
	Matches          []packageIdentity `json:"matches,omitempty"`
}

type resolvedIdentity struct {
	PURL string `json:"purl"`
}

type correlationRule struct {
	Type        string `json:"type"`
	SourceField string `json:"sourceField"`
	TargetField string `json:"targetField"`
}

type inputRecord struct {
	Role      string `json:"role"`
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	SHA256    string `json:"sha256"`
}

type producer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type authorityBoundary struct {
	Mode     string `json:"mode"`
	ReadOnly bool   `json:"readOnly"`
}

type outputReport struct {
	Schema             string            `json:"schema"`
	ReportVersion      string            `json:"reportVersion"`
	GeneratedAt        string            `json:"generatedAt"`
	Producer           producer          `json:"producer"`
	AuthorityBoundary  authorityBoundary `json:"authorityBoundary"`
	TrivySchemaVersion int               `json:"trivySchemaVersion"`
	SRACDocumentID     string            `json:"sracDocumentId"`
	Inputs             []inputRecord     `json:"inputs"`
	Summary            map[string]int    `json:"summary"`
	Correlations       []correlation     `json:"correlations"`
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "validate-report" {
		fs := flag.NewFlagSet("validate-report", flag.ContinueOnError)
		var reportPath string
		fs.StringVar(&reportPath, "report", "", "SRAC correlation report to validate")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		if reportPath == "" {
			fmt.Fprintln(os.Stderr, "srac: --report is required")
			os.Exit(2)
		}
		if err := validateReportFile(reportPath); err != nil {
			fmt.Fprintln(os.Stderr, "srac:", err)
			os.Exit(1)
		}
		fmt.Printf("valid SRAC correlation report: %s\n", reportPath)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "correlate" {
		fmt.Fprintln(os.Stderr, "usage:")
		fmt.Fprintln(os.Stderr, "  srac correlate --trivy-report FILE --srac FILE [--sbom FILE] --output FILE [--srac-sha256 HEX]")
		fmt.Fprintln(os.Stderr, "  srac validate-report --report FILE")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("correlate", flag.ContinueOnError)
	var opts options
	fs.StringVar(&opts.trivyPath, "trivy-report", "", "saved Trivy JSON report")
	fs.StringVar(&opts.sracPath, "srac", "", "SRAC JSON document")
	fs.StringVar(&opts.sbomPath, "sbom", "", "optional CycloneDX JSON SBOM used to resolve bom-ref")
	fs.StringVar(&opts.outputPath, "output", "srac-correlation-report.json", "output report path, or - for stdout")
	fs.StringVar(&opts.expectedDigest, "srac-sha256", "", "optional expected SHA-256 digest for the SRAC file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if err := run(opts, time.Now().UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "srac:", err)
		os.Exit(1)
	}
}

func run(opts options, now time.Time) error {
	if opts.trivyPath == "" || opts.sracPath == "" {
		return errors.New("--trivy-report and --srac are required")
	}

	trivyBytes, trivyDigest, err := readAndDigest(opts.trivyPath)
	if err != nil {
		return fmt.Errorf("read Trivy report: %w", err)
	}
	sracBytes, sracDigest, err := readAndDigest(opts.sracPath)
	if err != nil {
		return fmt.Errorf("read SRAC document: %w", err)
	}
	if opts.expectedDigest != "" && !strings.EqualFold(strings.TrimSpace(opts.expectedDigest), sracDigest) {
		return fmt.Errorf("SRAC digest mismatch: expected %s, got %s", opts.expectedDigest, sracDigest)
	}

	var trivy trivyReport
	if err := json.Unmarshal(trivyBytes, &trivy); err != nil {
		return fmt.Errorf("parse Trivy JSON: %w", err)
	}
	if trivy.SchemaVersion <= 0 {
		return errors.New("Trivy report has no valid SchemaVersion")
	}
	var srac sracDocument
	if err := json.Unmarshal(sracBytes, &srac); err != nil {
		return fmt.Errorf("parse SRAC JSON: %w", err)
	}
	if srac.DocumentID == "" {
		return errors.New("SRAC documentId is required")
	}

	inputs := []inputRecord{
		newInputRecord(inputRoleTrivy, opts.trivyPath, "application/json", trivyDigest),
		newInputRecord(inputRoleSRAC, opts.sracPath, "application/srac+json", sracDigest),
	}
	bomRefs := map[string]string{}
	if opts.sbomPath != "" {
		sbomBytes, sbomDigest, err := readAndDigest(opts.sbomPath)
		if err != nil {
			return fmt.Errorf("read SBOM: %w", err)
		}
		var sbom cycloneDX
		if err := json.Unmarshal(sbomBytes, &sbom); err != nil {
			return fmt.Errorf("parse CycloneDX SBOM: %w", err)
		}
		indexCDX(sbom.Components, bomRefs)
		inputs = append(inputs, newInputRecord(inputRoleSBOM, opts.sbomPath, "application/vnd.cyclonedx+json", sbomDigest))
	}

	packages := indexPackages(trivy)
	correlations := make([]correlation, 0, len(srac.Assertions))
	summary := map[string]int{"matched": 0, "unmatched": 0, "ambiguous": 0, "invalid": 0, "stale": 0}
	for _, assertion := range srac.Assertions {
		result := correlateAssertion(assertion, bomRefs, packages, now)
		correlations = append(correlations, result)
		summary[result.State]++
	}

	out := outputReport{
		Schema: reportSchema, ReportVersion: reportVersion, GeneratedAt: now.Format(time.RFC3339),
		Producer:           producer{Name: producerName, Version: version},
		AuthorityBoundary:  authorityBoundary{Mode: "external", ReadOnly: true},
		TrivySchemaVersion: trivy.SchemaVersion, SRACDocumentID: srac.DocumentID,
		Inputs: inputs, Summary: summary, Correlations: correlations,
	}
	if err := validateReport(out); err != nil {
		return fmt.Errorf("generated report failed contract validation: %w", err)
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if opts.outputPath == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return os.WriteFile(opts.outputPath, encoded, 0o644)
}

func newInputRecord(role, path, mediaType, digest string) inputRecord {
	return inputRecord{Role: role, Name: filepath.Base(path), MediaType: mediaType, SHA256: digest}
}

func validateReportFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}
	for _, field := range []string{
		"schema", "reportVersion", "generatedAt", "producer", "authorityBoundary",
		"trivySchemaVersion", "sracDocumentId", "inputs", "summary", "correlations",
	} {
		if _, ok := raw[field]; !ok {
			return fmt.Errorf("required field %q is missing", field)
		}
	}
	var report outputReport
	if err := json.Unmarshal(b, &report); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}
	return validateReport(report)
}

func validateReport(report outputReport) error {
	if report.Schema != reportSchema {
		return fmt.Errorf("unsupported schema %q", report.Schema)
	}
	major, err := semanticVersionMajor(report.ReportVersion)
	if err != nil || major != 1 {
		return fmt.Errorf("unsupported reportVersion %q", report.ReportVersion)
	}
	if _, err := time.Parse(time.RFC3339, report.GeneratedAt); err != nil {
		return errors.New("generatedAt must be RFC3339")
	}
	if report.Producer.Name == "" || report.Producer.Version == "" {
		return errors.New("producer name and version are required")
	}
	if _, err := semanticVersionMajor(report.Producer.Version); err != nil {
		return errors.New("producer version must use semantic versioning")
	}
	if report.AuthorityBoundary.Mode != "external" || !report.AuthorityBoundary.ReadOnly {
		return errors.New("authorityBoundary must be external and read-only")
	}
	if report.TrivySchemaVersion <= 0 {
		return errors.New("trivySchemaVersion must be positive")
	}
	if report.SRACDocumentID == "" {
		return errors.New("sracDocumentId is required")
	}

	roleCounts := map[string]int{}
	for _, input := range report.Inputs {
		if input.Role != inputRoleTrivy && input.Role != inputRoleSRAC && input.Role != inputRoleSBOM {
			return fmt.Errorf("unsupported input role %q", input.Role)
		}
		roleCounts[input.Role]++
		if input.Name == "" || strings.ContainsAny(input.Name, `/\\`) {
			return fmt.Errorf("input %q must use a portable base name", input.Name)
		}
		if input.MediaType == "" {
			return fmt.Errorf("input %q has no mediaType", input.Name)
		}
		decoded, err := hex.DecodeString(input.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("input %q has an invalid SHA-256 digest", input.Name)
		}
	}
	if roleCounts[inputRoleTrivy] != 1 || roleCounts[inputRoleSRAC] != 1 || roleCounts[inputRoleSBOM] > 1 {
		return errors.New("inputs require exactly one trivy-report and srac-document and at most one sbom")
	}

	allowedStates := map[string]bool{"matched": true, "unmatched": true, "ambiguous": true, "invalid": true, "stale": true}
	if len(report.Summary) != len(allowedStates) {
		return errors.New("summary must contain exactly the five defined correlation states")
	}
	actual := map[string]int{"matched": 0, "unmatched": 0, "ambiguous": 0, "invalid": 0, "stale": 0}
	assertionIDs := map[string]bool{}
	for _, result := range report.Correlations {
		if !allowedStates[result.State] {
			return fmt.Errorf("assertion %q has unsupported state %q", result.AssertionID, result.State)
		}
		if result.AssertionID == "" && result.State != "invalid" {
			return errors.New("assertionId is required unless the source assertion is invalid")
		}
		if result.AssertionID != "" {
			if assertionIDs[result.AssertionID] {
				return fmt.Errorf("duplicate assertionId %q", result.AssertionID)
			}
			assertionIDs[result.AssertionID] = true
		}
		actual[result.State]++

		matchCount := len(result.Matches)
		switch result.State {
		case "matched":
			if matchCount != 1 {
				return fmt.Errorf("matched assertion %q must have exactly one match", result.AssertionID)
			}
		case "ambiguous":
			if matchCount < 2 {
				return fmt.Errorf("ambiguous assertion %q must have at least two matches", result.AssertionID)
			}
		default:
			if matchCount != 0 {
				return fmt.Errorf("%s assertion %q must not contain matches", result.State, result.AssertionID)
			}
		}

		if result.State == "matched" || result.State == "ambiguous" {
			if result.ResolvedIdentity == nil || result.ResolvedIdentity.PURL == "" {
				return fmt.Errorf("%s assertion %q requires a resolved pURL", result.State, result.AssertionID)
			}
			if result.CorrelationRule == nil {
				return fmt.Errorf("%s assertion %q requires correlationRule", result.State, result.AssertionID)
			}
		}
		if result.CorrelationRule != nil {
			rule := result.CorrelationRule
			if rule.Type != correlationPURL && rule.Type != correlationBOMRef {
				return fmt.Errorf("assertion %q has unsupported correlation rule %q", result.AssertionID, rule.Type)
			}
			if rule.SourceField == "" || rule.TargetField == "" {
				return fmt.Errorf("assertion %q has an incomplete correlationRule", result.AssertionID)
			}
		}
	}
	for state := range report.Summary {
		if !allowedStates[state] {
			return fmt.Errorf("summary has unsupported state %q", state)
		}
	}
	for state := range allowedStates {
		if report.Summary[state] != actual[state] {
			return fmt.Errorf("summary count for %s is %d, expected %d", state, report.Summary[state], actual[state])
		}
	}
	return nil
}

func semanticVersionMajor(value string) (int, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return 0, errors.New("version must have major.minor.patch")
	}
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return 0, err
		}
	}
	return strconv.Atoi(parts[0])
}

func readAndDigest(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	h := sha256.New()
	b, err := io.ReadAll(io.TeeReader(f, h))
	if err != nil {
		return nil, "", err
	}
	return b, hex.EncodeToString(h.Sum(nil)), nil
}

func indexCDX(components []cdxComponent, refs map[string]string) {
	for _, c := range components {
		if c.BOMRef != "" && c.PURL != "" {
			refs[c.BOMRef] = c.PURL
		}
		indexCDX(c.Components, refs)
	}
}

func indexPackages(report trivyReport) map[string][]packageIdentity {
	type mutablePackage struct {
		identity packageIdentity
		findings map[string]finding
		targets  map[string]bool
	}
	mutable := map[string]*mutablePackage{}
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			purl := strings.TrimSpace(pkg.Identifier.PURL)
			if purl == "" {
				continue
			}
			key := purl + "\x00" + pkg.Name + "\x00" + pkg.Version
			if mutable[key] == nil {
				mutable[key] = &mutablePackage{identity: packageIdentity{PURL: purl, Name: pkg.Name, Version: pkg.Version}, findings: map[string]finding{}, targets: map[string]bool{}}
			}
			mutable[key].targets[result.Target] = true
		}
	}
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			vpurl := strings.TrimSpace(vuln.Identifier.PURL)
			for _, pkg := range mutable {
				identityMatch := vpurl != "" && vpurl == pkg.identity.PURL
				fallbackMatch := vpurl == "" && vuln.PkgName == pkg.identity.Name && vuln.InstalledVersion == pkg.identity.Version
				if identityMatch || fallbackMatch {
					pkg.findings[vuln.VulnerabilityID] = finding{ID: vuln.VulnerabilityID, Severity: vuln.Severity}
				}
			}
		}
	}

	byPURL := map[string][]packageIdentity{}
	for _, pkg := range mutable {
		for target := range pkg.targets {
			pkg.identity.Targets = append(pkg.identity.Targets, target)
		}
		for _, f := range pkg.findings {
			pkg.identity.Findings = append(pkg.identity.Findings, f)
		}
		sort.Strings(pkg.identity.Targets)
		sort.Slice(pkg.identity.Findings, func(i, j int) bool { return pkg.identity.Findings[i].ID < pkg.identity.Findings[j].ID })
		byPURL[pkg.identity.PURL] = append(byPURL[pkg.identity.PURL], pkg.identity)
	}
	for purl := range byPURL {
		sort.Slice(byPURL[purl], func(i, j int) bool {
			left, right := byPURL[purl][i], byPURL[purl][j]
			if left.Name != right.Name {
				return left.Name < right.Name
			}
			return left.Version < right.Version
		})
	}
	return byPURL
}

func correlateAssertion(a sracAssertion, bomRefs map[string]string, packages map[string][]packageIdentity, now time.Time) correlation {
	result := correlation{
		AssertionID: a.ID, SafetyRelevance: a.SafetyRelevance, Rationale: a.Rationale,
		SourceURI: a.SourceURI, Evidence: a.Evidence, ReviewStatus: a.ReviewStatus,
	}
	if a.ID == "" || a.SafetyRelevance == "" {
		result.State, result.Reason = "invalid", "assertion id and safetyRelevance are required"
		return result
	}
	purl := strings.TrimSpace(a.Component.PURL)
	rule := correlationRule{Type: correlationPURL, SourceField: "component.purl", TargetField: "PkgIdentifier.PURL"}
	if purl == "" && a.Component.BOMRef != "" {
		purl = bomRefs[a.Component.BOMRef]
		if purl == "" {
			result.State, result.Reason = "invalid", "bomRef could not be resolved through the supplied SBOM"
			return result
		}
		rule = correlationRule{Type: correlationBOMRef, SourceField: "component.bomRef", TargetField: "PkgIdentifier.PURL"}
	}
	if purl == "" {
		result.State, result.Reason = "invalid", "component purl or resolvable bomRef is required; name-only matching is prohibited"
		return result
	}
	result.ResolvedIdentity = &resolvedIdentity{PURL: purl}
	if a.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339, a.ValidUntil)
		if err != nil {
			result.State, result.Reason = "invalid", "validUntil must be RFC3339"
			return result
		}
		if now.After(until) {
			result.State, result.Reason = "stale", "assertion validity period has expired"
			return result
		}
	}
	matches := packages[purl]
	if len(matches) == 0 {
		result.State, result.Reason = "unmatched", "no Trivy package has the asserted pURL"
		return result
	}
	result.Matches = matches
	if len(matches) > 1 {
		result.CorrelationRule = &rule
		result.State, result.Reason = "ambiguous", "the asserted pURL resolves to multiple distinct package identities"
		return result
	}
	result.CorrelationRule = &rule
	result.State = "matched"
	return result
}
