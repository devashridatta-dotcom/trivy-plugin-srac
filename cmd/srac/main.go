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
	"sort"
	"strings"
	"time"
)

const version = "0.1.0"

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
	AssertionID     string            `json:"assertionId"`
	State           string            `json:"state"`
	SafetyRelevance string            `json:"safetyRelevance,omitempty"`
	ResolvedPURL    string            `json:"resolvedPurl,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Rationale       string            `json:"rationale,omitempty"`
	SourceURI       string            `json:"sourceUri,omitempty"`
	Evidence        []string          `json:"evidence,omitempty"`
	ReviewStatus    string            `json:"reviewStatus,omitempty"`
	Matches         []packageIdentity `json:"matches,omitempty"`
}

type digestRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type outputReport struct {
	ReportVersion      string         `json:"reportVersion"`
	GeneratedAt        string         `json:"generatedAt"`
	TrivySchemaVersion int            `json:"trivySchemaVersion"`
	SRACDocumentID     string         `json:"sracDocumentId"`
	Inputs             []digestRecord `json:"inputs"`
	Summary            map[string]int `json:"summary"`
	Correlations       []correlation  `json:"correlations"`
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "correlate" {
		fmt.Fprintln(os.Stderr, "usage: srac correlate --trivy-report FILE --srac FILE [--sbom FILE] --output FILE [--srac-sha256 HEX]")
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

	inputs := []digestRecord{{Path: opts.trivyPath, SHA256: trivyDigest}, {Path: opts.sracPath, SHA256: sracDigest}}
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
		inputs = append(inputs, digestRecord{Path: opts.sbomPath, SHA256: sbomDigest})
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
		ReportVersion: "1.0", GeneratedAt: now.Format(time.RFC3339),
		TrivySchemaVersion: trivy.SchemaVersion, SRACDocumentID: srac.DocumentID,
		Inputs: inputs, Summary: summary, Correlations: correlations,
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
	if purl == "" && a.Component.BOMRef != "" {
		purl = bomRefs[a.Component.BOMRef]
		if purl == "" {
			result.State, result.Reason = "invalid", "bomRef could not be resolved through the supplied SBOM"
			return result
		}
	}
	if purl == "" {
		result.State, result.Reason = "invalid", "component purl or resolvable bomRef is required; name-only matching is prohibited"
		return result
	}
	result.ResolvedPURL = purl
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
		result.State, result.Reason = "ambiguous", "the asserted pURL resolves to multiple distinct package identities"
		return result
	}
	result.State = "matched"
	return result
}
