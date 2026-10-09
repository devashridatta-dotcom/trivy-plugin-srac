# Trivy SRAC plugin

`trivy-plugin-srac` correlates an externally authored Safety Relevance
Assertion and Context (SRAC) document with packages and vulnerabilities in a
saved Trivy JSON report. It preserves the source artifacts, records their
SHA-256 digests, and produces a machine-readable correlation report.

The plugin is deliberately read-only: it does not create, modify, or approve a
safety decision. Product safety owners remain authoritative for the SRAC
assertions.

## Initial scope

- Read Trivy JSON through the versioned `SchemaVersion` field.
- Ignore unknown JSON fields and tolerate omitted optional fields.
- Correlate by exact pURL and version, never by package name alone.
- Optionally resolve CycloneDX `bom-ref` values through a supplied SBOM.
- Verify an expected SHA-256 digest for the SRAC input when supplied.
- Report `matched`, `unmatched`, `ambiguous`, `invalid`, and `stale` states.
- Preserve assertion source, evidence, review state, and input digests.

## Build

```bash
go build -o srac ./cmd/srac
```

## Usage

```bash
trivy fs --format json --output trivy-report.json .

trivy srac correlate \
  --trivy-report trivy-report.json \
  --srac product.srac.json \
  --sbom product.cdx.json \
  --output srac-correlation-report.json
```

The SBOM argument is optional. It is needed only when an assertion is bound by
`bom-ref` instead of pURL. To fail closed against a known SRAC digest, add:

```bash
--srac-sha256 <expected-lowercase-or-uppercase-sha256>
```

For local development, invoke the binary directly:

```bash
./srac correlate --trivy-report testdata/trivy-report.json \
  --srac testdata/product.srac.json --output report.json
```

## Correlation contract

An assertion matches only when its pURL identity agrees with a package in the
Trivy report. If the SRAC document supplies a `bomRef`, the plugin first resolves
that value through the optional CycloneDX SBOM and then applies the same pURL
rule. A name-only match is never accepted.

The plugin does not infer safety relevance from a vulnerability, severity, or
package name. It only projects externally authored assertions onto identified
Trivy packages and their findings.

## Security boundary

Trivy plugins execute with the invoking user's privileges and are not sandboxed
or audited by Trivy. Review release provenance before installation and use
trusted, immutable input files. The plugin performs no network retrieval and
does not follow external references.

Automatic retrieval of SRAC documents from SPDX or CycloneDX external
references is intentionally outside this initial implementation. Current
transport conventions can be used by upstream workflows to provide explicit
files; native-format adapters can be added after the relevant standards and
implementations stabilize.

## Development

```bash
go test ./...
go vet ./...
```

See [`docs/input-contract.md`](docs/input-contract.md) for the accepted SRAC
shape and [`testdata`](testdata) for a reproducible example.

## License

Apache-2.0.
Trivy plugin for read-only SRAC safety-relevance correlation
