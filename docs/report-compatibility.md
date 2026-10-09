# SRAC correlation report compatibility

The SRAC correlation report is the interoperability boundary between a
correlation producer and downstream consumers such as compliance systems,
graph stores, and CI workflows. Consumers do not need to import Trivy code or
reimplement SRAC correlation.

## Versions

The plugin version and report-contract version are independent:

- plugin version: `0.2.0`
- report contract: `1.0.0`
- schema identifier: `urn:srac:schema:correlation-report:1`

The report version follows semantic versioning:

- **Patch:** clarifications or fixes that do not change accepted documents.
- **Minor:** additive optional fields. Consumers must ignore unknown fields in
  the same major version.
- **Major:** removed fields, new required fields, changed field meaning, changed
  state semantics, or new correlation rules that existing consumers cannot
  safely process.

Consumers must reject unsupported major versions. A consumer that understands
version `1.x` must preserve the safety boundary and must not translate missing
or unknown information into a negative safety decision.

## Stable invariants

- The authoritative safety decision is external to the report producer.
- The report is read-only correlation output, not an approval record.
- Exactly one Trivy report and one SRAC document are identified as inputs.
- An SBOM input is optional.
- Input provenance uses portable names and SHA-256 digests, not absolute paths.
- Name-only component matching is prohibited.
- Every successful or ambiguous result records its correlation rule.
- Summary counts equal the correlation records.
- Assertion identifiers are unique when present.

## Correlation states

| State | Meaning |
|---|---|
| `matched` | The assertion resolves to exactly one distinct package identity. |
| `unmatched` | No package has the asserted identity. |
| `ambiguous` | The asserted identity resolves to multiple distinct packages. |
| `invalid` | The assertion, reference, or required identity is invalid. |
| `stale` | The assertion validity period has expired. |

Missing SRAC information is not equivalent to `not safety-relevant`.

## Validation

Validate both document structure and semantic invariants:

```bash
trivy srac validate-report --report srac-correlation-report.json
```

The command exits with status `0` only when the report satisfies the supported
major-version contract. Structural or semantic failures return a non-zero exit
status.
