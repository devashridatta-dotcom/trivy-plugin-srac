# SRAC input contract

The initial implementation accepts a compact, transport-neutral SRAC document.
Unknown fields are ignored so additive producer changes do not break consumers.

```json
{
  "schemaVersion": "1.0",
  "documentId": "urn:example:srac:vehicle-a:2026-10-09",
  "generatedAt": "2026-10-09T12:00:00Z",
  "assertions": [
    {
      "id": "SRAC-001",
      "component": {
        "purl": "pkg:maven/org.example/controller@1.2.3"
      },
      "safetyRelevance": "safety-relevant",
      "rationale": "Used in the braking control path.",
      "sourceUri": "https://example.org/safety/SRAC-001",
      "evidence": ["urn:example:evidence:test-42"],
      "reviewStatus": "approved",
      "validUntil": "2027-10-09T12:00:00Z"
    }
  ]
}
```

## Required fields

- `documentId`
- `assertions[].id`
- `assertions[].safetyRelevance`
- either `assertions[].component.purl`, or
  `assertions[].component.bomRef` together with `--sbom`

`validUntil`, when present, must be an RFC 3339 timestamp. The plugin reports an
expired assertion as `stale`. It never converts that state into a new safety
decision.

## Identity rules

1. Exact pURL identity is authoritative for correlation.
2. `bomRef` is resolved through an explicitly supplied CycloneDX SBOM.
3. Package names alone are not identities and are never used to correlate an
   assertion.
4. Multiple distinct Trivy package records for one pURL produce `ambiguous`, not
   an arbitrary match.
