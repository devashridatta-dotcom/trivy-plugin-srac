#!/usr/bin/env python3
"""Validate the published schema and structural conformance fixtures."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "srac-correlation-report-1.0.schema.json"
FIXTURES = ROOT / "testdata" / "conformance"

VALID = (
    "valid-matched.json",
    "valid-unmatched.json",
    "valid-ambiguous.json",
    "valid-stale.json",
    "forward-compatible-unknown-field.json",
)

STRUCTURALLY_INVALID = (
    "invalid-digest.json",
    "invalid-name-only-rule.json",
)


def load(path: Path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> None:
    schema = load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for name in VALID:
        errors = sorted(validator.iter_errors(load(FIXTURES / name)), key=str)
        if errors:
            raise SystemExit(f"{name}: {errors[0].message}")

    for name in STRUCTURALLY_INVALID:
        if not list(validator.iter_errors(load(FIXTURES / name))):
            raise SystemExit(f"{name}: invalid fixture unexpectedly passed JSON Schema")


if __name__ == "__main__":
    main()
