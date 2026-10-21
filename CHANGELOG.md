# Changelog

## 1.1.0 (unreleased)

- Installable package with an `aws-compliance-as-code` command (`scan`, `oscal`, `demo`), published to PyPI with trusted publishing and SLSA provenance. `run.py` and `oscal_export.py` still work from a clone.
- `demo` runs every check against a deliberately misconfigured fake account (moto) and writes hashed evidence, OSCAL and a report; [`sample-output/`](sample-output) is the committed result and CI checks it.
- OSCAL output is reproducible: deterministic UUIDs, `SOURCE_DATE_EPOCH` for timestamps, evidence links relative to the output folder.

## 1.0.0 (2026-10-17)

First tagged release. Read-only AWS control checks mapped to NIST 800-53, SOC 2, ISO 27001 and CIS, with SHA-256-hashed evidence and OSCAL 1.1.2 export.

- CI on Python 3.11 / current Terraform tooling with every GitHub Action pinned to a commit SHA
- Dependencies pinned by version and hash (`requirements.in` → `requirements.txt`)
- CodeQL, OpenSSF Scorecard and Dependabot
- Security policy with private vulnerability reporting
