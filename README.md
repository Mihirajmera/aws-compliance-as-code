# aws-compliance-as-code

[![Tests](https://github.com/Mihirajmera/aws-compliance-as-code/actions/workflows/tests.yml/badge.svg)](https://github.com/Mihirajmera/aws-compliance-as-code/actions/workflows/tests.yml)
[![CodeQL](https://github.com/Mihirajmera/aws-compliance-as-code/actions/workflows/codeql.yml/badge.svg)](https://github.com/Mihirajmera/aws-compliance-as-code/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Mihirajmera/aws-compliance-as-code/badge)](https://scorecard.dev/viewer/?uri=github.com/Mihirajmera/aws-compliance-as-code)
[![Release](https://img.shields.io/github/v/release/Mihirajmera/aws-compliance-as-code?color=0891b2)](https://github.com/Mihirajmera/aws-compliance-as-code/releases)

Automated, repeatable compliance evidence for an AWS account, mapped to NIST 800-53, SOC 2, ISO 27001 and the CIS AWS Foundations Benchmark, and exported as OSCAL.

## Problem

Audit evidence is still mostly collected by hand. Someone logs into the console, takes screenshots of the IAM password policy, exports a CloudTrail config, pastes it into a spreadsheet, and repeats the whole thing next quarter for a different framework. It is slow, it only proves the state of the account on the day the screenshot was taken, nobody can tell whether a screenshot was edited, and the same AWS setting gets re-collected separately for SOC 2, ISO and NIST even though it is one fact.

## How it works

```
controls.yaml ──> run.py ──> checks/*.py ──(read-only AWS API)──> evidence/<date>/<CONTROL>.json ──> oscal_export.py ──> oscal/assessment-results.json
```

1. **Control catalog.** [`controls.yaml`](controls.yaml) lists each control once, with a crosswalk to the requirement IDs it satisfies in four frameworks. Test once, satisfy many frameworks.
2. **Checks.** Each control names a Python function in [`checks/`](checks) that takes a `boto3` session, makes read-only API calls and returns `PASS`/`FAIL`, the findings, the API calls used and the **raw API response**, so an auditor can re-perform the test from the evidence alone.
3. **Hashed evidence.** [`run.py`](run.py) writes one file per control to `evidence/<YYYY-MM-DD>/<CONTROL-ID>.json` with a timestamp, the account ID, the API call, the raw response and a SHA-256 of the raw response as canonical JSON (sorted keys, no spaces). Any edit to the raw data breaks the hash.
4. **OSCAL.** [`oscal_export.py`](oscal_export.py) turns a day's evidence into an [OSCAL](https://pages.nist.gov/OSCAL/) 1.1.2 **assessment-results** document: one *observation* per control pointing at its evidence file and hash, and one *finding* per mapped NIST 800-53 control objective (`satisfied` / `not-satisfied`). Any GRC tool that reads OSCAL can ingest it.
5. **Tested offline.** Every check has unit tests that run against AWS mocked with [moto](https://github.com/getmoto/moto), covering both the compliant and non-compliant case. [`.github/workflows/tests.yml`](.github/workflows/tests.yml) runs them on every push, so the project is verified without needing a live AWS account.

## Controls covered

| ID | Control | Check |
|----|---------|-------|
| IAM-01 | Root account has MFA enabled | `check_root_mfa` |
| IAM-02 | Root account has no access keys | `check_root_access_keys` |
| IAM-03 | IAM password policy meets minimum strength | `check_password_policy` |
| IAM-04 | Access keys are rotated within 90 days | `check_access_key_age` |
| IAM-05 | Unused credentials are disabled | `check_unused_credentials` |
| IAM-06 | No policies grant full `*:*` administrative privileges | `check_no_wildcard_admin` |
| LOG-01 | CloudTrail is enabled in all regions | `check_cloudtrail_multi_region` |
| LOG-02 | CloudTrail log file validation is enabled | `check_cloudtrail_log_validation` |
| DATA-01 | S3 Block Public Access is enabled at the account level | `check_s3_account_public_access_block` |
| DATA-02 | S3 buckets have default encryption configured | `check_s3_default_encryption` |
| DATA-03 | EBS encryption by default is enabled | `check_ebs_default_encryption` |
| DET-01 | GuardDuty is enabled | `check_guardduty_enabled` |
| DET-02 | Security Hub is enabled | `check_securityhub_enabled` |
| NET-01 | VPC flow logs are enabled | not implemented yet |
| CFG-01 | AWS Config recorder is on | not implemented yet |

Framework versions: NIST SP 800-53 Rev. 5, AICPA TSC 2017 (rev. 2022), ISO/IEC 27001:2022 Annex A, CIS AWS Foundations v3.0.0. Mappings are my own judgment and should be checked against the official crosswalks before being relied on in a real audit.

## Run it

Requirements: Python 3.11+, the AWS CLI v2, and a read-only profile (`SecurityAudit` + `ReadOnlyAccess`).

```bash
git clone https://github.com/Mihirajmera/aws-compliance-as-code.git
cd aws-compliance-as-code
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

aws configure sso --profile pm
python run.py --profile pm        # PASS/FAIL table + evidence/<today>/*.json
python oscal_export.py            # oscal/assessment-results.json
pytest -q                         # offline unit tests against mocked AWS (moto)
```

No AWS account? `pytest -q` exercises every check against mocked AWS, with no credentials needed.

## What I'd do at enterprise scale

- **Run it continuously.** Schedule it in CI with short-lived OIDC credentials (no stored AWS keys) and commit each day's evidence, giving a dated, version-controlled evidence history.
- **Many accounts, one run.** Run from a security tooling account and assume a read-only audit role in every member account through AWS Organizations, so one nightly job covers hundreds of accounts.
- **Lean on native services.** Use AWS Config conformance packs and Security Hub's CIS/NIST standards for continuous detection, and keep this pipeline for what auditors actually need: evidence tied to framework requirements, in OSCAL.
- **Make evidence tamper-evident beyond the hash.** Write evidence to an S3 bucket with Object Lock (WORM) in a separate account, and sign each file or chain the hashes so editing evidence also needs access the editor doesn't have.
- **Close the loop.** Turn `not-satisfied` findings into OSCAL POA&M items and tickets with owners and due dates, and track exceptions with expiry dates instead of letting them live forever.
- **Govern the catalog.** Version `controls.yaml` with reviews from compliance, security and the control owners, and validate OSCAL output against the official NIST schemas in CI.

## Safety

Every check is read-only and only needs the `SecurityAudit` / `ReadOnlyAccess` managed policies. No credentials are stored in this repo. If you run it against a real account, note that evidence files contain the account ID and IAM user names, so keep `evidence/` out of public repos.
