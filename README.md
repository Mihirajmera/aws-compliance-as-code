# aws-compliance-as-code

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
5. **Nightly, keyless.** [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs every night at 03:30 UTC. It signs in to AWS through GitHub's OIDC provider, assuming a `SecurityAudit`-only role whose trust policy accepts only this repo's `main` branch, so no long-lived AWS keys exist anywhere. It then commits the new evidence and OSCAL output back to the repo, giving a dated, version-controlled evidence history.

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

To run it nightly from GitHub Actions, deploy the OIDC provider and role once with an admin profile, then save the role ARN as the `AWS_ROLE_ARN` repository variable:

```bash
aws cloudformation deploy --template-file infra/github-oidc.yaml --stack-name pm-github-audit --capabilities CAPABILITY_NAMED_IAM --profile <admin-profile>
aws cloudformation describe-stacks --stack-name pm-github-audit --query "Stacks[0].Outputs" --profile <admin-profile>
gh variable set AWS_ROLE_ARN --body <RoleArn>
```

## What I'd do at enterprise scale

- **Many accounts, one run.** Run from a security tooling account and assume a read-only audit role in every member account through AWS Organizations, so one nightly job covers hundreds of accounts.
- **Lean on native services.** Use AWS Config conformance packs and Security Hub's CIS/NIST standards for continuous detection, and keep this pipeline for what auditors actually need: evidence tied to framework requirements, in OSCAL.
- **Make evidence tamper-evident beyond the hash.** Write evidence to an S3 bucket with Object Lock (WORM) in a separate account, and sign each file or chain the hashes so editing evidence also needs access the editor doesn't have.
- **Close the loop.** Turn `not-satisfied` findings into OSCAL POA&M items and tickets with owners and due dates, and track exceptions with expiry dates instead of letting them live forever.
- **Govern the catalog.** Version `controls.yaml` with reviews from compliance, security and the control owners, and validate OSCAL output against the official NIST schemas in CI.

## Safety

This project runs only against a dedicated sandbox AWS account with read-only credentials. Credentials are never stored in the repo or in GitHub secrets; the workflow uses short-lived OIDC credentials. Evidence files do contain the sandbox account ID and IAM user names.
