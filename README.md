# aws-compliance-as-code

Automated, repeatable compliance evidence for an AWS account, mapped to NIST 800-53, SOC 2, ISO 27001 and the CIS AWS Foundations Benchmark.

## The problem

Audit evidence is still mostly collected by hand. Someone logs into the console, takes screenshots of the IAM password policy, exports a CloudTrail config, pastes it into a spreadsheet, and repeats the whole thing next quarter for a different framework. It is slow, it only proves the state of the account on the day the screenshot was taken, and the same AWS setting gets re-collected separately for SOC 2, ISO and NIST even though it is one fact.

## What this repo does

- **`controls.yaml`** is a single control catalog. Each control is one testable AWS setting (for example, "root account has MFA") with a crosswalk to the requirement IDs it satisfies in four frameworks.
- Each control names a **check function** that calls the AWS API (read-only, through `boto3`) and returns pass/fail plus the raw API response.
- The raw response is saved as **evidence**: timestamped, machine-generated, and re-runnable on demand.

Test once, satisfy many frameworks.

## How to run

Requirements: Python 3.11+, the AWS CLI v2, and a read-only profile (`SecurityAudit` + `ReadOnlyAccess`).

```bash
git clone https://github.com/Mihirajmera/aws-compliance-as-code.git
cd aws-compliance-as-code
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

aws configure sso --profile pm
aws sts get-caller-identity --profile pm
```

Run every control and print a PASS/FAIL table. Each control writes one evidence file to `evidence/<YYYY-MM-DD>/<CONTROL-ID>.json` with a timestamp, the account ID, the API call, the raw response and a SHA-256 of the raw response (canonical JSON: sorted keys, no spaces), so any edit is detectable:

```bash
python run.py --profile pm
```

Run the unit tests offline against mocked AWS (`moto`), with no account needed:

```bash
pytest -q
```

Controls whose check is not written yet show as `NOT_IMPLEMENTED`.

## Controls

| ID | Control |
|----|---------|
| IAM-01 | Root account has MFA enabled |
| IAM-02 | Root account has no access keys |
| IAM-03 | IAM password policy meets minimum strength |
| IAM-04 | Access keys are rotated within 90 days |
| IAM-05 | Unused credentials are disabled |
| IAM-06 | No policies grant full `*:*` administrative privileges |
| LOG-01 | CloudTrail is enabled in all regions |
| LOG-02 | CloudTrail log file validation is enabled |
| DATA-01 | S3 Block Public Access is enabled at the account level |
| DATA-02 | S3 buckets have default encryption configured |
| DATA-03 | EBS encryption by default is enabled |
| DET-01 | GuardDuty is enabled |
| DET-02 | Security Hub is enabled |
| NET-01 | VPC flow logs are enabled |
| CFG-01 | AWS Config recorder is on |

Framework versions: NIST SP 800-53 Rev. 5, AICPA TSC 2017 (rev. 2022), ISO/IEC 27001:2022 Annex A, CIS AWS Foundations v3.0.0. Mappings are my own judgment and should be checked against the official crosswalks before being relied on in a real audit.

## Safety

This project runs only against a dedicated sandbox AWS account, uses read-only credentials, and never stores credentials in the repo.
