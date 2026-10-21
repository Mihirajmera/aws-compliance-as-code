# AWS control assessment (demo account)

A fake, deliberately misconfigured account created with moto; no real AWS account is touched. Regions covered: us-east-1, eu-west-1.

**4 pass · 9 fail · 2 not implemented**

| Control | Status | Title | NIST 800-53 | CIS AWS | Findings |
|---|---|---|---|---|---|
| [IAM-01](evidence/IAM-01.json) | FAIL | Root account has MFA enabled | IA-2(1) | 1.5 | – |
| [IAM-02](evidence/IAM-02.json) | PASS | Root account has no access keys | AC-6(2), IA-2 | 1.4 | – |
| [IAM-03](evidence/IAM-03.json) | FAIL | IAM password policy meets minimum strength | IA-5(1) | 1.8, 1.9 | MinimumPasswordLength 8 < 14<br>PasswordReusePrevention None < 24 |
| [IAM-04](evidence/IAM-04.json) | PASS | Access keys are rotated within 90 days | IA-5(1), AC-2 | 1.14 | – |
| [IAM-05](evidence/IAM-05.json) | PASS | Unused credentials are disabled | AC-2(3) | 1.12 | – |
| [IAM-06](evidence/IAM-06.json) | FAIL | No policies grant full "*:*" administrative privileges | AC-6 | 1.16 | BreakGlassAdmin allows Action '*' on Resource '*' |
| [LOG-01](evidence/LOG-01.json) | FAIL | CloudTrail is enabled in all regions | AU-2, AU-12 | 3.1 | No multi-region trail is currently logging |
| [LOG-02](evidence/LOG-02.json) | FAIL | CloudTrail log file validation is enabled | AU-9 | 3.2 | acme-audit: log file validation is off |
| [DATA-01](evidence/DATA-01.json) | FAIL | S3 Block Public Access is enabled at the account level | AC-3, SC-7 | 2.1.4 | BlockPublicPolicy is false<br>RestrictPublicBuckets is false |
| [DATA-02](evidence/DATA-02.json) | FAIL | S3 buckets have default encryption configured | SC-28 | N/A - removed in CIS v2.0; AWS encrypts new buckets by default (SSE-S3) | acme-customer-exports: no default encryption |
| [DATA-03](evidence/DATA-03.json) | FAIL | EBS encryption by default is enabled | SC-28 | 2.2.1 | eu-west-1: EBS encryption by default is off |
| [DET-01](evidence/DET-01.json) | FAIL | GuardDuty is enabled | SI-4 | N/A - no GuardDuty control in CIS AWS Foundations v3.0 | eu-west-1: no enabled GuardDuty detector |
| [DET-02](evidence/DET-02.json) | PASS | Security Hub is enabled | CA-7, SI-4 | 4.16 | – |
| NET-01 | NOT_IMPLEMENTED | VPC flow logs are enabled | AU-12, SI-4 | 3.7 | – |
| CFG-01 | NOT_IMPLEMENTED | AWS Config recorder is on | CM-2, CM-8 | 3.3 | – |

Every evidence file holds the raw API response and its SHA-256; [`oscal/assessment-results.json`](oscal/assessment-results.json) has one observation per control and one finding per mapped NIST 800-53 objective.
