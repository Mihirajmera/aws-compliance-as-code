# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub's private vulnerability reporting:

**https://github.com/Mihirajmera/aws-compliance-as-code/security/advisories/new**

What to expect:

- **Acknowledgement within 5 business days.**
- **An assessment within 14 days**: whether it's accepted as a vulnerability, its severity, and a planned fix.
- **Coordinated disclosure**: a fix is released and the advisory published together, normally within 90 days of the report. You'll be credited in the advisory unless you'd rather not be.

## Scope

Every check is read-only against the AWS API. Evidence files contain the account ID and IAM user names. Especially relevant: a check that could modify AWS resources, credentials appearing in evidence or OSCAL output, or a way to change evidence without breaking its SHA-256 hash.

## Supply chain

GitHub Actions are pinned to commit SHAs, dependencies are pinned by hash, and CodeQL, OpenSSF Scorecard and Dependabot run on this repository.
