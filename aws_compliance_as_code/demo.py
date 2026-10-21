"""Run every check against a fake, deliberately misconfigured AWS account (moto), so the
evidence, OSCAL and report can be seen without an AWS account or credentials.

The account looks like a sandbox that drifted: root without MFA, a weak password policy,
a break-glass admin policy with Action '*', a single-region trail without log validation,
partial S3 Block Public Access, an unencrypted bucket, and EBS encryption and GuardDuty
turned on in only one of the two regions the demo covers.
"""
import json
import os
import pathlib

import boto3

from . import scan
from .checks import logging_storage
from .oscal import build_assessment_results

REGIONS = ['us-east-1', 'eu-west-1']   # the demo covers two regions to keep evidence readable


def build_account(session):
    iam = session.client('iam')
    iam.update_account_password_policy(MinimumPasswordLength=8)   # no reuse prevention either
    iam.create_user(UserName='alice')
    iam.create_login_profile(UserName='alice', Password='example-Passw0rd!')
    iam.create_user(UserName='ci-deploy')
    iam.create_access_key(UserName='ci-deploy')
    iam.create_policy(PolicyName='BreakGlassAdmin', PolicyDocument=json.dumps(
        {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}))
    iam.create_policy(PolicyName='DeployToS3', PolicyDocument=json.dumps(
        {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:PutObject',
                                                  'Resource': 'arn:aws:s3:::acme-app-artifacts/*'}]}))

    s3 = session.client('s3', region_name='us-east-1')
    for bucket in ('acme-cloudtrail-logs', 'acme-app-artifacts', 'acme-customer-exports'):
        s3.create_bucket(Bucket=bucket)
    for bucket in ('acme-cloudtrail-logs', 'acme-app-artifacts'):
        s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
    account = session.client('sts').get_caller_identity()['Account']
    session.client('s3control', region_name='us-east-1').put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration={
            'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False})

    ct = session.client('cloudtrail', region_name='us-east-1')
    ct.create_trail(Name='acme-audit', S3BucketName='acme-cloudtrail-logs', IsMultiRegionTrail=False,
                    EnableLogFileValidation=False)
    ct.start_logging(Name='acme-audit')

    session.client('ec2', region_name='us-east-1').enable_ebs_encryption_by_default()
    session.client('guardduty', region_name='us-east-1').create_detector(Enable=True)
    for region in REGIONS:
        session.client('securityhub', region_name=region).enable_security_hub()
    return account


def run_demo(out):
    from moto import mock_aws   # optional dependency: pip install "aws-compliance-as-code[demo]"

    out = pathlib.Path(out)
    for var in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE'):
        os.environ.pop(var, None)
    os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing', AWS_DEFAULT_REGION='us-east-1')
    controls = scan.load_controls()
    original = logging_storage.enabled_regions
    logging_storage.enabled_regions = lambda session: REGIONS
    try:
        with mock_aws():
            session = boto3.Session(region_name='us-east-1')
            account = build_account(session)
            results = scan.run(session, controls)
            scan.write_evidence(results, account, out / 'evidence')
    finally:
        logging_storage.enabled_regions = original

    doc = build_assessment_results(out / 'evidence', controls, root=out)
    (out / 'oscal').mkdir(parents=True, exist_ok=True)
    (out / 'oscal' / 'assessment-results.json').write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8', newline='\n')
    write_report(results, controls, out / 'report.md')
    return results, controls


def write_report(results, controls, path):
    by_id = {c['id']: c for c in controls}
    counts = {s: sum(r['status'] == s for r in results) for s in ('PASS', 'FAIL', 'NOT_IMPLEMENTED', 'ERROR')}
    lines = ['# AWS control assessment (demo account)', '',
             'A fake, deliberately misconfigured account created with moto; no real AWS account is touched. '
             f'Regions covered: {", ".join(REGIONS)}.', '',
             f"**{counts['PASS']} pass · {counts['FAIL']} fail · {counts['NOT_IMPLEMENTED']} not implemented**", '',
             '| Control | Status | Title | NIST 800-53 | CIS AWS | Findings |', '|---|---|---|---|---|---|']
    for r in results:
        c = by_id.get(r['control_id'], {})
        m = c.get('mappings', {})
        findings = '<br>'.join(r.get('findings', [])) or '–'
        evidence = f"[{r['control_id']}](evidence/{r['control_id']}.json)" if 'raw' in r else r['control_id']
        lines.append(f"| {evidence} | {r['status']} | {c.get('title', '')} | {', '.join(m.get('nist_800_53', []))} | "
                     f"{', '.join(m.get('cis_aws', []))} | {findings} |")
    lines += ['', 'Every evidence file holds the raw API response and its SHA-256; '
              '[`oscal/assessment-results.json`](oscal/assessment-results.json) has one observation per control '
              'and one finding per mapped NIST 800-53 objective.']
    pathlib.Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
