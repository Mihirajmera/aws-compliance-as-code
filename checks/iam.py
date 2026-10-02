import csv
import datetime
import io
import json
import time
import urllib.parse

MIN_PASSWORD_LENGTH = 14
MIN_PASSWORD_REUSE_PREVENTION = 24
MAX_ACCESS_KEY_AGE_DAYS = 90
MAX_UNUSED_DAYS = 45


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _result(control_id, passed, api_call, raw, findings=None):
    return {
        'control_id': control_id,
        'status': 'PASS' if passed else 'FAIL',
        'api_call': api_call,
        'findings': findings or [],
        'raw': raw,
    }


def _parse_date(value):
    """Credential report dates are ISO 8601 strings, or 'N/A' / 'no_information'."""
    if not value or value in ('N/A', 'no_information', 'not_supported'):
        return None
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))


def get_credential_report(iam, timeout=60):
    """Generate the IAM credential report and return its rows as a list of dicts."""
    deadline = time.time() + timeout
    while iam.generate_credential_report()['State'] != 'COMPLETE':
        if time.time() > deadline:
            raise TimeoutError('IAM credential report was not ready in time')
        time.sleep(2)
    content = iam.get_credential_report()['Content']
    if isinstance(content, bytes):
        content = content.decode('utf-8')
    return list(csv.DictReader(io.StringIO(content)))


def check_root_mfa(session):
    s = session.client('iam').get_account_summary()['SummaryMap']
    return _result('IAM-01', s.get('AccountMFAEnabled') == 1, 'iam:GetAccountSummary', s)


def check_root_access_keys(session):
    s = session.client('iam').get_account_summary()['SummaryMap']
    return _result('IAM-02', s.get('AccountAccessKeysPresent', 0) == 0, 'iam:GetAccountSummary', s)


def check_password_policy(session):
    iam = session.client('iam')
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
    except iam.exceptions.NoSuchEntityException:
        return _result('IAM-03', False, 'iam:GetAccountPasswordPolicy', {},
                       ['No account password policy is set'])

    findings = []
    if policy.get('MinimumPasswordLength', 0) < MIN_PASSWORD_LENGTH:
        findings.append(f"MinimumPasswordLength {policy.get('MinimumPasswordLength')} < {MIN_PASSWORD_LENGTH}")
    if policy.get('PasswordReusePrevention', 0) < MIN_PASSWORD_REUSE_PREVENTION:
        findings.append(f"PasswordReusePrevention {policy.get('PasswordReusePrevention')} < {MIN_PASSWORD_REUSE_PREVENTION}")
    return _result('IAM-03', not findings, 'iam:GetAccountPasswordPolicy', policy, findings)


def check_access_key_age(session, now=None):
    now = now or _now()
    iam = session.client('iam')
    raw, findings = [], []
    for page in iam.get_paginator('list_users').paginate():
        for user in page['Users']:
            for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                raw.append(key)
                age = (now - key['CreateDate']).days
                if key['Status'] == 'Active' and age > MAX_ACCESS_KEY_AGE_DAYS:
                    findings.append(f"{user['UserName']}: key {key['AccessKeyId']} is {age} days old")
    return _result('IAM-04', not findings, 'iam:ListUsers, iam:ListAccessKeys', raw, findings)


def check_unused_credentials(session, now=None):
    now = now or _now()
    rows = get_credential_report(session.client('iam'))
    limit = datetime.timedelta(days=MAX_UNUSED_DAYS)
    findings = []
    for row in rows:
        if row['user'] == '<root_account>':
            continue  # root is covered by IAM-01 / IAM-02
        if row.get('password_enabled') == 'true':
            last = _parse_date(row.get('password_last_used')) or _parse_date(row.get('password_last_changed'))
            if last and now - last > limit:
                findings.append(f"{row['user']}: console password unused for {(now - last).days} days")
        for n in ('1', '2'):
            if row.get(f'access_key_{n}_active') == 'true':
                last = (_parse_date(row.get(f'access_key_{n}_last_used_date'))
                        or _parse_date(row.get(f'access_key_{n}_last_rotated')))
                if last and now - last > limit:
                    findings.append(f"{row['user']}: access key {n} unused for {(now - last).days} days")
    return _result('IAM-05', not findings, 'iam:GenerateCredentialReport, iam:GetCredentialReport', rows, findings)


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _is_full_admin(document):
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    for stmt in _as_list(document.get('Statement', [])):
        if (stmt.get('Effect') == 'Allow'
                and '*' in _as_list(stmt.get('Action', []))
                and '*' in _as_list(stmt.get('Resource', []))):
            return True
    return False


def check_no_wildcard_admin(session):
    iam = session.client('iam')
    raw, findings = [], []
    for page in iam.get_paginator('list_policies').paginate(Scope='Local', OnlyAttached=False):
        for policy in page['Policies']:
            version = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
            document = version['PolicyVersion']['Document']
            raw.append({'PolicyArn': policy['Arn'], 'Document': document})
            if _is_full_admin(document):
                findings.append(f"{policy['PolicyName']} allows Action '*' on Resource '*'")
    return _result('IAM-06', not findings, 'iam:ListPolicies, iam:GetPolicyVersion', raw, findings)
