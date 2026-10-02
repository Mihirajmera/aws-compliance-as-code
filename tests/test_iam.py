import datetime
import json

import boto3
import pytest
from moto import mock_aws

from checks.iam import (check_access_key_age, check_no_wildcard_admin, check_password_policy,
                        check_root_access_keys, check_root_mfa, check_unused_credentials)


@pytest.fixture
def session(monkeypatch):
    for var in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    with mock_aws():
        yield boto3.Session(region_name='us-east-1')


def in_days(days):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)


# IAM-01
def test_root_mfa_fails_when_not_enabled(session):
    result = check_root_mfa(session)
    assert result['status'] == 'FAIL'
    assert result['raw']['AccountMFAEnabled'] == 0


# IAM-02
def test_root_access_keys_pass_when_none_present(session):
    assert check_root_access_keys(session)['status'] == 'PASS'


# IAM-03
@mock_aws
def test_password_policy_fails_when_missing():
    assert check_password_policy(boto3.Session(region_name='us-east-1'))['status'] == 'FAIL'


def test_password_policy_fails_when_too_weak(session):
    session.client('iam').update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=24)
    result = check_password_policy(session)
    assert result['status'] == 'FAIL'
    assert any('MinimumPasswordLength' in f for f in result['findings'])


def test_password_policy_passes_when_strong(session):
    session.client('iam').update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert check_password_policy(session)['status'] == 'PASS'


# IAM-04
def test_access_key_age_passes_for_new_key(session):
    iam = session.client('iam')
    iam.create_user(UserName='alice')
    iam.create_access_key(UserName='alice')
    assert check_access_key_age(session)['status'] == 'PASS'


def test_access_key_age_fails_for_key_older_than_90_days(session):
    iam = session.client('iam')
    iam.create_user(UserName='alice')
    iam.create_access_key(UserName='alice')
    result = check_access_key_age(session, now=in_days(91))
    assert result['status'] == 'FAIL'
    assert 'alice' in result['findings'][0]


def test_access_key_age_ignores_inactive_keys(session):
    iam = session.client('iam')
    iam.create_user(UserName='alice')
    key = iam.create_access_key(UserName='alice')['AccessKey']
    iam.update_access_key(UserName='alice', AccessKeyId=key['AccessKeyId'], Status='Inactive')
    assert check_access_key_age(session, now=in_days(91))['status'] == 'PASS'


# IAM-05
def test_unused_credentials_passes_for_recent_key(session):
    iam = session.client('iam')
    iam.create_user(UserName='bob')
    iam.create_access_key(UserName='bob')
    assert check_unused_credentials(session)['status'] == 'PASS'


def test_unused_credentials_fails_for_key_unused_46_days(session):
    iam = session.client('iam')
    iam.create_user(UserName='bob')
    iam.create_access_key(UserName='bob')
    result = check_unused_credentials(session, now=in_days(46))
    assert result['status'] == 'FAIL'
    assert 'bob' in result['findings'][0]


# IAM-06
def _create_policy(iam, name, statement):
    iam.create_policy(PolicyName=name, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [statement]}))


def test_wildcard_admin_fails_for_star_star_policy(session):
    iam = session.client('iam')
    _create_policy(iam, 'god-mode', {'Effect': 'Allow', 'Action': '*', 'Resource': '*'})
    result = check_no_wildcard_admin(session)
    assert result['status'] == 'FAIL'
    assert 'god-mode' in result['findings'][0]


def test_wildcard_admin_passes_for_scoped_policy(session):
    iam = session.client('iam')
    _create_policy(iam, 's3-read', {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'})
    assert check_no_wildcard_admin(session)['status'] == 'PASS'
