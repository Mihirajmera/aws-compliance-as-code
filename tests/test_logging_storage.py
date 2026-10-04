import boto3
import pytest
from moto import mock_aws

from checks.logging_storage import (check_cloudtrail_log_validation, check_cloudtrail_multi_region,
                                    check_ebs_default_encryption, check_guardduty_enabled,
                                    check_s3_account_public_access_block, check_s3_default_encryption,
                                    check_securityhub_enabled)

REGION = 'us-east-1'


@pytest.fixture
def session(monkeypatch):
    for var in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def _make_trail(session, multi_region=True, validation=True, logging=True):
    session.client('s3').create_bucket(Bucket='trail-logs')
    ct = session.client('cloudtrail')
    ct.create_trail(Name='main', S3BucketName='trail-logs',
                    IsMultiRegionTrail=multi_region, EnableLogFileValidation=validation)
    if logging:
        ct.start_logging(Name='main')


# LOG-01
def test_cloudtrail_multi_region_fails_with_no_trails(session):
    assert check_cloudtrail_multi_region(session)['status'] == 'FAIL'


def test_cloudtrail_multi_region_passes_when_logging(session):
    _make_trail(session)
    assert check_cloudtrail_multi_region(session)['status'] == 'PASS'


def test_cloudtrail_multi_region_fails_when_single_region(session):
    _make_trail(session, multi_region=False)
    assert check_cloudtrail_multi_region(session)['status'] == 'FAIL'


# LOG-02
def test_cloudtrail_log_validation_passes_when_enabled(session):
    _make_trail(session)
    assert check_cloudtrail_log_validation(session)['status'] == 'PASS'


def test_cloudtrail_log_validation_fails_when_disabled(session):
    _make_trail(session, validation=False)
    result = check_cloudtrail_log_validation(session)
    assert result['status'] == 'FAIL'
    assert 'main' in result['findings'][0]


# DATA-01
def test_s3_public_access_block_fails_when_missing(session):
    assert check_s3_account_public_access_block(session)['status'] == 'FAIL'


def test_s3_public_access_block_passes_when_all_on(session):
    account_id = session.client('sts').get_caller_identity()['Account']
    session.client('s3control').put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                                        'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    assert check_s3_account_public_access_block(session)['status'] == 'PASS'


# DATA-02
def test_s3_default_encryption_passes_when_configured(session):
    s3 = session.client('s3')
    s3.create_bucket(Bucket='encrypted')
    s3.put_bucket_encryption(Bucket='encrypted', ServerSideEncryptionConfiguration={
        'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
    assert check_s3_default_encryption(session)['status'] == 'PASS'


def test_s3_default_encryption_fails_when_removed(session):
    s3 = session.client('s3')
    s3.create_bucket(Bucket='plain')
    s3.delete_bucket_encryption(Bucket='plain')
    result = check_s3_default_encryption(session)
    assert result['status'] == 'FAIL'
    assert 'plain' in result['findings'][0]


# DATA-03
def test_ebs_default_encryption_fails_when_off(session):
    assert check_ebs_default_encryption(session, regions=[REGION])['status'] == 'FAIL'


def test_ebs_default_encryption_passes_when_on(session):
    session.client('ec2').enable_ebs_encryption_by_default()
    assert check_ebs_default_encryption(session, regions=[REGION])['status'] == 'PASS'


# DET-01
def test_guardduty_fails_with_no_detector(session):
    assert check_guardduty_enabled(session, regions=[REGION])['status'] == 'FAIL'


def test_guardduty_passes_with_enabled_detector(session):
    session.client('guardduty').create_detector(Enable=True)
    assert check_guardduty_enabled(session, regions=[REGION])['status'] == 'PASS'


# DET-02
def test_securityhub_fails_when_not_enabled(session):
    assert check_securityhub_enabled(session, regions=[REGION])['status'] == 'FAIL'


def test_securityhub_passes_when_enabled(session):
    session.client('securityhub').enable_security_hub()
    assert check_securityhub_enabled(session, regions=[REGION])['status'] == 'PASS'
