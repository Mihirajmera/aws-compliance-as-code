from botocore.exceptions import ClientError


def _result(control_id, passed, api_call, raw, findings=None):
    return {
        'control_id': control_id,
        'status': 'PASS' if passed else 'FAIL',
        'api_call': api_call,
        'findings': findings or [],
        'raw': raw,
    }


def _error_code(e):
    return e.response.get('Error', {}).get('Code', '')


def enabled_regions(session):
    """Regions this account can use (opted-in or opt-in not required)."""
    regions = session.client('ec2').describe_regions(AllRegions=False)['Regions']
    return sorted(r['RegionName'] for r in regions)


def _trails_with_status(session):
    ct = session.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=False)['trailList']
    for trail in trails:
        status = ct.get_trail_status(Name=trail['TrailARN'])
        trail['IsLogging'] = status.get('IsLogging', False)
    return trails


def check_cloudtrail_multi_region(session):
    trails = _trails_with_status(session)
    passed = any(t.get('IsMultiRegionTrail') and t['IsLogging'] for t in trails)
    findings = [] if passed else ['No multi-region trail is currently logging']
    return _result('LOG-01', passed, 'cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus', trails, findings)


def check_cloudtrail_log_validation(session):
    trails = session.client('cloudtrail').describe_trails(includeShadowTrails=False)['trailList']
    findings = [f"{t['Name']}: log file validation is off" for t in trails if not t.get('LogFileValidationEnabled')]
    if not trails:
        findings.append('No CloudTrail trails exist')
    return _result('LOG-02', not findings, 'cloudtrail:DescribeTrails', trails, findings)


def check_s3_account_public_access_block(session):
    account_id = session.client('sts').get_caller_identity()['Account']
    try:
        config = session.client('s3control').get_public_access_block(AccountId=account_id)['PublicAccessBlockConfiguration']
    except ClientError as e:
        if _error_code(e) != 'NoSuchPublicAccessBlockConfiguration':
            raise
        return _result('DATA-01', False, 's3control:GetPublicAccessBlock', {},
                       ['No account-level S3 Block Public Access configuration'])
    findings = [f'{name} is false' for name, value in config.items() if not value]
    return _result('DATA-01', not findings, 's3control:GetPublicAccessBlock', config, findings)


def check_s3_default_encryption(session):
    s3 = session.client('s3')
    raw, findings = {}, []
    for bucket in s3.list_buckets()['Buckets']:
        name = bucket['Name']
        try:
            raw[name] = s3.get_bucket_encryption(Bucket=name)['ServerSideEncryptionConfiguration']
        except ClientError as e:
            if _error_code(e) != 'ServerSideEncryptionConfigurationNotFoundError':
                raise
            raw[name] = None
            findings.append(f'{name}: no default encryption')
    return _result('DATA-02', not findings, 's3:ListBuckets, s3:GetBucketEncryption', raw, findings)


def check_ebs_default_encryption(session, regions=None):
    raw, findings = {}, []
    for region in regions or enabled_regions(session):
        enabled = session.client('ec2', region_name=region).get_ebs_encryption_by_default()['EbsEncryptionByDefault']
        raw[region] = enabled
        if not enabled:
            findings.append(f'{region}: EBS encryption by default is off')
    return _result('DATA-03', not findings, 'ec2:GetEbsEncryptionByDefault', raw, findings)


def check_guardduty_enabled(session, regions=None):
    raw, findings = {}, []
    for region in regions or enabled_regions(session):
        gd = session.client('guardduty', region_name=region)
        detectors = {d: gd.get_detector(DetectorId=d).get('Status') for d in gd.list_detectors()['DetectorIds']}
        raw[region] = detectors
        if 'ENABLED' not in detectors.values():
            findings.append(f'{region}: no enabled GuardDuty detector')
    return _result('DET-01', not findings, 'guardduty:ListDetectors, guardduty:GetDetector', raw, findings)


def check_securityhub_enabled(session, regions=None):
    raw, findings = {}, []
    for region in regions or enabled_regions(session):
        try:
            hub = session.client('securityhub', region_name=region).describe_hub()
            raw[region] = {k: v for k, v in hub.items() if k != 'ResponseMetadata'}
        except ClientError as e:
            if _error_code(e) not in ('InvalidAccessException', 'ResourceNotFoundException'):
                raise
            raw[region] = None
            findings.append(f'{region}: Security Hub is not enabled')
    return _result('DET-02', not findings, 'securityhub:DescribeHub', raw, findings)
