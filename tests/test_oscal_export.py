import json

from oscal_export import build_assessment_results, nist_to_oscal_id

CONTROLS = [
    {'id': 'IAM-01', 'title': 'Root account has MFA enabled', 'mappings': {'nist_800_53': ['IA-2(1)']}},
    {'id': 'LOG-01', 'title': 'CloudTrail is enabled in all regions', 'mappings': {'nist_800_53': ['AU-2', 'AU-12']}},
]


def _write_evidence(folder, control_id, status):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f'{control_id}.json').write_text(json.dumps({
        'timestamp': '2026-10-04T03:30:00+00:00', 'account_id': '123456789012', 'control_id': control_id,
        'api_call': 'x:Y', 'status': status, 'raw': {}, 'sha256': 'abc'}))


def test_nist_ids_use_oscal_format():
    assert nist_to_oscal_id('IA-2(1)') == 'ia-2.1'
    assert nist_to_oscal_id('AU-12') == 'au-12'


def test_one_observation_per_evidence_file_with_findings_per_nist_control(tmp_path):
    day = tmp_path / 'evidence' / '2026-10-04'
    _write_evidence(day, 'IAM-01', 'FAIL')
    _write_evidence(day, 'LOG-01', 'PASS')

    doc = build_assessment_results(day, CONTROLS, root=tmp_path)['assessment-results']
    result = doc['results'][0]

    assert doc['uuid'] and doc['metadata']['title']
    assert [o['title'] for o in result['observations']] == ['IAM-01', 'LOG-01']
    assert result['observations'][0]['relevant-evidence'][0]['href'] == 'evidence/2026-10-04/IAM-01.json'
    states = {f['target']['target-id']: f['target']['status']['state'] for f in result['findings']}
    assert states == {'ia-2.1_obj': 'not-satisfied', 'au-2_obj': 'satisfied', 'au-12_obj': 'satisfied'}
