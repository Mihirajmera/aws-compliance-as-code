"""Convert a folder of evidence files into an OSCAL 1.1.2 assessment-results document.

    aws-compliance-as-code oscal evidence/2026-10-04 --out oscal/assessment-results.json

Each evidence file becomes one observation (the collected evidence) and one finding
(whether the mapped NIST 800-53 control objective is satisfied, based on that observation).
"""
import json
import pathlib
import re
import uuid

from .scan import now

# Namespace for deterministic UUIDs: the same evidence always yields the same document.
NS = uuid.uuid5(uuid.NAMESPACE_URL, 'https://github.com/Mihirajmera/aws-compliance-as-code')


def nist_to_oscal_id(control):
    """'IA-2(1)' -> 'ia-2.1', the control-id format used by the NIST 800-53 OSCAL catalog."""
    return re.sub(r'\((\d+)\)', r'.\1', control).lower()


def _uuid(*parts):
    return str(uuid.uuid5(NS, '|'.join(str(p) for p in parts)))


def build_assessment_results(evidence_dir, controls, root=None):
    """`root` is the folder evidence links are made relative to (default: the evidence folder's parent)."""
    evidence_dir = pathlib.Path(evidence_dir)
    root = pathlib.Path(root) if root else evidence_dir.parent
    by_id = {c['id']: c for c in controls}
    stamp = now().isoformat()

    observations, findings, reviewed = [], [], []
    for path in sorted(evidence_dir.glob('*.json')):
        ev = json.loads(path.read_text(encoding='utf-8'))
        control = by_id.get(ev['control_id'], {})
        nist = control.get('mappings', {}).get('nist_800_53', [])
        href = path.resolve().relative_to(pathlib.Path(root).resolve()).as_posix()

        obs_uuid = _uuid('observation', ev['control_id'], ev['sha256'])
        observations.append({
            'uuid': obs_uuid,
            'title': ev['control_id'],
            'description': ev['status'],
            'methods': ['TEST'],
            'types': ['control-objective'],
            'props': [
                {'name': 'api-call', 'value': ev['api_call']},
                {'name': 'account-id', 'value': ev['account_id']},
            ],
            'relevant-evidence': [{'href': href, 'description': f"sha256 {ev['sha256']}"}],
            'collected': ev['timestamp'],
        })
        for control_id in nist:
            oscal_id = nist_to_oscal_id(control_id)
            reviewed.append(oscal_id)
            findings.append({
                'uuid': _uuid('finding', ev['control_id'], control_id, ev['sha256']),
                'title': f"{ev['control_id']} -> {control_id}",
                'description': control.get('title', ev['control_id']),
                'target': {
                    'type': 'objective-id',
                    'target-id': f'{oscal_id}_obj',
                    'status': {'state': 'satisfied' if ev['status'] == 'PASS' else 'not-satisfied'},
                },
                'related-observations': [{'observation-uuid': obs_uuid}],
            })

    digest = '|'.join(o['uuid'] for o in observations)
    return {'assessment-results': {
        'uuid': _uuid('assessment-results', digest),
        'metadata': {
            'title': 'AWS control assessment',
            'last-modified': stamp,
            'version': '1.0',
            'oscal-version': '1.1.2',
        },
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uuid('result', digest),
            'title': 'Automated control assessment',
            'description': f'Automated checks from {evidence_dir.as_posix()}',
            'start': min((o['collected'] for o in observations), default=stamp),
            'end': max((o['collected'] for o in observations), default=stamp),
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': c} for c in sorted(set(reviewed))]}]},
            'observations': observations,
            'findings': findings,
        }],
    }}
