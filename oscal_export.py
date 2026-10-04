"""Convert one day's evidence files into an OSCAL 1.1.2 assessment-results document.

    python oscal_export.py                    # latest evidence/<date>/ folder
    python oscal_export.py --date 2026-10-04

Each evidence file becomes one observation (the collected evidence) and one finding
(whether the mapped NIST 800-53 control objective is satisfied, based on that observation).
"""
import argparse
import datetime
import json
import pathlib
import re
import uuid

import yaml

ROOT = pathlib.Path(__file__).parent


def nist_to_oscal_id(control):
    """'IA-2(1)' -> 'ia-2.1', the control-id format used by the NIST 800-53 OSCAL catalog."""
    return re.sub(r'\((\d+)\)', r'.\1', control).lower()


def _uuid():
    return str(uuid.uuid4())


def build_assessment_results(evidence_dir, controls, root=ROOT):
    evidence_dir = pathlib.Path(evidence_dir)
    by_id = {c['id']: c for c in controls}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    observations, findings, reviewed = [], [], []
    for path in sorted(evidence_dir.glob('*.json')):
        ev = json.loads(path.read_text())
        control = by_id.get(ev['control_id'], {})
        nist = control.get('mappings', {}).get('nist_800_53', [])
        href = path.resolve().relative_to(pathlib.Path(root).resolve()).as_posix()

        obs_uuid = _uuid()
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
                'uuid': _uuid(),
                'title': f"{ev['control_id']} -> {control_id}",
                'description': control.get('title', ev['control_id']),
                'target': {
                    'type': 'objective-id',
                    'target-id': f'{oscal_id}_obj',
                    'status': {'state': 'satisfied' if ev['status'] == 'PASS' else 'not-satisfied'},
                },
                'related-observations': [{'observation-uuid': obs_uuid}],
            })

    return {'assessment-results': {
        'uuid': _uuid(),
        'metadata': {
            'title': 'AWS sandbox control assessment',
            'last-modified': now,
            'version': '1.0',
            'oscal-version': '1.1.2',
        },
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uuid(),
            'title': 'Nightly run',
            'description': f'Automated checks from {evidence_dir.as_posix()}',
            'start': min((o['collected'] for o in observations), default=now),
            'end': max((o['collected'] for o in observations), default=now),
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': c} for c in sorted(set(reviewed))]}]},
            'observations': observations,
            'findings': findings,
        }],
    }}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--date', help='evidence date folder (YYYY-MM-DD); defaults to the latest')
    parser.add_argument('--out', default=str(ROOT / 'oscal' / 'assessment-results.json'))
    args = parser.parse_args()

    evidence_root = ROOT / 'evidence'
    if args.date:
        evidence_dir = evidence_root / args.date
    else:
        dated = sorted(p for p in evidence_root.glob('????-??-??') if p.is_dir())
        if not dated:
            raise SystemExit('No evidence found; run run.py first.')
        evidence_dir = dated[-1]

    controls = yaml.safe_load(open(ROOT / 'controls.yaml'))['controls']
    doc = build_assessment_results(evidence_dir, controls)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2))
    result = doc['assessment-results']['results'][0]
    print(f"Wrote {out} with {len(result['observations'])} observations and {len(result['findings'])} findings")


if __name__ == '__main__':
    main()
