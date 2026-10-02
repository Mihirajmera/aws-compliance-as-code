"""Run every control in controls.yaml against an AWS account and print the results.

    python run.py --profile pm
"""
import argparse
import datetime
import importlib
import json
import pathlib
import pkgutil

import boto3
import yaml

import checks

ROOT = pathlib.Path(__file__).parent


def load_check_functions():
    """Map check function name -> function, across every module in checks/."""
    functions = {}
    for module_info in pkgutil.iter_modules(checks.__path__):
        module = importlib.import_module(f'checks.{module_info.name}')
        for name in dir(module):
            if name.startswith('check_') and callable(getattr(module, name)):
                functions[name] = getattr(module, name)
    return functions


def run(session, controls):
    functions = load_check_functions()
    results = []
    for control in controls:
        fn = functions.get(control['check'])
        if fn is None:
            results.append({'control_id': control['id'], 'status': 'NOT_IMPLEMENTED', 'findings': []})
            continue
        try:
            results.append(fn(session))
        except Exception as e:  # one broken check must not stop the run
            results.append({'control_id': control['id'], 'status': 'ERROR', 'findings': [f'{type(e).__name__}: {e}']})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--controls', default=str(ROOT / 'controls.yaml'))
    parser.add_argument('--evidence-dir', default=str(ROOT / 'evidence'))
    args = parser.parse_args()

    controls = yaml.safe_load(open(args.controls))['controls']
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    results = run(session, controls)

    titles = {c['id']: c['title'] for c in controls}
    print(f"{'CONTROL':<9} {'STATUS':<16} TITLE")
    for r in results:
        print(f"{r['control_id']:<9} {r['status']:<16} {titles.get(r['control_id'], '')}")
        for finding in r.get('findings', []):
            print(f"{'':<9} - {finding}")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = pathlib.Path(args.evidence_dir) / f'{timestamp}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({'collected_at': timestamp, 'results': results}, indent=2, default=str))
    print(f'\nEvidence written to {out}')


if __name__ == '__main__':
    main()
