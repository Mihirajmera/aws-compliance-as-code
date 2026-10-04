"""Run every control in controls.yaml against an AWS account, print the results,
and write one hashed evidence file per control to evidence/<YYYY-MM-DD>/.

    python run.py --profile pm
"""
import argparse
import datetime
import hashlib
import importlib
import json
import os
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


def write_evidence(result, account_id):
    raw = result['raw']
    body = {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'account_id': account_id,
        'control_id': result['control_id'],
        'api_call': result['api_call'],
        'status': result['status'],
        'findings': result.get('findings', []),
        'raw': raw,
        # SHA-256 of raw as canonical JSON (sorted keys, no whitespace) so edits are detectable.
        'sha256': hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest(),
    }
    d = f"evidence/{body['timestamp'][:10]}"
    os.makedirs(d, exist_ok=True)
    with open(f"{d}/{result['control_id']}.json", 'w') as f:
        json.dump(body, f, indent=2, default=str)
    return f"{d}/{result['control_id']}.json"


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
    args = parser.parse_args()

    controls = yaml.safe_load(open(args.controls))['controls']
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client('sts').get_caller_identity()['Account']
    results = run(session, controls)

    titles = {c['id']: c['title'] for c in controls}
    print(f"{'CONTROL':<9} {'STATUS':<16} TITLE")
    for r in results:
        print(f"{r['control_id']:<9} {r['status']:<16} {titles.get(r['control_id'], '')}")
        for finding in r.get('findings', []):
            print(f"{'':<9} - {finding}")

    os.chdir(ROOT)  # evidence/ always lands in the repo, wherever run.py is called from
    written = [write_evidence(r, account_id) for r in results if 'raw' in r]
    print(f"\nWrote {len(written)} evidence files to {os.path.dirname(written[0]) if written else 'evidence/'}")


if __name__ == '__main__':
    main()
