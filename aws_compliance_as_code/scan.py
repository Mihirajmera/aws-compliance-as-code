"""Run every control in controls.yaml against an AWS account and write one hashed evidence
file per control.

    aws-compliance-as-code scan --profile pm --out evidence
"""
import datetime
import hashlib
import importlib
import json
import os
import pathlib
import pkgutil

import yaml

from . import checks

CONTROLS_FILE = pathlib.Path(__file__).parent / 'controls.yaml'


def load_controls(path=CONTROLS_FILE):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)['controls']


def now():
    """UTC now, or SOURCE_DATE_EPOCH when set, so committed sample output is reproducible."""
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch:
        return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc)


def load_check_functions():
    """Map check function name -> function, across every module in checks/."""
    functions = {}
    for module_info in pkgutil.iter_modules(checks.__path__):
        module = importlib.import_module(f'{checks.__name__}.{module_info.name}')
        for name in dir(module):
            if name.startswith('check_') and callable(getattr(module, name)):
                functions[name] = getattr(module, name)
    return functions


def evidence_record(result, account_id, timestamp):
    raw = result['raw']
    return {
        'timestamp': timestamp.isoformat(),
        'account_id': account_id,
        'control_id': result['control_id'],
        'api_call': result['api_call'],
        'status': result['status'],
        'findings': result.get('findings', []),
        'raw': raw,
        # SHA-256 of raw as canonical JSON (sorted keys, no whitespace) so edits are detectable.
        'sha256': hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest(),
    }


def write_evidence(results, account_id, folder):
    """Write <folder>/<CONTROL-ID>.json for every result that has raw evidence."""
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = now()
    written = []
    for result in results:
        if 'raw' not in result:
            continue
        path = folder / f"{result['control_id']}.json"
        body = json.dumps(evidence_record(result, account_id, stamp), indent=2, default=str, sort_keys=True)
        path.write_text(body + '\n', encoding='utf-8', newline='\n')
        written.append(path)
    return written


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


def print_table(results, controls):
    titles = {c['id']: c['title'] for c in controls}
    print(f"{'CONTROL':<9} {'STATUS':<16} TITLE")
    for r in results:
        print(f"{r['control_id']:<9} {r['status']:<16} {titles.get(r['control_id'], '')}")
        for finding in r.get('findings', []):
            print(f"{'':<9} - {finding}")
