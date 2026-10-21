"""aws-compliance-as-code: read-only AWS control checks with hashed evidence and OSCAL output.

examples:
  aws-compliance-as-code demo                          # fake misconfigured account, no AWS needed
  aws-compliance-as-code scan --profile pm             # your account -> evidence/<date>/
  aws-compliance-as-code oscal evidence/2026-10-04     # -> oscal/assessment-results.json
"""
import argparse
import json
import pathlib
import sys

from . import __version__, scan


def main(argv=None):
    p = argparse.ArgumentParser(prog='aws-compliance-as-code', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--version', action='version', version=__version__)
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('scan', help='run every control against an AWS account (read-only)')
    s.add_argument('--profile', help='AWS CLI profile name')
    s.add_argument('--region', default='us-east-1')
    s.add_argument('--out', help='evidence folder (default: evidence/<today>)')
    o = sub.add_parser('oscal', help='turn an evidence folder into OSCAL assessment-results')
    o.add_argument('evidence', help='folder of <CONTROL-ID>.json evidence files')
    o.add_argument('--out', default='oscal/assessment-results.json')
    d = sub.add_parser('demo', help='run every check against a fake misconfigured account (needs the [demo] extra)')
    d.add_argument('--out', default='aws-compliance-demo')
    args = p.parse_args(argv)

    if args.cmd == 'scan':
        import boto3
        controls = scan.load_controls()
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        account_id = session.client('sts').get_caller_identity()['Account']
        results = scan.run(session, controls)
        scan.print_table(results, controls)
        out = pathlib.Path(args.out or f'evidence/{scan.now():%Y-%m-%d}')
        written = scan.write_evidence(results, account_id, out)
        print(f'\nWrote {len(written)} evidence files to {out}')
        return 0

    if args.cmd == 'oscal':
        from .oscal import build_assessment_results
        out = pathlib.Path(args.out)
        doc = build_assessment_results(args.evidence, scan.load_controls(), root=out.parent.parent)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8', newline='\n')
        result = doc['assessment-results']['results'][0]
        print(f"Wrote {out} with {len(result['observations'])} observations and {len(result['findings'])} findings")
        return 0

    try:
        from .demo import run_demo
        results, controls = run_demo(args.out)
    except ImportError:
        print('The demo needs moto: pip install "aws-compliance-as-code[demo]"', file=sys.stderr)
        return 1
    scan.print_table(results, controls)
    print(f'\nEvidence, OSCAL and report.md written to {args.out}/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
