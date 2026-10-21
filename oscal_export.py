"""Backwards-compatible entry point: OSCAL for the latest evidence/<date>/ folder."""
import pathlib
import sys

from aws_compliance_as_code.__main__ import main

if __name__ == '__main__':
    dated = sorted(p for p in pathlib.Path('evidence').glob('????-??-??') if p.is_dir())
    if not dated:
        sys.exit('No evidence found; run run.py first.')
    sys.exit(main(['oscal', str(dated[-1]), *sys.argv[1:]]))
