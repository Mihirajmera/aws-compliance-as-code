"""Backwards-compatible entry point: `python run.py --profile pm` = `aws-compliance-as-code scan`."""
import sys

from aws_compliance_as_code.__main__ import main

if __name__ == '__main__':
    sys.exit(main(['scan', *sys.argv[1:]]))
