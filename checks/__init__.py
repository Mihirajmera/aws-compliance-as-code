"""Compliance checks. Every check takes a boto3 Session and returns a result dict:

    {'control_id': str, 'status': 'PASS' | 'FAIL', 'api_call': str, 'raw': ...}

`raw` is the unmodified API response the decision was based on, so an auditor
can re-perform the test from the evidence alone.
"""
