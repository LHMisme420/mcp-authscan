#!/usr/bin/env python3
"""Submit SYNTHETIC demo findings to a dashboard.

This script does not scan anything. The vector list is fixed, and whether a
finding is emitted at all is decided by `random.random()`. Its only legitimate
use is filling a dashboard with obviously-fake data, so:

  * it refuses to run without an explicit --demo acknowledgement,
  * every finding it creates is labelled `[DEMO]` in the description and
    carries `demo: true`,
  * it refuses a non-loopback API URL unless --allow-remote is passed too,
  * it no longer performs any network call at import time.

Fabricated findings matter here because the dashboard computes its compliance
score from severity counts: a random CRITICAL lowers a customer's score exactly
as much as a measured one.
"""
import argparse
import sys
import urllib.parse

import requests

DEFAULT_API_URL = 'http://127.0.0.1:5000'
ORG_NAME = 'Dashboard-Viewer'
TIMEOUT = 10

VECTORS = [
    'sql_injection', 'hardcoded_secrets', 'xxe_injection', 'auth_bypass',
    'path_traversal', 'cors_bypass', 'info_disclosure', 'rate_limit_bypass',
]


def is_loopback(url):
    """True only for addresses that cannot leave the machine."""
    host = urllib.parse.urlsplit(url).hostname or ''
    return host in ('localhost', '::1') or host.startswith('127.')


def register_scanner(api_url, timeout=TIMEOUT):
    try:
        res = requests.post(f'{api_url}/auth/register',
                            json={'org_name': ORG_NAME}, timeout=timeout)
        data = res.json()
        return data.get('access_token')
    except (requests.RequestException, ValueError) as e:
        print(f'Register error: {e}')
        return None


def submit_finding(api_url, token, vector, severity, description, timeout=TIMEOUT):
    try:
        requests.post(f'{api_url}/api/findings',
                      headers={'Authorization': f'Bearer {token}'},
                      json={'vector_type': vector, 'severity': severity,
                            'description': f'[DEMO] {description}',
                            'remediation': 'Investigate and patch',
                            'demo': True},
                      timeout=timeout)
    except requests.RequestException as e:
        print(f'Submit error: {e}')


def main(argv=None, rng=None):
    parser = argparse.ArgumentParser(
        description='Submit synthetic demo findings. This does not scan.')
    parser.add_argument('--demo', action='store_true', required=True,
                        help='required acknowledgement that the findings are fake')
    parser.add_argument('--api-url', default=DEFAULT_API_URL)
    parser.add_argument('--allow-remote', action='store_true',
                        help='allow sending demo data to a non-loopback URL')
    args = parser.parse_args(argv)

    if not is_loopback(args.api_url) and not args.allow_remote:
        print(f'Refusing to send fabricated findings to {args.api_url}. '
              f'Pass --allow-remote if that is really what you want.')
        return 2

    import random
    rng = rng or random

    token = register_scanner(args.api_url)
    if not token:
        print('Failed to register scanner')
        return 1

    for vector in VECTORS:
        if rng.random() < 0.3:
            severity = rng.choice(['CRITICAL', 'HIGH', 'MEDIUM'])
            submit_finding(args.api_url, token, vector, severity,
                           f'{vector} vulnerability detected')
            print(f'  Submitted demo finding: {vector} ({severity})')

    print('Demo scan complete - no server was contacted')
    return 0


if __name__ == '__main__':
    sys.exit(main())
