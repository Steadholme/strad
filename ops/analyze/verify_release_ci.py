#!/usr/bin/env python3
"""Require every current Strad CI contract for the exact release revision."""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE_CHECKS = ('Rust', 'Bridge, frontend, and Holdfast', 'Secret scan')


def required_checks(root=ROOT):
    names = []
    for target in ['postgres_contract', 'application_upload_contract']:
        source = (root / 'tests' / f'{target}.rs').read_text()
        tests = re.findall(r'#\[(?:tokio::)?test\]\s*(?:async )?fn (\w+)\(', source)
        if not tests:
            raise ValueError(f'no release contracts found in {target}')
        names.extend('PostgreSQL / ' + name for name in tests)
    expected = [*BASE_CHECKS, *names]
    if len(set(expected)) != len(expected):
        raise ValueError('release check names are ambiguous')
    return expected


def verify(document, revision, root=ROOT):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('release revision must be an exact commit SHA')
    pages = document if isinstance(document, list) else [document]
    runs = []
    if not pages:
        raise ValueError('no check-run pages received')
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get('check_runs'), list):
            raise ValueError('invalid GitHub check-run response')
        runs.extend(page['check_runs'])
    for name in required_checks(root):
        selected = [run for run in runs if isinstance(run, dict) and run.get('name') == name
                    and isinstance(run.get('app'), dict) and run['app'].get('slug') == 'github-actions']
        if len(selected) != 1:
            raise ValueError(f'required CI check is missing or ambiguous: {name}')
        run = selected[0]
        if run.get('head_sha') != revision or run.get('status') != 'completed' or run.get('conclusion') != 'success':
            raise ValueError(f'required CI check is not successful for this revision: {name}')
    return len(required_checks(root))


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify_release_ci.py COMMIT_SHA < paginated-check-runs.json')
    raw = sys.stdin.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise SystemExit('check-run response exceeds its bound')
    try:
        count = verify(json.loads(raw), sys.argv[1])
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error)) from None
    print(f'Exact-revision release CI verified: {count} required checks')


if __name__ == '__main__':
    main()
