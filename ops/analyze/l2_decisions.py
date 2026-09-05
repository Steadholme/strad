#!/usr/bin/env python3
"""Closed consumer-boundary faults applied to real Verdict responses."""
import argparse
import json
import os
from pathlib import Path
import time
import uuid

import l2_security as security


def write_control(path, value):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('fault control must be an existing regular file')
    # Keep the inode: the container has this single file bind-mounted read-only.
    with path.open('r+') as handle:
        handle.seek(0)
        json.dump(value, handle)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())


def run_decisions(run):
    cases = [('stale_digest', 'decision_digest_mismatch', -32005),
             ('stale_version', 'stale_decision', -32005),
             ('stale_ttl', 'expired_decision', -32005),
             ('deny', 'deny', -32004), ('indeterminate', 'indeterminate', -32005),
             ('dependency_failure', 'authorization_unavailable', -32005)]
    control = run.work / 'decision-fault.json'
    checks = security.SecurityChecks(run)
    subject = run.application_request['application_sub']
    run.ready()
    run.mcp_session = None
    run.mcp('initialize', security.INITIALIZE)
    run.diagnostic_checkpoint('decision-test-client-' + uuid.uuid4().hex)
    try:
        for mode, expected_audit, rpc in cases:
            write_control(control, {'mode': 'pass'})
            run.tool('analysis.read', {'operation_id': str(uuid.uuid4()),
                                      'analysis_id': run.analysis_created['analysis_id']})
            case_id = uuid.uuid4().hex
            write_control(control, {'mode': mode, 'case_id': case_id, 'application_sub': subject,
                                    'expires_at': int(time.time()) + 60})
            operation, response = checks.read_probe()
            write_control(control, {'mode': 'pass'})
            checks.expect_denied(mode, operation, response, rpc=rpc)
            rows = json.loads(run.sql(f"SELECT COALESCE(json_agg(json_build_object('outcome',outcome,'has_decision_digest',decision_digest IS NOT NULL)),'[]'::json) FROM application_audit_events WHERE application_sub='{subject}' AND operation_id='{operation}' AND event_kind='authorization';", 'strad_l2'))
            expected = [{'outcome': expected_audit, 'has_decision_digest': mode != 'dependency_failure'}]
            if rows != expected:
                raise RuntimeError(mode + ': authorization audit differs: ' + json.dumps(rows))
            logs = run.command(['docker', 'logs', '--tail', '100', run.container_ids['acceptance']])
            applied = [json.loads(line.removeprefix('L2_DECISION_FAULT ')) for line in logs.splitlines()
                       if line.startswith('L2_DECISION_FAULT ') and case_id in line]
            if len(applied) != 1 or applied[0]['mode'] != mode:
                raise RuntimeError(mode + ': exactly one response fault was not observed')
            checks.cases[mode].update({'layer': 'consumer_boundary_response_fault',
                'original_upstream_decision': 'Allow', 'injection': applied[0], 'authorization_audit': rows})
            print('L2 decision fault: ' + mode + ' audited once, zero dispatches', flush=True)
        run.tool('analysis.read', {'operation_id': str(uuid.uuid4()),
                                  'analysis_id': run.analysis_created['analysis_id']})
        return checks.cases
    finally:
        write_control(control, {'mode': 'pass'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != security.runtime.INFRA / '.runtime':
        parser.error('choose a new diagnostic output inside the private runtime directory')
    run = security.restore(Path(args.work), args.checkpoint)
    result = run_decisions(run)
    security.runtime.write_private_json(output, {'scope': 'live_consumer_boundary_fault_acceptance',
        'release_eligible': False, 'project': run.project, 'cases': result})


if __name__ == '__main__':
    main()
