#!/usr/bin/env python3
"""Real gateway -> Verdict Allow -> PostgreSQL wait -> revoke -> final fence."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid

import l2_security as security


def run_fence(run):
    checks = security.SecurityChecks(run)
    checks.fresh_browser()
    run.mcp_session = None
    run.mcp('initialize', security.INITIALIZE)
    run.diagnostic_checkpoint('final-fence-client-' + uuid.uuid4().hex)
    run.tool('analysis.read', {'operation_id': str(uuid.uuid4()),
                              'analysis_id': run.analysis_created['analysis_id']})
    subject = run.application_request['application_sub']
    principal = checks.principal()
    decisions_query = f"SELECT COALESCE(json_agg(decision_id),'[]'::json) FROM policy_application_decisions_v2 WHERE application_sub='{subject}';"
    previous = set(json.loads(run.sql(decisions_query, 'verdict_l2')))
    operation = str(uuid.uuid4())
    process = subprocess.Popen(['node', str(security.runtime.ROOT / 'pg-fence-barrier.mjs')],
        cwd=security.runtime.STRAD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, env={**os.environ,
        'L2_PG_HOST': run.address('postgres'), 'L2_PG_PASSWORD': run.env['L2_POSTGRES_PASSWORD'],
        'L2_BARRIER_CHANNEL': 'analyze_fence_' + uuid.uuid4().hex[:16]})
    events = queue.Queue()

    def receive():
        for line in process.stdout:
            try: events.put(json.loads(line))
            except ValueError: events.put({'event': 'invalid_barrier_output'})
        events.put({'event': 'eof'})

    threading.Thread(target=receive, daemon=True).start()

    def wait_event(expected):
        try: event = events.get(timeout=12)
        except queue.Empty: raise RuntimeError('PostgreSQL barrier observation timed out') from None
        if event.get('event') != expected:
            raise RuntimeError('Unexpected PostgreSQL barrier event: ' + str(event.get('event')))
        return event

    request_pool = ThreadPoolExecutor(max_workers=1)
    try:
        locked = wait_event('locked')
        request = request_pool.submit(checks.rpc_probe, 'tools/call', {'name': 'analysis.read', 'arguments': {
            'operation_id': operation, 'analysis_id': run.analysis_created['analysis_id']}})
        wait_event('blocked')
        added = set(json.loads(run.sql(decisions_query, 'verdict_l2'))) - previous
        if len(added) != 1:
            raise RuntimeError('Barrier did not observe exactly one new real Verdict decision')
        decision_id = added.pop()
        if not security.re.fullmatch(r'dec_[a-f0-9]+', decision_id):
            raise RuntimeError('Unexpected Verdict decision identity')
        decision = json.loads(run.sql(f"SELECT json_build_object('decision',decision,'digest',decision_digest,'subject_version',subject_version,'issued_at',issued_at,'expires_at',expires_at) FROM policy_application_decisions_v2 WHERE decision_id='{decision_id}';", 'verdict_l2'))
        if decision['decision'] != 'Allow':
            raise RuntimeError('Request was not allowed by real Verdict before the barrier')
        run.api('/api/v1/applications/' + run.application_request['id'] + '/credentials/' +
                run.credential['credential_id'] + '/revoke', method='POST', expected=204,
                value={'expected_version': principal['version']})
        revoked_at = time.time()
        if checks.principal()['revocation_epoch'] <= principal['revocation_epoch']:
            raise RuntimeError('Revocation was not durable before releasing the barrier')
        process.stdin.write('release\n'); process.stdin.flush()
        released_at = time.time()
        wait_event('released')
        print('L2 final fence: real Allow observed, revocation committed, barrier released', flush=True)
        transport = {}
        try:
            status, _, response, response_sha = request.result(timeout=35)
            transport = {'http_status': status, 'response_sha256': response_sha}
            if status == 200 and 'error' not in response:
                raise RuntimeError('Revoked in-flight request returned application data')
        except (OSError, security.runtime.http.client.HTTPException):
            transport = {'connection_closed': True}
        durable = json.loads(run.sql(f"SELECT json_build_object('state',state,'dispatch_count',dispatch_count,'reservation_active',reservation_active,'error_code',error_code) FROM application_operations WHERE application_sub='{subject}' AND operation_id='{operation}';", 'strad_l2'))
        if durable != {'state': 'failed', 'dispatch_count': 0, 'reservation_active': False, 'error_code': 'unauthenticated'}:
            raise RuntimeError('Final authority fence did not reject before dispatch: ' + json.dumps(durable))
        return {'status': 'pass', 'barrier': 'postgres_advisory_notify', 'operation_id': operation,
            'decision_id': decision_id, 'decision': decision, 'locker_pid': locked['pid'],
            'revoked_at': revoked_at, 'released_at': released_at, 'revoke_committed_before_release': revoked_at <= released_at,
            'fence_result': 'inactive', 'dispatch_count': 0, 'durable_operation': durable, 'transport': transport}
    finally:
        if process.poll() is None:
            try: process.stdin.write('release\n'); process.stdin.flush()
            except (BrokenPipeError, OSError): pass
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate(); process.wait(timeout=5)
        request_pool.shutdown(wait=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != security.runtime.INFRA / '.runtime':
        parser.error('choose a new output in the private runtime directory')
    os.umask(0o077)
    run = security.restore(Path(args.work), args.checkpoint)
    result = run_fence(run)
    security.runtime.write_private_json(output, {'scope': 'live_final_fence_acceptance',
        'release_eligible': False, 'project': run.project, 'strad_image': run.env['L2_STRAD_IMAGE'],
        'final_fence': result})
    print('L2 final fence verified: no unauthorized dispatch or data release', flush=True)


if __name__ == '__main__':
    main()
