#!/usr/bin/env python3
"""Observe a real production-configured upload timeout, without a model call."""
import argparse
import json
from pathlib import Path
import signal
import time
import uuid

import l2_security as security


def timeout_state(run):
    subject = run.application_request['application_sub']
    operation = str(uuid.UUID(run.analysis_created['finalize_operation_id']))
    if not security.re.fullmatch(r'application:[A-Za-z0-9_-]{16,128}', subject):
        raise RuntimeError('invalid timeout application subject')
    query = f"SELECT json_build_object('state',o.state,'reservation_active',o.reservation_active,'dispatch_count',o.dispatch_count,'error_code',o.error_code,'upload_state',u.state,'binding_state',b.reservation_state,'analysis_id',a.id,'analysis_state',a.state,'bridge_operation_id',u.operation_id,'upload_lease_remaining_seconds',GREATEST(0,extract(epoch FROM u.lease_until-clock_timestamp()))) FROM application_operations o JOIN application_upload_bindings b ON b.application_sub=o.application_sub AND b.finalize_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id JOIN analyses a ON a.upload_id=u.id WHERE o.application_sub='{subject}' AND o.operation_id='{operation}';"
    return json.loads(run.sql(query, 'strad_l2'))


def run_timeout(run):
    checks = security.SecurityChecks(run)
    checks.fresh_browser()
    run.application_approval()
    run.mcp_transport()
    run.diagnostic_checkpoint('timeout-client-' + uuid.uuid4().hex)
    created = run.analysis_created
    subject = run.application_request['application_sub']
    operation = created['finalize_operation_id']
    upload = created['upload_id']
    sample = (run.work / 'sample.elf').read_bytes()
    prefix = security.runtime.upload_contract(created, sample)
    status, _, _ = run.application_http(prefix + '/chunks/0', body=sample, headers={
        'Content-Type': 'application/octet-stream', 'Content-Range': f'bytes 0-{len(sample)-1}/{len(sample)}',
        'X-Chunk-Sha256': security.hashlib.sha256(sample).hexdigest()})
    if status != 204: raise RuntimeError('timeout test chunk was not accepted')
    state = lambda: timeout_state(run)
    started = time.monotonic()
    first_status = None
    try:
        run.command(['docker', 'pause', run.container_ids['analyzer']])
        first_status, _, _ = run.application_http(prefix + '/finalize', body=b'',
            headers={'Idempotency-Key': operation}, timeout=35)
        if first_status != 503:
            raise RuntimeError(f'paused analyzer did not cause public timeout/unavailability: HTTP {first_status}')
        print('L2 timeout: public caller failed closed; observing the unchanged 900-second backend deadline', flush=True)
        deadline = started + 925
        next_report = time.monotonic()
        while time.monotonic() < deadline:
            current = state()
            if current['dispatch_count'] != 1 or current['reservation_active'] is not True:
                raise RuntimeError('timed-out dispatch lost its single reserved execution')
            if current['state'] == 'downstream_uncertain':
                break
            if current['state'] != 'leased':
                raise RuntimeError('unexpected pending timeout state: ' + json.dumps(current))
            if time.monotonic() >= next_report:
                print(f'L2 timeout: elapsed={int(time.monotonic()-started)}s, dispatch=1, reservation retained', flush=True)
                next_report = time.monotonic() + 45
            time.sleep(3)
        else:
            # A disconnected caller can cancel its service future. After the
            # unchanged hard deadline and real lease expiry, restart recovery
            # must preserve uncertainty instead of resending the operation.
            run.compose('restart', 'strad', timeout=60)
            time.sleep(2)
            current = state()
        if current['state'] != 'downstream_uncertain' or current['dispatch_count'] != 1:
            raise RuntimeError('timeout did not become durable uncertainty')
        uncertain = current
        run.diagnostic_checkpoint('timeout-uncertain-' + uuid.uuid4().hex,
            timeout_observation={'first_public_status': first_status, 'state': uncertain,
                                 'elapsed_seconds': time.monotonic() - started})
    finally:
        run.command(['docker', 'unpause', run.container_ids['analyzer']])
    run.ready()
    print('L2 timeout: analyzer resumed; resolving only from the durable backend operation', flush=True)
    return recover_timeout(run, uncertain, started=started, first_status=first_status)


def recover_timeout(run, uncertain, *, started=None, first_status=None):
    """Resume the original operation only; this function never sends an upload."""
    subject = run.application_request['application_sub']
    operation = run.analysis_created['finalize_operation_id']
    state = lambda: timeout_state(run)
    if (uncertain['state'] != 'downstream_uncertain' or uncertain['dispatch_count'] != 1
            or uncertain['reservation_active'] is not True):
        raise RuntimeError('timeout recovery requires an existing single uncertain dispatch')

    def backend():
        status, _, raw = run.request('analyzer', 18090, '/internal/v1/operations/' + uncertain['bridge_operation_id'],
            headers={'Authorization': 'Bearer ' + run.env['L2_BRIDGE_TOKEN']})
        return status, json.loads(raw)

    status, backend_result = backend()
    if status == 404:
        # Cancel every old socket before treating an absent journal row as
        # authoritative non-execution; then inspect the persistent journal again.
        run.compose('restart', 'analyzer', timeout=60)
        run.ready()
        status, backend_result = backend()
    deadline = time.monotonic() + 60
    while status == 200 and backend_result.get('data', {}).get('state') in {'pending', 'unknown'} and time.monotonic() < deadline:
        time.sleep(1)
        status, backend_result = backend()
    completed = status == 200 and backend_result.get('data', {}).get('state') == 'succeeded'
    definitely_failed = status == 404 or (status == 200 and backend_result.get('data', {}).get('state') == 'failed')
    if not completed and not definitely_failed:
        raise RuntimeError('backend timeout outcome remains unknown; reservation must remain retained')
    if completed:
        # The upload lease (30 minutes) intentionally outlives the HTTP deadline
        # (900 seconds). Wait for the real lease plus two worker ticks, without
        # shortening either deadline or stealing a still-live forwarding lease.
        remaining = float(state().get('upload_lease_remaining_seconds') or 0)
        if not 0 <= remaining <= 1800:
            raise RuntimeError('upload lease is outside the configured recovery bound')
        deadline = time.monotonic() + remaining + 60
        next_report = time.monotonic()
        while time.monotonic() < deadline:
            observed = state()
            if observed['dispatch_count'] != 1 or observed['reservation_active'] is not True:
                raise RuntimeError('recovery changed the reserved execution before audited reconciliation')
            if observed['upload_state'] == 'finalized':
                break
            if time.monotonic() >= next_report:
                print('L2 timeout: waiting for the original upload lease/reconciliation worker; dispatch=1', flush=True)
                next_report = time.monotonic() + 45
            time.sleep(1)
        settled = state()
        if settled['upload_state'] != 'finalized': raise RuntimeError('successful backend upload has not reconciled')
        frozen = {'analysis_id': settled['analysis_id'], 'state': settled['analysis_state']}
    else:
        frozen = None
    reconciliation = {'application_sub': subject, 'reconciliation_id': str(uuid.uuid4()),
        'completed': completed, 'response_status': 202 if completed else None, 'response_body': frozen}
    for _ in range(2):
        result, _, _ = run.request('strad', 9360, '/internal/v1/facade/operations/analysis.create/' + operation + '/reconcile',
            method='POST', body=json.dumps(reconciliation).encode(),
            headers={'Authorization': 'Bearer ' + run.env['L2_STRAD_FACADE_TOKEN'], 'Content-Type': 'application/json'})
        if result != 204: raise RuntimeError('audited timeout reconciliation failed')
    terminal = state()
    audits = int(run.sql(f"SELECT count(*) FROM application_audit_events WHERE application_sub='{subject}' AND operation_id='{operation}' AND event_kind='reconciliation';", 'strad_l2'))
    if terminal['reservation_active'] is not False or terminal['dispatch_count'] != 1 or audits != 1:
        raise RuntimeError('timeout reconciliation did not preserve exactly-once semantics')
    if completed:
        if terminal['upload_state'] != 'finalized' or terminal['binding_state'] != 'committed':
            raise RuntimeError('successful timeout recovery did not commit the upload binding')
    elif terminal['binding_state'] != 'released' or terminal['upload_state'] not in {'cancelled', 'expired'}:
        raise RuntimeError('failed timeout recovery still retains the upload reservation')
    return {'name': 'dispatch_timeout', 'fault_mechanism': 'paused_real_analyzer_with_original_timeouts',
        'state': 'downstream_uncertain', 'reservation_retained': True, 'automatic_resend_count': 0,
        'audited_reconciliation': True,
        'elapsed_seconds': time.monotonic()-started if started is not None else None,
        'first_public_status': first_status, 'resumed_original_operation': started is None,
        'operation_id': operation, 'before_reconciliation': uncertain, 'after_reconciliation': terminal,
        'backend_observation': {'http_status': status, 'state': backend_result.get('data', {}).get('state')},
        'reconciliation_audits': audits}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--resume', action='store_true',
        help='reconcile the checkpoint operation without creating or resending an upload')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != security.runtime.INFRA / '.runtime':
        parser.error('choose a new output inside the private runtime directory')
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt('timeout acceptance interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    run = security.restore(Path(args.work), args.checkpoint)
    result = recover_timeout(run, timeout_state(run)) if args.resume else run_timeout(run)
    security.runtime.write_private_json(output, {'scope': 'live_dispatch_timeout_acceptance',
        'release_eligible': False, 'project': run.project, 'fault': result})
    print('L2 real timeout and audited recovery verified', flush=True)


if __name__ == '__main__':
    main()
