#!/usr/bin/env python3
"""Real upload response followed by an operation-result commit failure."""
import argparse
import json
from pathlib import Path
import time
import uuid

import l2_security as security


def run_commit_fault(run):
    run.ready()
    run.mcp_session = None
    run.mcp('initialize', security.INITIALIZE)
    run.diagnostic_checkpoint('commit-fault-client-' + uuid.uuid4().hex)
    sample = (run.work / 'sample.elf').read_bytes()
    create_operation = str(uuid.uuid4())
    created = run.tool('analysis.create', {'operation_id': create_operation,
        'filename': 'commit-fault.elf', 'total_bytes': len(sample)})
    prefix = security.runtime.upload_contract(created, sample)
    subject = run.application_request['application_sub']
    operation = created['finalize_operation_id']
    name = 'l2_commit_' + uuid.uuid4().hex[:16]
    status, _, _ = run.application_http(prefix + '/chunks/0', body=sample, headers={
        'Content-Type': 'application/octet-stream',
        'Content-Range': f'bytes 0-{len(sample)-1}/{len(sample)}',
        'X-Chunk-Sha256': security.hashlib.sha256(sample).hexdigest()})
    if status != 204: raise RuntimeError('real test upload chunk was not accepted')

    def state():
        return json.loads(run.sql(f"SELECT json_build_object('state',o.state,'reservation_active',o.reservation_active,'dispatch_count',o.dispatch_count,'error_code',o.error_code,'binding_state',b.reservation_state,'upload_state',u.state,'analysis_id',a.id,'analysis_state',a.state,'bridge_operation_id',u.operation_id) FROM application_operations o JOIN application_upload_bindings b ON b.application_sub=o.application_sub AND b.finalize_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id JOIN analyses a ON a.upload_id=u.id WHERE o.application_sub='{subject}' AND o.operation_id='{operation}';", 'strad_l2'))

    def finalize():
        return run.application_http(prefix + '/finalize', body=b'',
            headers={'Idempotency-Key': operation}, timeout=35)

    run.sql(f"CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'closed result commit failure'; END $$; CREATE TRIGGER {name} BEFORE UPDATE ON application_operations FOR EACH ROW WHEN (NEW.application_sub='{subject}' AND NEW.operation_id='{operation}'::uuid AND OLD.state='leased' AND NEW.state='completed') EXECUTE FUNCTION {name}();", 'strad_l2')
    try:
        status, _, _ = finalize()
        if status != 503: raise RuntimeError(f'commit failure did not surface as unavailable: HTTP {status}')
        uncertain = state()
        if (uncertain['state'] != 'downstream_uncertain' or uncertain['reservation_active'] is not True
                or uncertain['dispatch_count'] != 1 or uncertain['error_code'] != 'response_before_commit_crash'
                or uncertain['upload_state'] != 'finalized' or uncertain['binding_state'] != 'committed'):
            raise RuntimeError('post-response uncertainty was not retained: ' + json.dumps(uncertain))
        retry_status, _, retry_body = finalize()
        if retry_status != 503 or json.loads(retry_body).get('error', {}).get('code') != 'dependency_unavailable':
            raise RuntimeError(f'uncertain replay returned an unexpected public response: HTTP {retry_status}')
        if state()['dispatch_count'] != 1:
            raise RuntimeError('an uncertain operation was blindly resent')
        bridge_id = uncertain['bridge_operation_id']
        status, _, raw = run.request('analyzer', 18090, '/internal/v1/operations/' + bridge_id,
            headers={'Authorization': 'Bearer ' + run.env['L2_BRIDGE_TOKEN']})
        bridge = json.loads(raw).get('data', {})
        if status != 200 or bridge.get('state') != 'succeeded':
            raise RuntimeError('real downstream completion is not proven')
    finally:
        run.sql(f'DROP TRIGGER IF EXISTS {name} ON application_operations; DROP FUNCTION IF EXISTS {name}();', 'strad_l2')

    observed = state()
    frozen = {'analysis_id': observed['analysis_id'], 'state': observed['analysis_state']}
    reconciliation = {'application_sub': subject, 'reconciliation_id': str(uuid.uuid4()),
        'completed': True, 'response_status': 202, 'response_body': frozen}
    for _ in range(2):
        status, _, _ = run.request('strad', 9360,
            '/internal/v1/facade/operations/analysis.create/' + operation + '/reconcile', method='POST',
            headers={'Authorization': 'Bearer ' + run.env['L2_STRAD_FACADE_TOKEN'], 'Content-Type': 'application/json'},
            body=json.dumps(reconciliation).encode())
        if status != 204: raise RuntimeError('audited reconciliation was not accepted')
    status, _, raw = finalize()
    if status != 202 or json.loads(raw) != frozen:
        raise RuntimeError('reconciled result did not replay the observed frozen response')
    terminal = state()
    audits = int(run.sql(f"SELECT count(*) FROM application_audit_events WHERE application_sub='{subject}' AND operation_id='{operation}' AND event_kind='reconciliation';", 'strad_l2'))
    if terminal['state'] != 'completed' or terminal['reservation_active'] is not False or terminal['dispatch_count'] != 1 or audits != 1:
        raise RuntimeError('reconciliation did not preserve exactly-once dispatch/audit semantics')
    return {'name': 'response_before_crash', 'fault_mechanism': 'targeted_result_transaction_failure',
        'state': 'downstream_uncertain', 'reservation_retained': True, 'automatic_resend_count': 0,
        'audited_reconciliation': True, 'operation_id': operation, 'bridge_operation_id': bridge_id,
        'before_reconciliation': uncertain, 'after_reconciliation': terminal, 'reconciliation_audits': audits}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != security.runtime.INFRA / '.runtime':
        parser.error('choose a new output inside the private runtime directory')
    run = security.restore(Path(args.work), args.checkpoint)
    result = run_commit_fault(run)
    security.runtime.write_private_json(output, {'scope': 'live_result_commit_fault_acceptance',
        'release_eligible': False, 'project': run.project, 'fault': result})
    print('L2 fault: real downstream completion retained, no resend, audited reconciliation verified', flush=True)


if __name__ == '__main__':
    main()
