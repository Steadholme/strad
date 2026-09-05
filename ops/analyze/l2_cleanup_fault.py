#!/usr/bin/env python3
"""A scoped quota-release transaction failure during real upload cancellation."""
import argparse
import json
from pathlib import Path
import uuid

import l2_security as security


def run_cleanup_fault(run):
    run.mcp_session = None
    run.mcp('initialize', security.INITIALIZE)
    run.diagnostic_checkpoint('cleanup-fault-client-' + uuid.uuid4().hex)
    created = run.tool('analysis.create', {'operation_id': str(uuid.uuid4()),
        'filename': 'cleanup-fault.bin', 'total_bytes': 9})
    upload = created['upload_id']
    subject = run.application_request['application_sub']
    operation = run.sql(f"SELECT cancel_operation_id FROM application_upload_bindings WHERE application_sub='{subject}' AND upload_id='{upload}';", 'strad_l2')
    uuid.UUID(operation)
    name = 'l2_cleanup_' + uuid.uuid4().hex[:16]
    query = f"SELECT json_build_object('state',o.state,'reservation_active',o.reservation_active,'dispatch_count',o.dispatch_count,'error_code',o.error_code,'binding_state',b.reservation_state,'upload_state',u.state,'reserved_bytes',q.reserved_bytes) FROM application_operations o JOIN application_upload_bindings b ON b.application_sub=o.application_sub AND b.cancel_operation_id=o.operation_id JOIN upload_sessions u ON u.id=b.upload_id JOIN owner_quotas q ON q.owner_sub=o.application_sub WHERE o.application_sub='{subject}' AND o.operation_id='{operation}';"

    def cancel():
        try:
            run.tool('analysis.upload.cancel', {'operation_id': operation, 'upload_id': upload})
        except security.runtime.McpFailure as error:
            return error.error.get('code')
        raise RuntimeError('injected cleanup failure unexpectedly returned success')

    try:
        run.sql(f"CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'closed quota cleanup failure'; END $$; CREATE TRIGGER {name} BEFORE UPDATE ON owner_quotas FOR EACH ROW WHEN (OLD.owner_sub='{subject}' AND NEW.reserved_bytes<OLD.reserved_bytes) EXECUTE FUNCTION {name}();", 'strad_l2')
        first_error = cancel()
        before = json.loads(run.sql(query, 'strad_l2'))
        if (before['state'] != 'downstream_uncertain' or before['reservation_active'] is not True
                or before['dispatch_count'] != 1 or before['binding_state'] != 'reserved'
                or before['reserved_bytes'] < 9):
            raise RuntimeError('cleanup uncertainty did not retain its reservation: ' + json.dumps(before))
        retry_error = cancel()
        if json.loads(run.sql(query, 'strad_l2'))['dispatch_count'] != 1:
            raise RuntimeError('cleanup failure was automatically dispatched again')
    finally:
        run.sql(f'DROP TRIGGER IF EXISTS {name} ON owner_quotas; DROP FUNCTION IF EXISTS {name}();', 'strad_l2')
    reconciliation = {'application_sub': subject, 'reconciliation_id': str(uuid.uuid4()),
        'completed': False, 'response_status': None, 'response_body': None}
    for _ in range(2):
        status, _, _ = run.request('strad', 9360,
            '/internal/v1/facade/operations/analysis.upload.cancel/' + operation + '/reconcile',
            method='POST', body=json.dumps(reconciliation).encode(),
            headers={'Authorization': 'Bearer ' + run.env['L2_STRAD_FACADE_TOKEN'], 'Content-Type': 'application/json'})
        if status != 204: raise RuntimeError('cleanup reconciliation failed')
    after = json.loads(run.sql(query, 'strad_l2'))
    audits = int(run.sql(f"SELECT count(*) FROM application_audit_events WHERE application_sub='{subject}' AND operation_id='{operation}' AND event_kind='reconciliation';", 'strad_l2'))
    if (after['state'] != 'failed' or after['reservation_active'] is not False or after['dispatch_count'] != 1
            or after['binding_state'] != 'released' or after['upload_state'] != 'cancelled' or audits != 1):
        raise RuntimeError('cleanup reconciliation did not converge: ' + json.dumps(after))
    return {'name': 'cleanup_crash', 'fault_mechanism': 'targeted_quota_release_transaction_failure',
        'state': 'downstream_uncertain', 'reservation_retained': True, 'automatic_resend_count': 0,
        'audited_reconciliation': True, 'operation_id': operation, 'before_reconciliation': before,
        'after_reconciliation': after, 'reconciliation_audits': audits,
        'first_json_rpc_error': first_error, 'retry_json_rpc_error': retry_error}


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
    result = run_cleanup_fault(run)
    security.runtime.write_private_json(output, {'scope': 'live_cleanup_fault_acceptance',
        'release_eligible': False, 'project': run.project, 'fault': result})
    print('L2 cleanup fault: reservation retained, zero resend, audited release verified', flush=True)


if __name__ == '__main__':
    main()
