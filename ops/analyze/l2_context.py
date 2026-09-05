#!/usr/bin/env python3
"""Replay and scope attenuation at the real Facade receiver boundary.

Uses a real approved credential and real Access initialization. The dedicated
L2 issuer key signs an explicitly attenuated context; no authority rows or
grants are injected, and the ordinary Sluice session is restored afterwards.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
from urllib.parse import urlencode
import uuid

import l2_security as security


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def signed_request(run, identity, session, request, *, attenuate=True):
    body = json.dumps(request, separators=(',', ':')).encode()
    now = int(time.time())
    context = {'v': 1, 'kid': 'application-l2', 'iss': 'sluice', 'aud': 'analyze-facade',
        'application_sub': identity['application_sub'], 'client_id': identity['client_id'],
        'credential_id': identity['credential_id'], 'credential_version': identity['credential_version'],
        'grant_id': identity['grant_id'], 'package_id': identity['package_id'],
        'package_revision_digest': identity['package_revision_digest'],
        'scopes': sorted(scope for scope in identity['scope'].split() if not attenuate or scope != 'analysis.read'),
        'method': 'POST', 'normalized_path': '/mcp', 'route': 'analyze-mcp',
        'body_sha256': hashlib.sha256(body).hexdigest(), 'request_id': uuid.uuid4().hex,
        'correlation_id': uuid.uuid4().hex, 'jti': encoded(secrets.token_bytes(16)),
        'mcp_session_digest': hashlib.sha256(session.encode()).hexdigest(),
        'credential_state': identity['credential_state'], 'overlap_until': identity['overlap_until'],
        'policy_epoch': identity['policy_epoch'], 'revocation_epoch': identity['revocation_epoch'],
        'iat': now, 'exp': now + 30}
    if len(context['scopes']) != (3 if attenuate else 4) or not set(context['scopes']).issubset(identity['scope'].split()):
        raise RuntimeError('test context must strictly attenuate the real credential')
    canonical = json.dumps(context, separators=(',', ':')).encode()
    seed = json.loads(run.env['L2_APPLICATION_SIGNING_KEYRING'])['application-l2']
    signature = run.command(['node', '-e', """
const fs=require('node:fs'),c=require('node:crypto'),p=JSON.parse(fs.readFileSync(0,'utf8'));
const key=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(p.seed,'base64url')]),format:'der',type:'pkcs8'});
process.stdout.write(c.sign(null,Buffer.from(p.body,'base64url'),key).toString('base64url'));
"""], stdin=json.dumps({'seed': seed, 'body': encoded(canonical)}))
    return body, {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
        'Mcp-Session-Id': session, 'MCP-Protocol-Version': '2025-11-25',
        'x-application-ctx-kid': 'application-l2', 'x-application-ctx': encoded(canonical),
        'x-application-ctx-sig': signature}


def run_context_checks(run):
    session = 'closed_scope_' + secrets.token_urlsafe(24)
    subject = run.application_request['application_sub']
    checks = security.SecurityChecks(run)
    counts = lambda: int(run.sql(f"SELECT COALESCE(sum(dispatch_count),0) FROM application_operations WHERE application_sub='{subject}';", 'strad_l2'))
    before = counts()
    try:
        status, _, raw = run.request('access', 9390, '/internal/v1/application-credentials/introspect',
            method='POST', body=urlencode({'token': run.credential['token'],
                'mcp_session_digest': hashlib.sha256(session.encode()).hexdigest(), 'initialize': 'true'}).encode(),
            headers={'Authorization': 'Bearer ' + run.env['L2_ACCESS_INTROSPECTION_TOKEN'],
                     'Content-Type': 'application/x-www-form-urlencoded'})
        identity = json.loads(raw)
        if status != 200 or identity.get('active') is not True or identity['application_sub'] != subject:
            raise RuntimeError('real Access did not authenticate the test credential')
        body, headers = signed_request(run, identity, session, {'jsonrpc': '2.0', 'id': 1,
            'method': 'initialize', 'params': security.INITIALIZE})
        first, _, raw = run.request('facade', 18120, '/mcp', host='analyze.w33d.xyz', method='POST', body=body, headers=headers)
        if first != 200 or json.loads(raw).get('result', {}).get('protocolVersion') != '2025-11-25':
            raise RuntimeError('attenuated test session was not accepted by the real receiver')
        status, _, raw = run.request('facade', 18120, '/mcp', host='analyze.w33d.xyz', method='POST', body=body, headers=headers)
        replay = json.loads(raw)
        if status != 409 or replay.get('error', {}).get('code') != 'replay_detected' or counts() != before:
            raise RuntimeError('exact signed-context replay was not rejected without dispatch')
        checks.cases['reused_jti'] = {'status': 'pass', 'http_status': 409, 'dispatch_count': 0,
            'layer': 'consumer_boundary', 'exact_signed_context_replayed': True}
        operation = str(uuid.uuid4())
        body, headers = signed_request(run, identity, session, {'jsonrpc': '2.0', 'id': 2,
            'method': 'tools/call', 'params': {'name': 'analysis.read', 'arguments': {
                'operation_id': operation, 'analysis_id': run.analysis_created['analysis_id']}}})
        decisions_before = int(run.sql(f"SELECT count(*) FROM policy_application_decisions_v2 WHERE application_sub='{subject}';", 'verdict_l2'))
        status, _, raw = run.request('facade', 18120, '/mcp', host='analyze.w33d.xyz', method='POST', body=body, headers=headers)
        response = (status, {}, json.loads(raw), hashlib.sha256(raw).hexdigest())
        checks.expect_denied('wrong_scope', operation, response, rpc=-32003)
        audit = json.loads(run.sql(f"SELECT json_agg(json_build_object('outcome',outcome,'has_digest',decision_digest IS NOT NULL)) FROM application_audit_events WHERE application_sub='{subject}' AND operation_id='{operation}' AND event_kind='authorization';", 'strad_l2'))
        if audit != [{'outcome': 'insufficient_scope', 'has_digest': False}]:
            raise RuntimeError('scope denial audit differs from the required single digest-free event')
        decisions_after = int(run.sql(f"SELECT count(*) FROM policy_application_decisions_v2 WHERE application_sub='{subject}';", 'verdict_l2'))
        if decisions_after != decisions_before:
            raise RuntimeError('insufficient scope reached Verdict')
        checks.cases['wrong_scope'].update({'layer': 'consumer_boundary_scope_attenuation',
            'real_access_introspection': True, 'issuer': 'controlled_L2_signer',
            'authority_rows_injected': False, 'authorization_audit': audit, 'verdict_calls': 0})
        print('L2 context: replay rejected and scope attenuation denied before Verdict/dispatch', flush=True)
        return checks.cases
    finally:
        run.mcp_session = None
        run.mcp('initialize', security.INITIALIZE)
        run.diagnostic_checkpoint('post-context-test-client-' + uuid.uuid4().hex)
        run.tool('analysis.read', {'operation_id': str(uuid.uuid4()),
                                  'analysis_id': run.analysis_created['analysis_id']})
        print('L2 context: ordinary Sluice-authenticated session restored', flush=True)


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
    result = run_context_checks(run)
    security.runtime.write_private_json(output, {'scope': 'live_consumer_context_acceptance',
        'release_eligible': False, 'project': run.project, 'cases': result})


if __name__ == '__main__':
    main()
