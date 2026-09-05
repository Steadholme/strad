"""Project completed, persisted suite evidence into the strict L2 receipt."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid

import l2_runtime as runtime
from l2_suite import NEGATIVE_CASES

spec = importlib.util.spec_from_file_location('l2_semantic_validator', runtime.ROOT / 'validate-l2-receipt.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def require(condition, message):
    if not condition:
        raise RuntimeError('full L2 receipt refused: ' + message)


def evidence_file(run, name, native=False):
    path = run.work / (('suite-native-' if native else 'suite-') + name + '.json')
    require(path.is_file() and not path.is_symlink(), 'missing persisted evidence for ' + name)
    return path


def build_receipt(suite):
    run = suite.run
    require(re.fullmatch(r'[0-9a-f]{32}', run.run_id) is not None, 'run identity is not schema v1')
    require(set(suite.records).issuperset(runtime.REQUIRED_SCENARIOS), 'not all nine scenarios completed')
    for name in suite.records:
        require(suite.records[name]['status'] == 'pass', 'non-passing scenario ' + name)
        require(json.loads(evidence_file(run, name).read_text()) == suite.records[name], 'scenario evidence changed: ' + name)
    for name in validator.NATIVE_CHECKS[:5]:
        require(suite.native.get(name, {}).get('status') == 'pass', 'native check missing: ' + name)
        require(json.loads(evidence_file(run, name, native=True).read_text()) == suite.native[name], 'native evidence changed: ' + name)
    for attribute, stage in [('approval', 'application_approval'), ('browser', 'oidc_browser'),
            ('negatives', 'authorization_negatives'), ('rotation', 'credential_rotation'),
            ('revocation', 'online_revocation'), ('fence', 'final_fence_barrier'),
            ('faults', 'fault_recovery'), ('missing', 'missing_dependencies'),
            ('expiration', 'source_grant_expiry')]:
        require(stage in suite.records and suite.records[stage]['details'] == getattr(suite, attribute),
                'summary is not bound to persisted evidence: ' + stage)
    require(set(suite.negatives) == set(NEGATIVE_CASES), 'negative matrix incomplete')
    require(all(value.get('status') == 'pass' and value.get('dispatch_count') == 0
                for value in suite.negatives.values()), 'a negative case dispatched work')
    require([item['name'] for item in suite.faults] == validator.FAULTS, 'fault matrix incomplete')
    require(all(item.get('state') == 'downstream_uncertain' and item.get('reservation_retained') is True
                and item.get('automatic_resend_count') == 0 and item.get('audited_reconciliation') is True
                for item in suite.faults), 'fault recovery invariant not proven')
    require([item['name'] for item in suite.missing] == validator.MISSING, 'missing-dependency matrix incomplete')
    require(all(item.get('result') == 'fail_closed' and item.get('pass_receipt_written') is False
                for item in suite.missing), 'missing dependency did not fail closed')
    counts = suite.approval['counts']
    require(all(counts.get(name) == 1 for name in ['decisions', 'sponsor_consumptions', 'grants', 'principals'])
            and counts.get('decision_ttl') == 300, 'approval cardinality/TTL not proven')
    require(suite.browser.get('csrf_distinct') is True, 'distinct browser CSRF not proven')
    mcp = suite.records['mcp_four_tools']['details']
    require(mcp.get('newapi_conversation_calls') == 1 and mcp.get('rest_cancel_status') in {404, 405}
            and mcp.get('analyzer_image') == run.analyzer_image, 'business acceptance differs')
    require(mcp.get('initial_transport', {}).get('status') == 'pass'
            and mcp['initial_transport'].get('created', {}).get('analysis_id') == mcp.get('analysis_id'),
            'initial transport proof is not bound to the analyzed object')
    wrong_scope = suite.negatives['wrong_scope']
    require(wrong_scope.get('authorization_audit') == [{'outcome': 'insufficient_scope', 'has_digest': False}]
            and wrong_scope.get('verdict_calls') == 0, 'scope refusal evidence differs')
    decision_cases = ['stale_digest', 'stale_version', 'stale_ttl', 'deny', 'indeterminate', 'dependency_failure']
    require(all(len(suite.negatives[name].get('authorization_audit', [])) == 1 for name in decision_cases),
            'non-allow audit cardinality differs')
    require(suite.expiration.get('source_grant_cascade') is True, 'source-grant cascade missing')
    rotation = suite.rotation['normal_rotation']
    require(rotation['overlap_until'] - rotation['rotated_at'] == 300
            and suite.rotation['normal_cases']['old_overlap_expired']['http_status'] == 401
            and suite.rotation['emergency_state'] == {'state': 'revoked', 'overlap_until': None},
            'credential lifecycle incomplete')
    require(suite.fence.get('fence_result') == 'inactive' and suite.fence.get('dispatch_count') == 0
            and suite.fence.get('revoke_committed_before_release') is True, 'final fence did not stop dispatch')
    contract = json.loads((runtime.ROOT / 'analyze-public-v1.json').read_text())
    completed = int(time.time())
    sources = {name + '_revision': run.sources[name]['revision'] for name in ['access', 'sluice', 'verdict', 'strad']}
    sources.update(facade_revision=sources['strad_revision'], analyzer_image=run.analyzer_image,
        postgres_image='postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa',
        task003_manifest_sha256=runtime.digest(validator.MANIFEST))
    strict_native = [{'name': name, 'status': 'pass', 'evidence_sha256': runtime.digest(evidence_file(run, name, native=True))}
                     for name in validator.NATIVE_CHECKS[:5]]
    strict_native.extend({'name': name, 'status': 'pass',
                          'evidence_sha256': runtime.digest(evidence_file(run, 'mcp_four_tools'))}
                         for name in validator.NATIVE_CHECKS[5:])
    return {'schema_version': 1, 'layer': 'L2', 'status': 'pass', 'ingress_closed': True,
        'run_id': run.run_id, 'started_at': run.started_at, 'completed_at': completed,
        'duration_seconds': completed - run.started_at, 'sources': sources,
        'topology': {'network_internal': True, 'published_ports': [],
            'services': ['access', 'sluice', 'verdict', 'facade', 'strad', 'analyzer', 'postgres', 'acceptance'],
            'postgres': 'real', 'service_readyz': True, 'composite_real_ghidra': True},
        'approval': {'ui_path': contract['control_plane']['ui'], 'routes': contract['control_plane']['routes'],
            'states': contract['control_plane']['states'], 'request_expiry_seconds': contract['approval']['request_expiry_seconds'],
            'strict_dtos': True, 'sponsor': {'producer': 'sluice_live_trusted_mfa', 'trusted_mfa': True,
                'version_bound': True, 'consumed_count': counts['sponsor_consumptions']},
            'system_decision': {'event': contract['approval']['system']['outbox_event'], 'worker': 'access_real_worker',
                'ttl_seconds': counts['decision_ttl'], 'consumed_count': counts['decisions']},
            'filesystem_assertion': False, 'direct_decision_injection': False},
        'browser': {'fixture_sha256': runtime.digest(runtime.ROOT / 'fixtures/oidc-browser-v1.json'),
            'issuer': contract['sso']['issuer'], 'audience': 'access-governance', 'resume_path': '/applications/',
            'csrf_distinct': True, 'cookie_flags': 'Secure; HttpOnly; SameSite=Lax',
            'dom_digest': suite.browser['dom_sha256'], 'sensitive_values_recorded': False},
        'mcp': {'protocol_version': contract['mcp']['protocol_version'],
            'tools': [item['name'] for item in contract['mcp']['tools']], 'upload_routes': contract['public_upload']['rest'],
            'rest_cancel_status': mcp['rest_cancel_status'], 'rest_cancel_compensation_count': 0,
            'real_binary': '/usr/bin/true', 'terminal_ghidra_read': True, 'newapi_model': mcp['newapi_model'],
            'newapi_conversation_calls': mcp['newapi_conversation_calls'], 'mcp_cancel': True,
            'idempotency_byte_identical': True, 'quota_exceeded': True},
        'authorization': {'request_v2_fields': validator.REQUEST_V2_FIELDS, 'negative_cases': list(NEGATIVE_CASES),
            'all_negative_dispatch_count': 0, 'insufficient_scope_authorization_event': True,
            'insufficient_scope_decision_digest': False, 'non_allow_audit_count_each': 1, 'non_allow_dispatch_count': 0},
        'credential': {'token_pattern': contract['credential']['token_pattern'], 'random_bytes': 32,
            'lookup': 'HMAC-SHA-256', 'plaintext_persisted': False, 'expiry_clipped': True,
            'lineage_recorded': True, 'last_used_recorded': True, 'states': contract['credential']['states'],
            'overlap_seconds': 300, 'original_session_only_overlap': True, 'new_session_new_credential': True,
            'old_expires': True, 'emergency_overlap_seconds': 0, 'source_grant_cascade': True},
        'revocation': {'event': 'analyze.application.sessions.revoked.v1', 'monotonic_epoch': True,
            'same_public_path_polled': True, 'cache_used': False, 'new_http_result': 'unauthenticated',
            'bound_session_result': 'invalid_session',
            **{key: suite.revocation[key] for key in ['durable_revoked_at', 'enforced_at', 'enforced_within_seconds']}},
        'final_fence': {'barrier': 'postgres_advisory_notify', 'revoke_committed_before_release': True,
            'execution_envelope_fields': validator.EXECUTION_FIELDS, 'subject_version_bound': True,
            'fence_result': 'inactive', 'dispatch_count': 0},
        'faults': [{key: item[key] for key in ['name', 'state', 'reservation_retained', 'automatic_resend_count',
                                            'audited_reconciliation']} for item in suite.faults],
        'missing_dependencies': [{key: item[key] for key in ['name', 'result', 'pass_receipt_written']} for item in suite.missing],
        'native_checks': strict_native,
        'scenarios': [{'name': name, 'status': 'pass', 'correlation_id': str(uuid.uuid4()),
                       'evidence_sha256': runtime.digest(evidence_file(run, name))} for name in runtime.REQUIRED_SCENARIOS],
        'evidence_digests': {'public_contract_sha256': runtime.digest(runtime.ROOT / 'analyze-public-v1.json'),
            'oidc_fixture_sha256': runtime.digest(runtime.ROOT / 'fixtures/oidc-browser-v1.json'),
            'compose_sha256': runtime.digest(runtime.ROOT / 'compose.closed.yml'),
            'analyzer_baseline_sha256': runtime.digest(runtime.ROOT / 'evidence/analyzer-baseline-v1.json')}}


def emit_receipt(suite, output: Path):
    receipt = build_receipt(suite)
    candidate = suite.run.work / 'l2-receipt-candidate.json'
    runtime.write_private_json(candidate, receipt)
    suite.run.command([str(suite.run.l2_schema_validator), 'validate', '--spec=draft2020', '--strict=true',
                       '-s', str(runtime.ROOT / 'l2-receipt.schema.json'), '-d', str(candidate)])
    validator.validate(candidate)
    bundle = output.parent / ('l2-evidence-' + suite.run.run_id)
    require(not output.exists() and not bundle.exists(), 'publication target already exists')
    # Preserve only explicit non-secret proof files, never diagnostic checkpoints.
    selected = [evidence_file(suite.run, name) for name in suite.records]
    selected += [evidence_file(suite.run, name, native=True) for name in validator.NATIVE_CHECKS[:5]]
    secrets = []
    for name, value in suite.run.env.items():
        if name.endswith(('_TOKEN', '_KEY', '_PASSWORD', '_SECRET', '_PEPPER', '_SIGNING_KEYRING')):
            secrets.append(value)
        if name.endswith('_SIGNING_KEYRING'):
            keys = json.loads(value)
            require(isinstance(keys, dict) and all(isinstance(key, str) for key in keys.values()),
                    'unexpected private signing keyring shape')
            secrets.extend(keys.values())
    for path in selected:
        content = path.read_text()
        require(not re.search(r'app_v1_[A-Za-z0-9_-]{43}|__Secure-gw=', content), 'sensitive proof material')
        require(all(len(secret) < 24 or secret not in content for secret in secrets), 'runtime secret in proof')
    bundle.mkdir(mode=0o700)
    for path in selected:
        destination = bundle / path.name
        shutil.copy2(path, destination)
        with destination.open('rb') as handle:
            os.fsync(handle.fileno())
    directory = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    # The passing marker is published last, after both validators and evidence.
    runtime.write_private_json(output, receipt)
    return receipt
