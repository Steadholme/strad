"""Complete composed acceptance. Only the final business stage calls a model."""
import copy
import hashlib
import json
import math
import time
from urllib.parse import urlencode
import uuid

import l2_context
import l2_decisions
import l2_fence
import l2_missing_dependencies
import l2_native
import l2_security as security
from l2_commit_fault import run_commit_fault
from l2_cleanup_fault import run_cleanup_fault
from l2_timeout import run_timeout

runtime = security.runtime
CLIENT_FIELDS = ('application_request', 'credential', 'mcp_session', 'analysis_created')
NEGATIVE_CASES = ('no_token', 'fake_credential', 'expired_credential', 'revoked_credential',
    'wrong_scope', 'stale_digest', 'stale_version', 'stale_ttl', 'deny', 'indeterminate',
    'dependency_failure', 'reused_jti', 'cross_application_read', 'cross_application_upload',
    'alias', 'introspection_outage')


def snapshot_client(run):
    return {name: copy.deepcopy(getattr(run, name)) for name in CLIENT_FIELDS}


def activate_client(run, client, *, initialize=False):
    for name in CLIENT_FIELDS:
        setattr(run, name, copy.deepcopy(client[name]))
    if initialize:
        run.mcp_session = None
        run.mcp('initialize', security.INITIALIZE)


class FullSuite:
    def __init__(self, run):
        self.run = run
        self.primary = snapshot_client(run)
        self.approval = copy.deepcopy(run.observations['application_approval_core'])
        self.browser = copy.deepcopy(run.observations['oidc_browser_core'])
        self.transport = copy.deepcopy(run.observations['mcp_transport'])
        self.native = {}
        self.records = {}
        self.negatives = {}
        self.missing = []
        self.faults = []

    def record(self, name, action):
        if not security.re.fullmatch(r'[a-z_]{1,64}', name) or name in self.records:
            raise RuntimeError('invalid or repeated full-suite stage name')
        started = int(time.time())
        value = action()
        if isinstance(value, dict) and value.get('status', 'pass') != 'pass':
            raise RuntimeError('non-passing full-suite stage: ' + name)
        record = {'name': name, 'status': 'pass', 'started_at': started,
                  'completed_at': int(time.time()), 'details': value}
        runtime.write_private_json(self.run.work / ('suite-' + name + '.json'), record)
        self.records[name] = record
        print('L2 complete suite: ' + name + ' verified', flush=True)
        return value

    def new_client(self, label, ttl=86400):
        security.SecurityChecks(self.run).fresh_browser()
        self.run.application_approval(credential_ttl_seconds=ttl)
        self.run.mcp_transport()
        self.run.diagnostic_checkpoint('suite-' + label + '-' + uuid.uuid4().hex)
        return snapshot_client(self.run)

    def topology(self):
        network = json.loads(self.run.command(['docker', 'network', 'inspect', self.run.project + '_closed']))[0]
        if network['Internal'] is not True:
            raise RuntimeError('full acceptance network is not internal')
        for identifier in self.run.container_ids.values():
            observed = json.loads(self.run.command(['docker', 'inspect', identifier]))[0]
            if (not observed['State']['Running'] or observed['State']['Paused']
                    or observed['HostConfig'].get('PortBindings')
                    or self.run.project + '_closed' not in observed['NetworkSettings']['Networks']
                    or any(observed['NetworkSettings']['Ports'].values())
                    or observed['Config']['Labels'].get('com.docker.compose.project') != self.run.project):
                raise RuntimeError('full acceptance container escaped the closed running topology')
        self.run.ready()
        return {'network_internal': True, 'published_ports': [],
                'actual_services': sorted(self.run.container_ids), 'service_readyz': True}

    def source_integrity(self):
        for name, checkout in runtime.CHECKOUTS.items():
            expected = self.run.sources[name]
            if (self.run.command(['git', 'rev-parse', 'HEAD'], cwd=checkout) != expected['revision']
                    or self.run.command(['git', 'status', '--porcelain'], cwd=checkout)
                    or runtime.source_digest(checkout) != expected['source_sha256']):
                raise RuntimeError('source changed during full acceptance: ' + name)
        runtime.verify_shared_public_contract(runtime.CHECKOUTS['access'])

    def cross_application(self):
        victim = self.new_client('isolation-victim')
        victim_upload = victim['analysis_created']['upload_id']
        victim_analysis = victim['analysis_created']['analysis_id']
        self.run.tool('analysis.read', {'operation_id': str(uuid.uuid4()), 'analysis_id': victim_analysis})
        self.new_client('isolation-attacker')
        checks = security.SecurityChecks(self.run)
        operation = str(uuid.uuid4())
        response = checks.rpc_probe('tools/call', {'name': 'analysis.read', 'arguments': {
            'operation_id': operation, 'analysis_id': victim_analysis}})
        checks.expect_denied('cross_application_read', operation, response, rpc=-32010)
        sample = (self.run.work / 'sample.elf').read_bytes()
        path = runtime.upload_contract(victim['analysis_created'], sample)
        subject = self.run.application_request['application_sub']
        query = f"SELECT json_build_object('state',state,'received_bytes',received_bytes,'owner_sub',owner_sub) FROM upload_sessions WHERE id='{victim_upload}';"
        count = lambda: int(self.run.sql(f"SELECT COALESCE(sum(dispatch_count),0) FROM application_operations WHERE application_sub='{subject}';", 'strad_l2'))
        before, before_count = self.run.sql(query, 'strad_l2'), count()
        status, _, body = self.run.application_http(path + '/chunks/0', body=sample, headers={
            'Content-Type': 'application/octet-stream',
            'Content-Range': f'bytes 0-{len(sample)-1}/{len(sample)}',
            'X-Chunk-Sha256': hashlib.sha256(sample).hexdigest()})
        if status != 404 or self.run.sql(query, 'strad_l2') != before or count() != before_count:
            raise RuntimeError('foreign upload was not refused before mutation/dispatch')
        checks.cases['cross_application_upload'] = {'status': 'pass', 'http_status': status,
            'dispatch_count': 0, 'victim_unchanged': True, 'response_sha256': hashlib.sha256(body).hexdigest()}
        return checks.cases

    def ordinary_negatives(self):
        activate_client(self.run, self.primary, initialize=True)
        checks = security.SecurityChecks(self.run)
        checks.basic()
        checks.introspection_outage()
        self.negatives.update(checks.cases)
        self.negatives.update(l2_context.run_context_checks(self.run))
        self.negatives.update(l2_decisions.run_decisions(self.run))
        self.negatives.update(self.cross_application())
        return copy.deepcopy(self.negatives)

    def missing_dependencies(self):
        activate_client(self.run, self.primary, initialize=True)
        checks = security.SecurityChecks(self.run)
        checks.postgres_outage()
        self.missing = [{'name': 'postgresql', 'result': 'fail_closed', 'pass_receipt_written': False,
                         'observation': checks.cases['postgresql_outage']}]
        self.missing.append(l2_missing_dependencies.check_missing_ghidra(self.run))
        self.missing.extend(l2_missing_dependencies.check_missing(self.run, case)
                            for case in l2_missing_dependencies.CASES)
        return copy.deepcopy(self.missing)

    def expiry(self, client):
        # The unchanged upload timeout has already exceeded this client's real
        # 900-second grant lifetime. No SQL expiration or clock injection occurs.
        deadline = time.monotonic() + 60
        subject = client['application_request']['application_sub']
        credential = client['credential']['credential_id']
        query = f"SELECT json_build_object('grant_state',g.state,'principal_state',p.state,'credential_state',c.credential_state,'expires_at',c.expires_at,'delivered',(SELECT count(*) FROM application_session_revocation_delivery d WHERE d.application_sub=p.subject AND d.reason='grant_expired' AND d.delivered_at IS NOT NULL)) FROM application_principal p JOIN \"grant\" g ON g.id=p.grant_id JOIN application_credential c ON c.application_sub=p.subject WHERE p.subject='{subject}' AND c.id='{credential}';"
        while True:
            observed = json.loads(self.run.sql(query))
            if (observed['grant_state'] == 'expired' and observed['principal_state'] == 'expired'
                    and observed['credential_state'] == 'expired' and observed['delivered'] >= 1
                    and observed['expires_at'] <= int(time.time())):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('real source-grant expiry cascade did not converge')
            time.sleep(1)
        activate_client(self.run, self.primary, initialize=True)
        checks = security.SecurityChecks(self.run)
        operation, response = checks.read_probe(token=client['credential']['token'], session=client['mcp_session'])
        checks.expect_denied('expired_credential', operation, response, http=401)
        active = int(self.run.sql(f"SELECT count(*) FROM analyze_facade_sessions WHERE application_sub='{subject}' AND state='active';", 'facade_l2'))
        if active != 0:
            raise RuntimeError('source-grant expiry left active facade sessions')
        self.negatives.update(checks.cases)
        return {**observed, 'active_facade_sessions': active, 'source_grant_cascade': True}

    def credential_lifecycle(self):
        self.new_client('rotation')
        checks = security.SecurityChecks(self.run)
        checks.rotate()
        normal = copy.deepcopy(checks.rotation)
        checks.expire_overlap()
        normal_cases = copy.deepcopy(checks.cases)
        # A separate rotation preserves the ordinary 300-second observation,
        # then exercises immediate revocation while another overlap is live.
        checks.rotate()
        old = checks.rotated
        principal = checks.principal()
        self.run.api('/api/v1/applications/' + self.run.application_request['id'] + '/credentials/' +
            old['old']['credential_id'] + '/revoke', method='POST', expected=204,
            value={'expected_version': principal['version']})
        operation, response = checks.read_probe(token=old['old']['token'], session=old['old_session'])
        checks.expect_denied('emergency_revoked_overlap', operation, response, http=401)
        old_state = json.loads(self.run.sql(f"SELECT json_build_object('state',credential_state,'overlap_until',overlap_until) FROM application_credential WHERE id='{old['old']['credential_id']}';"))
        if old_state != {'state': 'revoked', 'overlap_until': None}:
            raise RuntimeError('emergency revocation retained a usable overlap')
        self.rotation_client = snapshot_client(self.run)
        return {'normal_rotation': normal, 'normal_cases': normal_cases,
                'emergency_case': checks.cases['emergency_revoked_overlap'], 'emergency_state': old_state}

    def online_revocation(self):
        activate_client(self.run, self.rotation_client, initialize=True)
        subject = self.run.application_request['application_sub']
        credential = self.run.credential['credential_id']
        session_digest = hashlib.sha256(self.run.mcp_session.encode()).hexdigest()
        status, _, raw = self.run.request('access', 9390, '/internal/v1/application-credentials/introspect',
            method='POST', body=urlencode({'token': self.run.credential['token'],
                'mcp_session_digest': session_digest}).encode(),
            headers={'Authorization': 'Bearer ' + self.run.env['L2_ACCESS_INTROSPECTION_TOKEN'],
                     'Content-Type': 'application/x-www-form-urlencoded'})
        identity = json.loads(raw)
        if status != 200 or identity.get('active') is not True:
            raise RuntimeError('cannot capture the real pre-revocation session authority')
        operation = str(uuid.uuid4())
        body, headers = l2_context.signed_request(self.run, identity, self.run.mcp_session,
            {'jsonrpc': '2.0', 'id': 900001, 'method': 'tools/call', 'params': {'name': 'analysis.read',
             'arguments': {'operation_id': operation, 'analysis_id': self.run.analysis_created['analysis_id']}}},
            attenuate=False)
        checks = security.SecurityChecks(self.run)
        started = time.monotonic()
        checks.revoke()
        self.negatives['revoked_credential'] = checks.cases['revoked_credential']
        while True:
            delivery = json.loads(self.run.sql(f"SELECT json_build_object('effective_at',effective_at,'delivered_at',delivered_at,'event_id',event_id) FROM application_session_revocation_delivery WHERE application_sub='{subject}' AND credential_id='{credential}' ORDER BY issued_at DESC LIMIT 1;"))
            state = self.run.sql(f"SELECT state FROM analyze_facade_sessions WHERE mcp_session_digest='{session_digest}';", 'facade_l2')
            if delivery['delivered_at'] is not None and state == 'terminated':
                break
            if time.monotonic() - started >= 25:
                raise RuntimeError('revocation did not terminate the bound facade session in time')
            time.sleep(.25)
        status, _, raw = self.run.request('facade', 18120, '/mcp', host='analyze.w33d.xyz',
            method='POST', body=body, headers=headers)
        if status != 404 or json.loads(raw).get('error', {}).get('code') != 'invalid_session':
            raise RuntimeError('the previously bound session did not fail at the facade receiver')
        if checks.dispatches(operation) != 0:
            raise RuntimeError('revoked bound-session request dispatched work')
        enforced = math.ceil(time.time())
        elapsed = enforced - delivery['effective_at']
        if not 0 <= elapsed <= 30:
            raise RuntimeError('durable revocation exceeded the 30-second bound')
        return {'durable_revoked_at': delivery['effective_at'], 'enforced_at': enforced,
            'enforced_within_seconds': elapsed, 'delivery': delivery,
            'new_http_result': 'unauthenticated', 'bound_session_result': 'invalid_session',
            'bound_probe_layer': 'receiver_with_pre_revocation_authority_and_controlled_L2_signature',
            'bound_dispatch_count': 0, 'public_case': checks.cases['revoked_credential']}

    def fault_recovery(self):
        self.faults.append(run_timeout(self.run))
        self.new_client('result-commit-fault')
        self.faults.append(run_commit_fault(self.run))
        self.new_client('cleanup-fault')
        self.faults.append(run_cleanup_fault(self.run))
        return copy.deepcopy(self.faults)

    def final_fence(self):
        self.new_client('final-fence')
        return l2_fence.run_fence(self.run)

    def business(self):
        activate_client(self.run, self.primary, initialize=True)
        self.run.mcp_four_tools()
        return {**copy.deepcopy(self.run.observations['mcp_four_tools']),
                'initial_transport': self.transport}

    def execute(self):
        self.source_integrity()
        self.native = l2_native.run_native_checks(self.run)
        self.record('closed_topology', self.topology)
        self.record('application_approval', lambda: self.approval)
        self.record('oidc_browser', lambda: self.browser)
        expiry_client = self.new_client('expiry', ttl=900)
        self.record('ordinary_negatives', self.ordinary_negatives)
        self.record('missing_dependencies', self.missing_dependencies)
        self.rotation = self.record('credential_rotation', self.credential_lifecycle)
        self.revocation = self.record('online_revocation', self.online_revocation)
        self.fence = self.record('final_fence_barrier', self.final_fence)
        self.record('fault_recovery', self.fault_recovery)
        self.expiration = self.record('source_grant_expiry', lambda: self.expiry(expiry_client))
        if set(self.negatives) != set(NEGATIVE_CASES) or any(
                case.get('status') != 'pass' or case.get('dispatch_count') != 0 for case in self.negatives.values()):
            raise RuntimeError('complete negative authorization matrix was not proven')
        self.record('authorization_negatives', lambda: copy.deepcopy(self.negatives))
        # The only billable stage is deliberately last, after every refusal,
        # expiry, rotation, fault, and missing-dependency check has completed.
        self.record('mcp_four_tools', self.business)
        self.topology()
        self.source_integrity()
        return self
