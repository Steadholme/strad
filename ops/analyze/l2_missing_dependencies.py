#!/usr/bin/env python3
"""Missing configuration checks in disposable, network-disabled containers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

import l2_security as security


CASES = [
    ('ed25519_keyring', 'facade', 'SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING',
     'SLUICE_APPLICATION_CONTEXT_VERIFICATION_KEYRING'),
    ('application_credential_pepper', 'access', 'ACCESS_APPLICATION_CREDENTIAL_PEPPER',
     'Analyze application access configuration is partial'),
    ('approval_worker_signing_key', 'access', 'ACCESS_ANALYZE_APPROVAL_SIGNING_KEYRING',
     'Analyze application access configuration is partial'),
    ('strad_facade_token', 'strad', 'STRAD_FACADE_TOKEN', 'STRAD_FACADE_TOKEN'),
    ('strad_governance_reporting_token', 'strad', 'STRAD_GOVERNANCE_REPORTING_TOKEN',
     'STRAD_GOVERNANCE_REPORTING_TOKEN'),
]


def missing_ghidra_confirmed(details):
    return any(item.get('stage') == 'child_bootstrap' and item.get('code') == 'ENOENT'
        and '/opt/ghidra/support/analyzeHeadless' in item.get('message', '') for item in details)


def check_missing(run, case):
    name, service, missing, expected = case
    original = json.loads(run.command(['docker', 'inspect', run.container_ids[service]]))[0]
    env = {}
    for item in original['Config']['Env']:
        key, value = item.split('=', 1)
        if '\n' in value or '\r' in value:
            raise RuntimeError('unexpected multiline configuration in dependency probe')
        env[key] = value
    if not env.get(missing):
        raise RuntimeError('baseline service does not have the required dependency: ' + missing)
    env[missing] = ''
    root = run.work / 'dependency-probes'
    root.mkdir(mode=0o700, exist_ok=True)
    env_file = root / (name + '-' + uuid.uuid4().hex + '.env')
    with env_file.open('x') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(''.join(f'{key}={value}\n' for key, value in env.items()))
    identifier = None
    try:
        args = ['docker', 'create', '--name', 'analyze-dependency-' + uuid.uuid4().hex,
            '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '512m',
            '--no-healthcheck', '--env-file', str(env_file), '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m']
        for mount in original['Mounts']:
            if mount['Type'] == 'bind' and not mount['RW']:
                args.extend(['--mount', f"type=bind,src={mount['Source']},dst={mount['Destination']},readonly"])
        args.append(original['Config']['Image'])
        identifier = run.command(args)
        run.command(['docker', 'start', identifier])
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            observed = json.loads(run.command(['docker', 'inspect', identifier]))[0]
            if not observed['State']['Running']:
                break
            time.sleep(.25)
        else:
            raise RuntimeError(name + ': missing dependency did not stop startup')
        logs = run.command(['docker', 'logs', identifier])
        # Some entrypoints log to stderr; docker logs includes that stream in
        # the command's stderr, so collect it without exposing its contents.
        if expected not in logs:
            import subprocess
            result = subprocess.run(['docker', 'logs', identifier], capture_output=True, text=True, timeout=10)
            logs = result.stdout + result.stderr
        if observed['State']['ExitCode'] == 0 or expected not in logs or observed['State']['OOMKilled']:
            raise RuntimeError(name + ': failure was not caused by the removed configuration')
        if observed['HostConfig']['NetworkMode'] != 'none' or any(observed['NetworkSettings']['Ports'].values()):
            raise RuntimeError('dependency probe escaped network isolation')
        print('L2 missing dependency: ' + name + ' stops startup', flush=True)
        return {'name': name, 'result': 'fail_closed', 'pass_receipt_written': False,
            'removed_variable': missing, 'exit_code': observed['State']['ExitCode'],
            'network': 'none', 'recognized_failure': expected,
            'diagnostic_sha256': hashlib.sha256(logs.encode()).hexdigest()}
    finally:
        if identifier:
            run.command(['docker', 'rm', '-f', identifier])
        env_file.unlink(missing_ok=True)

def check_missing_ghidra(run):
    import subprocess
    import tempfile
    import shutil
    root = Path(tempfile.mkdtemp(prefix='missing-ghidra-', dir=run.work))
    identifier = None
    try:
        original = json.loads(run.command(['docker', 'inspect', run.container_ids['analyzer']]))[0]
        env_file = root / 'probe.env'
        with env_file.open('x') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write('\n'.join(original['Config']['Env']) + '\n')
        directories = [root / name for name in ['workspaces', 'storage', 'state', 'cache', 'audit', 'empty-ghidra']]
        for path in directories:
            path.mkdir(mode=0o700)
            os.chown(path, 1000, 1000)
        for path in [root/'workspaces/ghidra-projects', root/'audit/ghidra']:
            path.mkdir(mode=0o700); os.chown(path, 1000, 1000)
        args = ['docker', 'create', '--name', 'analyze-missing-ghidra-' + uuid.uuid4().hex,
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--no-healthcheck', '--env-file', str(env_file), '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700']
        for name in ['workspaces', 'storage', 'state', 'cache', 'audit']:
            args.extend(['--mount', f'type=bind,src={root/name},dst=/data/{name}'])
        args.extend(['--mount', f'type=bind,src={root/"empty-ghidra"},dst=/opt/ghidra,readonly',
            '--mount', f'type=bind,src={security.runtime.ROOT/"missing-ghidra-probe.mjs"},dst=/app/missing-ghidra-probe.mjs,readonly',
            '--entrypoint', '/usr/local/bin/node', '-e', 'HOME=/tmp/rikune-home',
            original['Config']['Image'], '/app/missing-ghidra-probe.mjs'])
        identifier = run.command(args)
        run.command(['docker', 'start', identifier])
        ready_seen = False
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            observed = json.loads(run.command(['docker', 'inspect', identifier]))[0]
            if not observed['State']['Running']:
                break
            probe = subprocess.run(['docker', 'exec', identifier, '/usr/local/bin/node', '-e',
                "fetch('http://127.0.0.1:18090/readyz',{signal:AbortSignal.timeout(700)}).then(r=>console.log(r.status)).catch(()=>console.log('unreachable'))"],
                capture_output=True, text=True, timeout=3)
            if probe.stdout.strip() == '200':
                ready_seen = True
                break
            time.sleep(.5)
        logs = subprocess.run(['docker', 'logs', identifier], capture_output=True, text=True, timeout=10)
        diagnostic = logs.stdout + logs.stderr
        details = [json.loads(line.removeprefix('MISSING_GHIDRA_DIAGNOSTIC '))
                   for line in diagnostic.splitlines() if line.startswith('MISSING_GHIDRA_DIAGNOSTIC ')]
        failed_backend = missing_ghidra_confirmed(details)
        worker_blocked = False
        if observed['State']['Running']:
            probe = subprocess.run(['docker', 'exec', identifier, '/usr/local/bin/node', '--input-type=module', '-e', """
import fs from 'node:fs';
import { DatabaseManager } from '/app/dist/database.js';
import { WorkspaceManager } from '/app/dist/workspace-manager.js';
import { DecompilerWorker } from '/app/dist/worker/decompiler-worker.js';
import { ghidraConfig } from '/app/dist/ghidra/ghidra-config.js';
const db=new DatabaseManager('/data/state/missing-worker-check.db');
try {
  let blocked=false;
  try { await new DecompilerWorker(db,new WorkspaceManager('/data/workspaces/worker-check')).analyze('sha256:'+'0'.repeat(64)); }
  catch(error) { blocked=ghidraConfig.isValid===false && error.message.startsWith('Ghidra is not properly configured.'); }
  if(fs.existsSync('/opt/ghidra/support/analyzeHeadless') || !blocked) process.exitCode=1;
  console.log('MISSING_GHIDRA_RESULT '+JSON.stringify({blocked}));
} finally { db.close(); }
"""], capture_output=True, text=True, timeout=15)
            worker_blocked = probe.returncode == 0 and 'MISSING_GHIDRA_RESULT {"blocked":true}' in probe.stdout
        if not worker_blocked and not (failed_backend and not observed['State']['Running']):
            safe = diagnostic
            for item in original['Config']['Env']:
                value = item.split('=', 1)[1]
                if len(value) >= 16: safe = safe.replace(value, '[redacted]')
            raise RuntimeError(f'missing Ghidra failure was not verified: service_ready={ready_seen}, running={observed["State"]["Running"]}; ' + safe[-1800:])
        print('L2 missing dependency: absent Ghidra blocks the real analysis worker', flush=True)
        return {'name': 'analyzer_ghidra', 'result': 'fail_closed', 'pass_receipt_written': False,
            'network': 'none', 'backend_masked_readonly': True, 'ready_seen': ready_seen,
            'real_worker_preflight_blocked': worker_blocked,
            'recognized_backend_diagnostic': details,
            'diagnostic_sha256': hashlib.sha256(diagnostic.encode()).hexdigest()}
    finally:
        if identifier: run.command(['docker', 'rm', '-f', identifier])
        shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists() or output.parent != security.runtime.INFRA / '.runtime':
        parser.error('choose a new output inside the private runtime directory')
    os.umask(0o077)
    run = security.restore(Path(args.work), args.checkpoint)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda case: check_missing(run, case), CASES))
    security.runtime.write_private_json(output, {'scope': 'isolated_missing_configuration_acceptance',
        'release_eligible': False, 'project': run.project, 'missing_dependencies': results})


if __name__ == '__main__':
    main()
