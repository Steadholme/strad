"""Native suites against separate databases, never the L2 authority databases."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote
import uuid

import l2_runtime as runtime


def database(run, purpose):
    if not re.fullmatch(r'[a-z_]{1,24}', purpose):
        raise RuntimeError('invalid native database purpose')
    name = 'l2_native_' + purpose + '_' + uuid.uuid4().hex[:12]
    run.command(['docker', 'exec', run.container_ids['postgres'], 'createdb', '-U', 'l2', name])
    return f"postgresql://l2:{quote(run.env['L2_POSTGRES_PASSWORD'], safe='')}@{run.address('postgres')}:5432/{name}"


def export_source(run, component, destination):
    checkout = runtime.CHECKOUTS[component]
    revision = run.sources[component]['revision']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise RuntimeError('native tests require an exact source revision')
    entries = run.command(['git', 'ls-tree', '-r', revision], cwd=checkout)
    if any(line.split()[0] not in {'100644', '100755'} for line in entries.splitlines()):
        raise RuntimeError('native source export contains non-regular entries')
    destination.mkdir(parents=True)
    producer = subprocess.Popen(['git', 'archive', revision], cwd=checkout, stdout=subprocess.PIPE)
    try:
        extracted = subprocess.run(['tar', '-xf', '-', '-C', str(destination)],
                                   stdin=producer.stdout, capture_output=True, timeout=60)
        producer.stdout.close()
        if extracted.returncode != 0 or producer.wait(timeout=60) != 0:
            raise RuntimeError('native source archive extraction failed')
    finally:
        if producer.stdout and not producer.stdout.closed:
            producer.stdout.close()
        if producer.poll() is None:
            producer.terminate()
            producer.wait(timeout=5)


def run_native_checks(run):
    root = run.work / 'native-sources'
    for component, directory in [('access', 'access-governance'), ('verdict', 'verdict'), ('strad', 'strad')]:
        export_source(run, component, root / directory)
    runtime.verify_shared_public_contract(root / 'access-governance')
    validator_root = root / 'strad' / 'ops' / 'analyze'
    run.command(['npm', 'ci', '--ignore-scripts'], cwd=validator_root)
    run.l2_schema_validator = validator_root / 'node_modules/.bin/ajv'
    result = {}

    def execute(name, invocations):
        transcripts = []
        for args, cwd, env in invocations:
            output = run.command(args, cwd=cwd, env=env, timeout=1200)
            for secret in run.env.values():
                if len(secret) >= 24:
                    output = output.replace(secret, '[redacted]')
            output = re.sub(r'postgres(?:ql)?://\S+|app_v1_[A-Za-z0-9_-]{43}', '[redacted]', output)
            transcripts.append({'command': args, 'stdout': output,
                                'output_sha256': hashlib.sha256(output.encode()).hexdigest()})
        result[name] = {'status': 'pass', 'checks': transcripts, 'real_postgres_configured': True}
        runtime.write_private_json(run.work / ('suite-native-' + name + '.json'), result[name])
        print('L2 native: ' + name + ' passed against isolated test databases', flush=True)

    access_env = {**os.environ, 'CARGO_BUILD_JOBS': '1',
                  'CARGO_TARGET_DIR': str(runtime.CHECKOUTS['access'] / 'target')}
    access_calls = []
    for target in ['application_access_flow', 'analyze_approval_worker', 'analyze_origin_flow']:
        access_calls.append((['cargo', 'test', '--locked', '--test', target, '--', '--test-threads=1'],
                             root / 'access-governance', {**access_env,
                             'ACCESS_GOVERNANCE_TEST_DATABASE_URL': database(run, 'access')}))
    execute('access_real_pg', access_calls)

    sluice = runtime.CHECKOUTS['sluice']
    execute('sluice_manifest', [(['go', 'test', '-mod=readonly', '-count=1', './...'], sluice,
        {**os.environ, 'GOMAXPROCS': '2', 'TEST_DATABASE_URL': database(run, 'sluice'),
         'GIT_DIR': run.command(['git', 'rev-parse', '--absolute-git-dir'], cwd=sluice),
         'GIT_WORK_TREE': str(sluice)})])

    verdict_calls = []
    for target in ['application_subject_flow', 'application_status_versions', 'pg_application_decision']:
        verdict_calls.append((['cargo', 'test', '--locked', '--test', target, '--', '--test-threads=1'],
            root / 'verdict', {**os.environ, 'CARGO_BUILD_JOBS': '1',
            'CARGO_TARGET_DIR': str(runtime.CHECKOUTS['verdict'] / 'target'),
            'TEST_DATABASE_URL': database(run, 'verdict')}))
    execute('verdict_manifest', verdict_calls)

    facade = root / 'strad' / 'facade'
    facade_env = {**os.environ, 'FACADE_TEST_DATABASE_URL': database(run, 'facade')}
    execute('facade_contract', [(['npm', 'ci', '--ignore-scripts'], facade, facade_env),
                                (['npm', 'test'], facade, facade_env)])
    execute('strad_real_pg', [(['cargo', 'test', '--locked', '--test', 'postgres_contract',
        '--test', 'application_upload_contract', '--test', 'application_facade_contract', '--', '--test-threads=1'],
        root / 'strad', {**os.environ, 'CARGO_BUILD_JOBS': '1',
        'CARGO_TARGET_DIR': str(runtime.STRAD / 'target'),
        'STRAD_TEST_DATABASE_URL': database(run, 'strad')})])
    return result
