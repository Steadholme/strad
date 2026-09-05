"""Receipt projection tests use synthetic evidence only in temporary folders."""
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import l2_receipt as receipt
import l2_runtime as runtime


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary) / 'private'
        work.mkdir(mode=0o700)
        output = Path(temporary) / 'result.json'
        manifest = Path(temporary) / 'manifest.json'
        manifest.write_text(json.dumps({'repositories': {name: {'final_commit_sha': 'a' * 40}
                            for name in ['sluice', 'verdict']}}))
        run = SimpleNamespace(work=work, run_id='b' * 32, started_at=int(time.time()) - 2,
            sources={name: {'revision': 'a' * 40} for name in ['access', 'sluice', 'verdict', 'strad']},
            analyzer_image='example.invalid/analyzer@sha256:' + 'c' * 64,
            env={'L2_ANALYZER_IMAGE': 'example.invalid/analyzer@sha256:' + 'c' * 64,
                 'L2_BRIDGE_TOKEN': 'synthetic-secret-' + 'x' * 32},
            l2_schema_validator=ROOT / 'node_modules/.bin/ajv')
        def command(args):
            result = subprocess.run(args, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            return result.stdout
        run.command = command
        suite = SimpleNamespace(run=run,
            native={name: {'status': 'pass', 'checks': ['synthetic fixture']}
                    for name in receipt.validator.NATIVE_CHECKS[:5]},
            negatives={name: {'status': 'pass', 'dispatch_count': 0}
                       for name in receipt.NEGATIVE_CASES},
            faults=[{'name': name, 'state': 'downstream_uncertain', 'reservation_retained': True,
                     'automatic_resend_count': 0, 'audited_reconciliation': True}
                    for name in receipt.validator.FAULTS],
            missing=[{'name': name, 'result': 'fail_closed', 'pass_receipt_written': False}
                     for name in receipt.validator.MISSING],
            approval={'counts': {'decisions': 1, 'sponsor_consumptions': 1, 'grants': 1,
                                'principals': 1, 'decision_ttl': 300}},
            browser={'csrf_distinct': True, 'dom_sha256': 'd' * 64},
            expiration={'source_grant_cascade': True},
            rotation={'normal_rotation': {'overlap_until': 1300, 'rotated_at': 1000},
                      'normal_cases': {'old_overlap_expired': {'http_status': 401}},
                      'emergency_state': {'state': 'revoked', 'overlap_until': None}},
            fence={'fence_result': 'inactive', 'dispatch_count': 0, 'revoke_committed_before_release': True},
            revocation={'durable_revoked_at': 1000, 'enforced_at': 1001, 'enforced_within_seconds': 1})
        suite.negatives['wrong_scope'].update(authorization_audit=[{'outcome': 'insufficient_scope', 'has_digest': False}], verdict_calls=0)
        for name in ['stale_digest', 'stale_version', 'stale_ttl', 'deny', 'indeterminate', 'dependency_failure']:
            suite.negatives[name]['authorization_audit'] = [{'outcome': name}]
        suite.records = {name: {'name': name, 'status': 'pass', 'details': {}}
                         for name in runtime.REQUIRED_SCENARIOS}
        for attribute, stage in [('approval', 'application_approval'), ('browser', 'oidc_browser'),
                ('negatives', 'authorization_negatives'), ('rotation', 'credential_rotation'),
                ('revocation', 'online_revocation'), ('fence', 'final_fence_barrier'),
                ('faults', 'fault_recovery'), ('missing', 'missing_dependencies'),
                ('expiration', 'source_grant_expiry')]:
            suite.records[stage] = {'name': stage, 'status': 'pass', 'details': getattr(suite, attribute)}
        suite.records['mcp_four_tools']['details'] = {'newapi_conversation_calls': 1, 'rest_cancel_status': 404,
            'analyzer_image': run.analyzer_image, 'newapi_model': 'glm-5.2', 'analysis_id': 'analysis-fixture',
            'initial_transport': {'status': 'pass', 'created': {'analysis_id': 'analysis-fixture'}}}
        for name, record in suite.records.items():
            runtime.write_private_json(work / f'suite-{name}.json', record)
        for name, record in suite.native.items():
            runtime.write_private_json(work / f'suite-native-{name}.json', record)
        with patch.object(receipt.validator, 'MANIFEST', manifest), \
             patch.object(receipt.validator, 'git_revision', return_value='a' * 40):
            yield suite, output


class CompleteReceiptTests(unittest.TestCase):
    def test_validator_repository_roots_match_runtime_roots(self):
        self.assertEqual(receipt.validator.INFRA_ROOT, runtime.INFRA)
        self.assertEqual(receipt.validator.ACCESS_ROOT, runtime.CHECKOUTS['access'])
        self.assertEqual(receipt.validator.SLUICE_ROOT, runtime.CHECKOUTS['sluice'])

    def test_complete_synthetic_fixture_validates_and_publishes_marker_last(self):
        with fixture() as (suite, output):
            value = receipt.emit_receipt(suite, output)
            self.assertEqual(value['status'], 'pass')
            self.assertEqual(len(value['scenarios']), 9)
            self.assertEqual(len(value['native_checks']), 7)
            self.assertEqual(json.loads(output.read_text()), value)
            bundle = output.parent / ('l2-evidence-' + suite.run.run_id)
            self.assertTrue(bundle.is_dir())
            for item in value['scenarios']:
                self.assertEqual(runtime.digest(bundle / f"suite-{item['name']}.json"), item['evidence_sha256'])
            self.assertFalse(list(bundle.glob('*.private.json')))

    def test_incomplete_or_modified_evidence_cannot_emit_a_passing_marker(self):
        mutations = [
            lambda s: s.records.pop('fault_recovery'),
            lambda s: s.native.pop('access_real_pg'),
            lambda s: s.negatives['deny'].update(dispatch_count=1),
            lambda s: s.faults[0].update(automatic_resend_count=1),
            lambda s: s.approval['counts'].update(sponsor_consumptions=0),
            lambda s: s.records['mcp_four_tools']['details'].update(newapi_conversation_calls=2),
        ]
        for mutation in mutations:
            with fixture() as (suite, output):
                mutation(suite)
                with self.assertRaises(RuntimeError):
                    receipt.emit_receipt(suite, output)
                self.assertFalse(output.exists())

    def test_schema_or_semantic_failure_never_writes_the_final_marker(self):
        with fixture() as (suite, output):
            suite.revocation['enforced_within_seconds'] = 99
            with self.assertRaises((RuntimeError, ValueError)):
                receipt.emit_receipt(suite, output)
            self.assertFalse(output.exists())

    def test_private_token_in_evidence_is_not_copied_to_publication_bundle(self):
        with fixture() as (suite, output):
            value = suite.records['oidc_browser']
            value['details']['token'] = 'app_v1_' + 'A' * 43
            source = suite.run.work / 'suite-oidc_browser.json'
            source.unlink()
            runtime.write_private_json(source, value)
            with self.assertRaisesRegex(RuntimeError, 'sensitive proof material'):
                receipt.emit_receipt(suite, output)
            self.assertFalse(output.exists())
            self.assertFalse((output.parent / ('l2-evidence-' + suite.run.run_id)).exists())


if __name__ == '__main__':
    unittest.main()
