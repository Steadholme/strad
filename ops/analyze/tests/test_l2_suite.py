"""Orchestration tests only: no model or authority endpoint is called here."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import l2_suite as suite


class SimulatedSuite(suite.FullSuite):
    def __init__(self, work, failure=None):
        run = SimpleNamespace(work=work, application_request={}, credential={}, mcp_session='test-session',
            analysis_created={}, observations={'application_approval_core': {'status': 'pass'},
            'oidc_browser_core': {'status': 'pass'}, 'mcp_transport': {'status': 'pass'}})
        super().__init__(run)
        self.timeline = []
        self.failure = failure
        self.model_calls = 0

    def note(self, name):
        self.timeline.append(name)
        if self.failure == name:
            raise RuntimeError('simulated stage failure')
        return {'status': 'pass'}

    def source_integrity(self):
        self.note('source_integrity')

    def topology(self):
        return self.note('topology')

    def new_client(self, label, ttl=86400):
        self.timeline.append((label, ttl))
        return {}

    def ordinary_negatives(self):
        self.note('ordinary_negatives')
        self.negatives = {name: {'status': 'pass', 'dispatch_count': 0}
                          for name in suite.NEGATIVE_CASES if name not in {'expired_credential', 'revoked_credential'}}
        return dict(self.negatives)

    def missing_dependencies(self):
        return self.note('missing_dependencies')

    def credential_lifecycle(self):
        return self.note('credential_lifecycle')

    def online_revocation(self):
        self.negatives['revoked_credential'] = {'status': 'pass', 'dispatch_count': 0}
        return self.note('online_revocation')

    def final_fence(self):
        return self.note('final_fence')

    def fault_recovery(self):
        return self.note('fault_recovery')

    def expiry(self, _client):
        self.negatives['expired_credential'] = {'status': 'pass', 'dispatch_count': 0}
        return self.note('expiry')

    def business(self):
        self.model_calls += 1
        return self.note('business')


class FullSuiteOrchestrationTests(unittest.TestCase):
    def test_all_nine_scenarios_are_recorded_and_business_is_last(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(suite.l2_native, 'run_native_checks', return_value={}):
            run = SimulatedSuite(Path(temporary)).execute()
            self.assertEqual(run.model_calls, 1)
            self.assertTrue(set(suite.runtime.REQUIRED_SCENARIOS).issubset(run.records))
            self.assertGreater(run.timeline.index('business'), run.timeline.index('expiry'))
            self.assertGreater(run.timeline.index('expiry'), run.timeline.index('fault_recovery'))
            self.assertIn(('expiry', 900), run.timeline)
            for name, record in run.records.items():
                self.assertEqual(json.loads((Path(temporary) / f'suite-{name}.json').read_text()), record)

    def test_pre_business_failure_never_reaches_model_or_business_pass_record(self):
        for failure in ['ordinary_negatives', 'missing_dependencies', 'credential_lifecycle',
                        'online_revocation', 'final_fence', 'fault_recovery', 'expiry']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(suite.l2_native, 'run_native_checks', return_value={}):
                run = SimulatedSuite(Path(temporary), failure)
                with self.assertRaisesRegex(RuntimeError, 'simulated stage failure'):
                    run.execute()
                self.assertEqual(run.model_calls, 0)
                self.assertFalse((Path(temporary) / 'suite-mcp_four_tools.json').exists())

    def test_stage_names_cannot_overwrite_or_escape_the_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = SimulatedSuite(Path(temporary))
            run.record('example', lambda: {'status': 'pass'})
            for name in ['example', '../escape']:
                with self.assertRaisesRegex(RuntimeError, 'stage name'):
                    run.record(name, lambda: {'status': 'pass'})
            with self.assertRaisesRegex(RuntimeError, 'non-passing'):
                run.record('failed', lambda: {'status': 'failed'})
            self.assertFalse((Path(temporary) / 'suite-failed.json').exists())


if __name__ == '__main__':
    unittest.main()
