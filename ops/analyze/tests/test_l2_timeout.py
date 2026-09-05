import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import l2_timeout as timeout


class RecoveryRun:
    def __init__(self):
        self.application_request = {'application_sub': 'application:abcdefghijklmnop'}
        self.analysis_created = {'finalize_operation_id': 'c0230c98-d0c2-8379-a242-35ddea1ec60f'}
        self.env = {'L2_BRIDGE_TOKEN': 'test-bridge', 'L2_STRAD_FACADE_TOKEN': 'test-facade'}
        self.current = {'state': 'downstream_uncertain', 'reservation_active': True,
            'dispatch_count': 1, 'upload_state': 'finalized', 'binding_state': 'committed',
            'analysis_id': '73bbc3f7-18c9-4d0c-b152-608999f5ae9f', 'analysis_state': 'uploaded',
            'bridge_operation_id': '91672779-8652-4fc2-803d-2c13a200a669',
            'upload_lease_remaining_seconds': 0}
        self.calls = []

    def sql(self, query, database):
        assert database == 'strad_l2'
        assert query.startswith('SELECT ')
        return '1' if 'count(*)' in query else json.dumps(self.current)

    def request(self, service, port, path, **kwargs):
        self.calls.append((service, path, kwargs))
        if service == 'analyzer':
            assert kwargs.get('method', 'GET') == 'GET'
            return 200, {}, b'{"data":{"state":"succeeded"}}'
        assert service == 'strad' and path.endswith('/reconcile')
        self.current = {**self.current, 'state': 'completed', 'reservation_active': False}
        return 204, {}, b''


class TimeoutRecoveryTests(unittest.TestCase):
    def test_resume_only_reads_journal_and_reconciles_same_operation(self):
        run = RecoveryRun()
        result = timeout.recover_timeout(run, dict(run.current))
        self.assertTrue(result['resumed_original_operation'])
        self.assertIsNone(result['elapsed_seconds'])
        self.assertIsNone(result['first_public_status'])
        self.assertEqual(result['after_reconciliation']['dispatch_count'], 1)
        self.assertEqual(len(run.calls), 3)
        self.assertEqual(run.calls[1][2]['body'], run.calls[2][2]['body'])

    def test_resume_rejects_non_uncertain_or_unreserved_executions(self):
        for override in [{'state': 'leased'}, {'reservation_active': False}, {'dispatch_count': 2}]:
            run = RecoveryRun()
            with self.assertRaisesRegex(RuntimeError, 'single uncertain dispatch'):
                timeout.recover_timeout(run, {**run.current, **override})
            self.assertEqual(run.calls, [])

    def test_successful_journal_does_not_bypass_live_upload_lease(self):
        run = RecoveryRun()
        run.current = {**run.current, 'upload_state': 'forwarding',
                       'upload_lease_remaining_seconds': 900}
        original = dict(run.current)
        with patch.object(timeout.time, 'monotonic', side_effect=[0, 0, 0, 901, 901, 901, 961]), \
             patch.object(timeout.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'has not reconciled'):
                timeout.recover_timeout(run, original)
        self.assertEqual(len(run.calls), 1)
        self.assertTrue(run.current['reservation_active'])

    def test_unexpected_lease_bound_never_authorizes_reconciliation(self):
        run = RecoveryRun()
        run.current['upload_lease_remaining_seconds'] = 1801
        with self.assertRaisesRegex(RuntimeError, 'recovery bound'):
            timeout.recover_timeout(run, dict(run.current))
        self.assertEqual(len(run.calls), 1)


if __name__ == '__main__':
    unittest.main()
