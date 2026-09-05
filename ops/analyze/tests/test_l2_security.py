"""Unit tests for the security harness, not substitutes for live checks."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("l2_security_checks", ROOT / "l2_security.py")
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


class SecurityHarnessTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.queries = []
        self.dispatch_count = 0
        self.run = SimpleNamespace(rpc_id=0, credential={"token": "unit-credential"},
            mcp_session="unit-session", analysis_created={"analysis_id": str(uuid.uuid4())})

        def request(*args, **kwargs):
            self.requests.append((args, kwargs))
            return 401, {}, b'{"error":{"code":"unauthenticated"}}'

        def sql(query, database):
            self.queries.append((query, database))
            return str(self.dispatch_count)

        self.run.request = request
        self.run.sql = sql
        self.checks = security.SecurityChecks(self.run)

    def test_no_token_really_omits_authorization_header(self):
        self.checks.read_probe(token=None, session=None)
        headers = self.requests[0][1]["headers"]
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Mcp-Session-Id", headers)

    def test_default_probe_uses_existing_client_and_unique_operation(self):
        first, _ = self.checks.read_probe()
        second, _ = self.checks.read_probe()
        self.assertNotEqual(first, second)
        self.assertEqual(self.requests[0][1]["headers"]["Authorization"], "Bearer unit-credential")
        body = json.loads(self.requests[0][1]["body"])
        self.assertEqual(body["params"]["name"], "analysis.read")

    def test_transport_failure_tolerance_is_explicit_and_never_accepts_success(self):
        self.run.request = lambda *args, **kwargs: (502, {}, b'')
        with self.assertRaisesRegex(RuntimeError, 'non-JSON'):
            self.checks.read_probe()
        _, response = self.checks.read_probe(allow_transport_error=True)
        self.assertEqual(response[0], 502)
        self.assertTrue(response[2]['transport_error'])
        self.run.request = lambda *args, **kwargs: (200, {}, b'not-json')
        with self.assertRaisesRegex(RuntimeError, 'non-JSON'):
            self.checks.read_probe(allow_transport_error=True)

    def test_denial_requires_zero_authoritative_dispatches(self):
        operation, response = self.checks.read_probe(token=None)
        self.dispatch_count = 1
        with self.assertRaisesRegex(RuntimeError, "unauthorized dispatch"):
            self.checks.expect_denied("no_token", operation, response, http=401)
        self.assertEqual(self.checks.cases, {})

    def test_success_cannot_be_recorded_as_a_denial(self):
        operation = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "expected HTTP"):
            self.checks.expect_denied("no_token", operation, (200, {}, {"result": {}}, "digest"), http=401)
        with self.assertRaisesRegex(RuntimeError, "explicit denial"):
            self.checks.expect_denied("no_token", operation, (200, {}, {"result": {}}, "digest"))

    def test_alias_requires_exact_not_found_contract(self):
        operation = str(uuid.uuid4())
        self.checks.expect_denied("alias", operation, (200, {}, {"error": {"code": -32010}}, "digest"), rpc=-32010)
        self.assertEqual(self.checks.cases["alias"]["dispatch_count"], 0)
        self.assertTrue(self.queries[0][0].startswith("SELECT"))
        self.assertEqual(self.queries[0][1], "strad_l2")

    def test_expired_credential_case_keeps_its_original_session(self):
        self.run.tool = lambda *args: {}
        original_request = self.run.request

        def respond(*args, **kwargs):
            body = json.loads(kwargs['body'])
            if body['params']['name'] == 'analysis_read':
                self.requests.append((args, kwargs))
                return 200, {}, b'{"error":{"code":-32010}}'
            return original_request(*args, **kwargs)

        self.run.request = respond
        self.checks.basic({'token': 'expired-unit-credential'}, 'original-expired-session')
        headers = self.requests[2][1]['headers']
        self.assertEqual(headers['Mcp-Session-Id'], 'original-expired-session')
        self.assertEqual(headers['Authorization'], 'Bearer expired-unit-credential')

    def test_restore_rejects_non_acceptance_directories_before_any_command(self):
        with self.assertRaisesRegex(RuntimeError, "closed run directory"):
            security.restore(Path('/root/w33d_infra/deploy'), 'client.private.json')

    def test_outage_always_restores_the_stopped_service(self):
        commands = []
        self.run.tool = lambda *args: {}
        self.run.compose = lambda *args, **kwargs: commands.append(args)
        self.run.ready = lambda: commands.append(('ready',))
        # The default fixture returns 401, not the required outage response.
        with self.assertRaisesRegex(RuntimeError, 'expected HTTP 503'):
            self.checks.introspection_outage()
        self.assertEqual(commands, [('stop', '--timeout', '5', 'access'), ('start', 'access'), ('ready',)])


if __name__ == '__main__':
    unittest.main()
