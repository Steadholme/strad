import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import stat
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("l2_runtime", ROOT / "l2_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class LiveProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(503 if self.path == "/unavailable" else 200)
        self.end_headers()
        self.wfile.write(b"x" * (1024 * 1024 + 1) if self.path == "/large" else b'{"status":"ready"}')


class RuntimeEvidenceTests(unittest.TestCase):
    def test_new_run_identity_matches_the_complete_receipt_schema(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(runtime, 'INFRA', Path(temporary)):
            run = runtime.ClosedRun()
            self.assertRegex(run.run_id, r'^[0-9a-f]{32}$')
            self.assertGreater(run.started_at, 0)
            self.assertEqual(run.project, 'analyze-l2-' + run.run_id)

    def test_access_standalone_fixture_must_match_the_shared_contract_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            fixture = checkout / 'tests/fixtures/analyze_public_v1.json'
            fixture.parent.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, 'contracts differ'):
                runtime.verify_shared_public_contract(checkout)
            fixture.write_bytes((ROOT / 'analyze-public-v1.json').read_bytes())
            runtime.verify_shared_public_contract(checkout)
            fixture.write_text('{}\n')
            with self.assertRaisesRegex(RuntimeError, 'contracts differ'):
                runtime.verify_shared_public_contract(checkout)
            fixture.unlink()
            fixture.symlink_to(ROOT / 'analyze-public-v1.json')
            with self.assertRaisesRegex(RuntimeError, 'contracts differ'):
                runtime.verify_shared_public_contract(checkout)

    def test_application_projection_waits_for_current_authority_not_old_active_status(self):
        run = object.__new__(runtime.ClosedRun)
        run.application_request = {"application_sub": "application:abcdefghijklmnop"}
        authority = {"state": "active", "subject_version": 2, "policy_epoch": 1,
                     "revocation_epoch": 1, "grant_state": "active",
                     "projection_state": "projected", "projection_error": None, "projected_edges": 4}
        current = {field: authority[field] for field in
                   ["state", "subject_version", "policy_epoch", "revocation_epoch"]}
        results = iter([authority, {**current, "subject_version": 1}, authority, current])
        queries = []

        def observe(query, database="access_l2"):
            queries.append((query, database))
            return json.dumps(next(results))

        run.sql = observe
        with patch.object(runtime.time, "sleep") as sleep:
            result = run.wait_application_projection()
        self.assertEqual(result["verdict"], current)
        sleep.assert_called_once_with(1)
        self.assertEqual([database for _, database in queries], ["access_l2", "verdict_l2"] * 2)
        self.assertTrue(all(query.lstrip().startswith("SELECT") for query, _ in queries))

    def test_application_projection_timeout_never_passes(self):
        run = object.__new__(runtime.ClosedRun)
        run.application_request = {"application_sub": "application:abcdefghijklmnop"}
        with self.assertRaisesRegex(RuntimeError, "did not converge"):
            run.wait_application_projection(timeout=0)

    def test_application_projection_rejects_invalid_subject_before_database(self):
        run = object.__new__(runtime.ClosedRun)
        run.application_request = {"application_sub": "application:invalid'"}
        run.sql = lambda *_: self.fail("invalid subject reached the database")
        with self.assertRaisesRegex(RuntimeError, "invalid application subject"):
            run.wait_application_projection()

    def test_failed_command_keeps_service_stdout_and_runtime_stderr_redacted(self):
        run = object.__new__(runtime.ClosedRun)
        secret = "closed-command-secret-" + "a" * 32
        run.env = {"L2_TEST_SECRET": secret}
        with self.assertRaises(RuntimeError) as caught:
            run.command([sys.executable, "-c",
                         "import sys; print('service configuration rejected ' + sys.argv[1]); "
                         "print('container created ' + sys.argv[1], file=sys.stderr); sys.exit(1)",
                         secret])
        message = str(caught.exception)
        self.assertIn("service configuration rejected [redacted]", message)
        self.assertIn("container created [redacted]", message)
        self.assertNotIn(secret, message)

    def test_registration_tls_has_separate_leaf_owners_and_purposes(self):
        with tempfile.TemporaryDirectory() as directory:
            run = object.__new__(runtime.ClosedRun)
            run.work = Path(directory)
            run.env = {}
            run.registration_tls()
            root = run.work / "registration"
            for name, uid, purpose in [("server", 65532, "sslserver"), ("client", 1000, "sslclient")]:
                key = root / f"{name}.key"
                self.assertEqual(key.stat().st_uid, uid)
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
                run.command(["openssl", "verify", "-CAfile", str(root / "ca.crt"),
                             "-purpose", purpose, str(root / f"{name}.crt")])
            run.command(["openssl", "x509", "-in", str(root / "server.crt"),
                         "-noout", "-checkhost", "closed-registration"])
            self.assertFalse((root / "ca.key").exists())

    def test_registration_compose_is_private_and_requires_all_client_settings(self):
        text = (ROOT / "compose.closed.yml").read_text()
        registration = text.split("  closed-registration:\n", 1)[1].split("\n  acceptance:", 1)[0]
        self.assertIn("${L2_NODE_IMAGE:", registration)
        self.assertIn("networks: [closed]", registration)
        self.assertNotIn("ports:", registration)
        self.assertNotIn("ca.key", text)
        self.assertNotIn("client.key", registration)
        access = text.split("  access:\n", 1)[1].split("\n  sluice:", 1)[0]
        self.assertNotIn("server.key", access)
        self.assertIn("KEYSTONE_REGISTRATION_URL: https://closed-registration:9443", access)
        self.assertIn('KEYSTONE_REGISTRATION_POLL_INTERVAL_SECONDS: "2"', access)
        for field in ["MTLS_CA", "MTLS_CERT", "MTLS_KEY", "MAC_KID", "MAC_KEY"]:
            self.assertIn("KEYSTONE_REGISTRATION_" + field + ":", access)

    def test_closed_access_uses_the_frozen_quorum_in_all_profiles(self):
        text = (ROOT / "compose.closed.yml").read_text()
        access = text.split("  access:\n", 1)[1].split("\n  sluice:", 1)[0]
        self.assertIn('ACCESS_GOVERNANCE_DEFAULT_APPROVERS: "user:u_admin,user:w33d"', access)
        self.assertNotIn("ACCESS_GOVERNANCE_DEFAULT_APPROVERS: ${L2_TEST_OWNER_SUBJECT}", access)

    def test_registration_observation_requires_real_worker_ack_and_fresh_cycle(self):
        run = object.__new__(runtime.ClosedRun)
        run.env = {"L2_REGISTRATION_SUBJECTS_JSON": '["user:u_admin","user:w33d"]'}
        run.sql = lambda _: ""
        with self.assertRaisesRegex(RuntimeError, "registration worker"):
            run.registration_snapshot(timeout=0)

    def test_cutover_waits_for_observed_legacy_lease_expiry_without_database_writes(self):
        run = object.__new__(runtime.ClosedRun)
        observations = iter([
            {"pending_events": 0, "has_error": False, "lease_active": True},
            {"pending_events": 0, "has_error": False, "lease_active": False},
        ])
        queries = []

        def observe(query):
            queries.append(query)
            return json.dumps(next(observations))

        run.sql = observe
        with patch.object(runtime.time, "sleep") as sleep:
            run.wait_legacy_writer_drain()
        sleep.assert_called_once_with(1)
        self.assertEqual(len(queries), 2)
        self.assertTrue(all(query.lstrip().startswith("SELECT") for query in queries))

    def test_cutover_never_waits_past_pending_events_or_worker_errors(self):
        run = object.__new__(runtime.ClosedRun)
        for state in [{"pending_events": 1, "has_error": False, "lease_active": False},
                      {"pending_events": 0, "has_error": True, "lease_active": False}]:
            with self.subTest(state=state), patch.object(runtime.time, "sleep") as sleep:
                run.sql = lambda _: json.dumps(state)
                with self.assertRaisesRegex(RuntimeError, "undrained events or worker errors"):
                    run.wait_legacy_writer_drain()
                sleep.assert_not_called()

    def test_cutover_live_lease_timeout_cannot_be_reported_as_drained(self):
        run = object.__new__(runtime.ClosedRun)
        run.sql = lambda _: json.dumps({"pending_events": 0, "has_error": False, "lease_active": True})
        with self.assertRaisesRegex(RuntimeError, "lease did not expire"):
            run.wait_legacy_writer_drain(timeout=0)

    def test_birthright_waits_for_actual_assignments_and_projection(self):
        run = object.__new__(runtime.ClosedRun)
        states = iter([{"subjects": 3, "active": 1, "failed": 0},
                       {"subjects": 3, "active": 3, "failed": 0}])
        queries = []

        def observe(query):
            queries.append(query)
            return json.dumps(next(states))

        run.sql = observe
        with patch.object(runtime.time, "sleep") as sleep:
            run.wait_birthright_projection(3)
        sleep.assert_called_once_with(1)
        self.assertEqual(len(queries), 2)
        for query in queries:
            self.assertTrue(query.lstrip().startswith("SELECT"))
            self.assertIn("grant_projection", query)
            self.assertIn("effective_writer_epoch", query)

    def test_birthright_projection_wait_rejects_errors_extra_subjects_and_timeout(self):
        run = object.__new__(runtime.ClosedRun)
        cases = [({"subjects": 3, "active": 3, "failed": 1}, "worker or projection failed"),
                 ({"subjects": 4, "active": 3, "failed": 0}, "subject count drift"),
                 ({"subjects": 3, "active": 2, "failed": 0}, "projection did not finish")]
        for state, message in cases:
            with self.subTest(state=state), patch.object(runtime.time, "sleep") as sleep:
                run.sql = lambda _: json.dumps(state)
                with self.assertRaisesRegex(RuntimeError, message):
                    run.wait_birthright_projection(3, timeout=0)
                sleep.assert_not_called()

    def test_bootstrap_does_not_promote_package_by_fixture_sql(self):
        run = object.__new__(runtime.ClosedRun)
        queries = []

        def read_only_catalog(query, database="access_l2"):
            queries.append(query)
            if not query.lstrip().startswith("SELECT"):
                raise RuntimeError("fixture wrote catalog outside promotion workflow")
            return ""

        run.sql = read_only_catalog
        with self.assertRaisesRegex(RuntimeError, "catalog must be promoted"):
            run.bootstrap_approver()
        self.assertEqual(len(queries), 1)
        self.assertIn("requestable=TRUE", queries[0])

    def test_private_json_publish_is_complete_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "receipt.json"
            value = {"status": "runtime_verified", "release_eligible": False}
            runtime.write_private_json(output, value)
            self.assertEqual(json.loads(output.read_text()), value)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(output.stat().st_nlink, 1)
            with self.assertRaises(FileExistsError):
                runtime.write_private_json(output, {"status": "replacement"})
            self.assertEqual(json.loads(output.read_text()), value)
            self.assertEqual(list(root.iterdir()), [output])

    def test_failed_json_serialization_does_not_publish_partial_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(TypeError):
                runtime.write_private_json(root / "receipt.json", {"unserializable": object()})
            self.assertEqual(list(root.iterdir()), [])

    def test_scope_digest_matches_access_domain_separated_vector(self):
        self.assertEqual(runtime.scopes_digest([
            "analysis.create", "analysis.read", "analysis.conversation", "analysis.upload.cancel"]),
            "90bca2399878c0977cc9b6c291641a9ff77059b8e1cbd6ac1143697dd233e964")

    def test_private_dial_preserves_tls_sni_and_hostname_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=closed-test",
                            "-addext", "subjectAltName=DNS:analyze.w33d.xyz",
                            "-keyout", str(root / "test.key"), "-out", str(root / "test.crt")],
                           check=True, capture_output=True)
            names = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / "test.crt", root / "test.key")
            context.sni_callback = lambda sock, name, original: names.append(name)
            server = ThreadingHTTPServer(("127.0.0.1", 0), LiveProbeHandler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            run = object.__new__(runtime.ClosedRun)
            run.work = root
            run.address = lambda _: "127.0.0.1"
            try:
                response = run.request("peer", server.server_port, "/readyz", tls=True,
                                       host="analyze.w33d.xyz")
                self.assertEqual(response[0], 200)
                self.assertEqual(names, ["analyze.w33d.xyz"])
                with self.assertRaises(ssl.SSLCertVerificationError):
                    run.request("peer", server.server_port, "/readyz", tls=True, host="id.w33d.xyz")
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_topology_and_native_checks_cannot_be_promoted_to_full_acceptance(self):
        observed = {"closed_topology": {"status": "pass", "checks": ["actual containers"],
                                       "started_at": 1, "finished_at": 2}}
        with self.assertRaisesRegex(RuntimeError, "application_approval.*mcp_four_tools"):
            runtime.require_complete(observed)

    def test_fixed_pass_flags_without_observations_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "no observed checks"):
            runtime.require_complete({name: {"status": "pass"} for name in runtime.REQUIRED_SCENARIOS})

    def test_build_fingerprint_changes_when_uncommitted_input_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            source = root / "src/main.rs"
            source.write_text("fn main() {}")
            before = runtime.source_digest(root)
            source.write_text("fn main() { panic!(); }")
            self.assertNotEqual(before, runtime.source_digest(root))

    def test_http_probe_observes_real_status_and_bounds_response(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LiveProbeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        run = object.__new__(runtime.ClosedRun)
        run.address = lambda _: "127.0.0.1"
        try:
            status, _, body = run.request("service", server.server_port, "/readyz")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"status": "ready"})
            self.assertEqual(run.request("service", server.server_port, "/unavailable")[0], 503)
            with self.assertRaisesRegex(RuntimeError, "exceeded bound"):
                run.request("service", server.server_port, "/large")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
