import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from .test_l2_runtime import runtime


class QuorumBootstrapTests(unittest.TestCase):
    @staticmethod
    def receipts(authority, idempotency):
        base = {"schema_version": 1, "schema": "w33d.access.approval-quorum-bootstrap-receipt.v1", "mode": "commit",
                "subjects": authority["subjects"], "permissions": authority["permissions"],
                "grant_ids": ["grt_closed_admin", "grt_closed_w33d"],
                "grant_expires_at": authority["grant_expires_at"], "requests_consumed": 0,
                "human_approvals_created": 0, "authority_payload_sha256": "c" * 64,
                "signature_sha256": "d" * 64, "signing_key_sha256": "e" * 64,
                "idempotency_key_sha256": hashlib.sha256(idempotency.encode()).hexdigest()}
        return [{**base, "created": True}, {**base, "created": False}]

    def run_fixture(self):
        run = object.__new__(runtime.ClosedRun)
        run.run_id = "a" * 24
        run.env = {"L2_POSTGRES_PASSWORD": "closed-test-password-" + "a" * 32}
        run.observations = {"catalog_prerequisites": {"status": "pass"}}
        run.registration_snapshot = lambda: {"snapshot_id": "closed-snapshot", "digest": "b" * 64, "count": 3}
        run.address = lambda _: "127.0.0.1"
        return run

    def test_signed_bootstrap_verifies_actual_signature_and_cleans_private_bundle(self):
        run = self.run_fixture()
        original = run.command
        captured = []
        with tempfile.TemporaryDirectory() as directory:
            run.work = Path(directory)

            def command(args, **kwargs):
                if args[0] != str(run.work / "build/access/app/service"):
                    return original(args, **kwargs)
                env = kwargs["env"]
                prefix = "ACCESS_APPROVAL_QUORUM_BOOTSTRAP_"
                root = Path(env[prefix + "RELEASE_ROOT"])
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                for path in root.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                authority = json.loads(Path(env[prefix + "AUTHORITY_FILE"]).read_text())
                self.assertEqual(authority["signing_key_sha256"], runtime.digest(root / "public.pem"))
                self.assertEqual(authority["idempotency_key_sha256"], hashlib.sha256(b"closed-genesis").hexdigest())
                self.assertEqual(env["STEADHOLME_PROFILE"], "dev")
                self.assertEqual(env[prefix + "ENVIRONMENT"], "closed-acceptance")
                original(["openssl", "dgst", "-sha256", "-verify", str(root / "public.pem"),
                          "-signature", str(root / "authority.sig"), str(root / "authority.json")])
                captured.append(root)
                return json.dumps({"created": len(captured) == 1, "schema": "w33d.access.approval-quorum-bootstrap-receipt.v1",
                    "mode": "commit", "authority_payload_sha256": runtime.digest(root / "authority.json"),
                    "signature_sha256": runtime.digest(root / "authority.sig"),
                    "signing_key_sha256": authority["signing_key_sha256"],
                    "idempotency_key_sha256": authority["idempotency_key_sha256"]})

            run.command = command
            result = run.signed_bootstrap("system-bootstrap-approval-quorum", {"schema": "signing-test"},
                                          "closed-genesis", environment={"STEADHOLME_PROFILE": "dev",
                                          "ACCESS_APPROVAL_QUORUM_BOOTSTRAP_ENVIRONMENT": "closed-acceptance"})
        self.assertEqual([receipt["created"] for receipt in result], [True, False])
        self.assertEqual(captured[0], captured[1])
        self.assertFalse(captured[0].exists())

    def test_signed_bootstrap_cleans_bundle_on_cli_error_or_unbound_receipt(self):
        for fail_cli in [True, False]:
            with self.subTest(fail_cli=fail_cli), tempfile.TemporaryDirectory() as directory:
                run = self.run_fixture()
                run.work = Path(directory)
                original = run.command
                roots = []

                def command(args, **kwargs):
                    if args[0] != str(run.work / "build/access/app/service"):
                        return original(args, **kwargs)
                    roots.append(Path(kwargs["env"]["ACCESS_APPROVAL_QUORUM_BOOTSTRAP_RELEASE_ROOT"]))
                    if fail_cli:
                        raise RuntimeError("injected closed CLI error")
                    return json.dumps({"created": True, "schema": "wrong-authority"})

                run.command = command
                with self.assertRaisesRegex(RuntimeError, "closed CLI error|exact authority bundle"):
                    run.signed_bootstrap("system-bootstrap-approval-quorum", {"schema": "signing-test"}, "closed-genesis")
                self.assertTrue(roots)
                self.assertTrue(all(not root.exists() for root in roots))

    def test_genesis_requires_real_parity_before_signing(self):
        run = self.run_fixture()
        run.observations = {}
        with patch.object(runtime.ClosedRun, "signed_bootstrap") as signing:
            with self.assertRaisesRegex(RuntimeError, "catalog prerequisites"):
                run.bootstrap_quorum()
            signing.assert_not_called()

    def test_genesis_refuses_open_catalog_before_signing(self):
        run = self.run_fixture()
        run.sql = lambda query: json.dumps({"epoch": 1, "generation": 2} if "FROM effective_writer_epoch" in query
                                           else {"requestable": 1})
        with patch.object(runtime.ClosedRun, "signed_bootstrap") as signing:
            with self.assertRaisesRegex(RuntimeError, "after catalog promotion"):
                run.bootstrap_quorum()
            signing.assert_not_called()

    def test_genesis_rejects_wider_scope_human_votes_and_non_idempotent_receipts(self):
        mutations = [lambda pair: pair[0].update(permissions=["access.approval.decide", "access.grant.create"]),
                     lambda pair: pair[0].update(human_approvals_created=1),
                     lambda pair: pair[0].update(requests_consumed=1),
                     lambda pair: pair[1].update(created=True),
                     lambda pair: pair[0].update(grant_expires_at=pair[0]["grant_expires_at"] + 1),
                     lambda pair: pair[0].update(extra="unexpected")]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                run = self.run_fixture()
                run.sql = lambda query: json.dumps({"epoch": 1, "generation": 2} if "FROM effective_writer_epoch" in query
                                                   else {"requestable": 0, "grants": 4})

                def sign(command, authority, idempotency, **kwargs):
                    pair = self.receipts(authority, idempotency)
                    mutate(pair)
                    return pair

                run.signed_bootstrap = sign
                with self.assertRaisesRegex(RuntimeError, "authorized closed scope"):
                    run.bootstrap_quorum()

    def test_genesis_rejects_extra_votes_or_unexpected_grant_count(self):
        for change in [{"approval_decisions": 1, "grants": 6}, {"approval_decisions": 0, "grants": 7}]:
            with self.subTest(change=change):
                run = self.run_fixture()
                calls = 0

                def query(sql):
                    nonlocal calls
                    if "FROM effective_writer_epoch" in sql:
                        return json.dumps({"epoch": 1, "generation": 2})
                    calls += 1
                    return json.dumps({"requestable": 0, "grants": 4, "roles": 1, "approval_decisions": 0}
                                      if calls == 1 else {"requestable": 0, "roles": 2, **change})

                run.sql = query
                run.signed_bootstrap = lambda command, authority, idempotency, **kwargs: self.receipts(authority, idempotency)
                with self.assertRaisesRegex(RuntimeError, "changed requests, votes, credentials or catalog"):
                    run.bootstrap_quorum()
                self.assertEqual(calls, 2)

    def test_existing_analyze_signer_remains_a_separate_non_grant_ceremony(self):
        run = self.run_fixture()
        results = iter([json.dumps({"id": "apr_closed", "digest": "b" * 64}),
                        "[0,0,0,0,6]", "[0,0,0,0,6]"])
        run.sql = lambda query: next(results)

        def sign(command, authority, idempotency, **kwargs):
            self.assertEqual(command, "system-bootstrap-analyze-approver")
            self.assertEqual(authority["principal"], "service:access-governance-analyze-approval")
            self.assertEqual(authority["package_id"], "pkg_analyze_mcp_client")
            self.assertEqual(authority["quota_tier"], "mvp-default-v1")
            self.assertNotIn("subjects", authority)
            self.assertNotIn("permissions", authority)
            self.assertNotIn("grant_expires_at", authority)
            self.assertEqual(kwargs, {})
            return [{"created": True, "requests_consumed": 0}, {"created": False, "requests_consumed": 0}]

        run.signed_bootstrap = sign
        with patch("builtins.print"):
            run.bootstrap_approver()
        self.assertTrue(run.bootstrap_receipt["created"])

    def test_genesis_binds_snapshot_writer_and_only_two_finite_system_grants(self):
        run = self.run_fixture()
        queries = []
        counts = {"requests": 0, "approval_decisions": 0, "application_requests": 0,
                  "application_decisions": 0, "application_principals": 0, "application_credentials": 0,
                  "grants": 4, "roles": 1, "requestable": 0}
        count_calls = 0
        projection_calls = 0

        def query(sql, database="access_l2"):
            nonlocal count_calls, projection_calls
            queries.append(sql)
            self.assertTrue(sql.lstrip().startswith("SELECT"))
            if "FROM effective_writer_epoch" in sql:
                return json.dumps({"epoch": 1, "generation": 2})
            if "FROM application_request" in sql:
                count_calls += 1
                return json.dumps({**counts, "grants": 4 if count_calls == 1 else 6,
                                   "roles": 1 if count_calls == 1 else 2})
            projection_calls += 1
            return json.dumps({"grants": 2, "exact": 2, "projected": 0 if projection_calls == 1 else 2, "failed": 0})

        def sign(command, authority, idempotency, **kwargs):
            self.assertEqual(command, "system-bootstrap-approval-quorum")
            self.assertEqual(authority["environment"], "closed-acceptance")
            self.assertEqual(authority["subjects"], ["user:u_admin", "user:w33d"])
            self.assertEqual(authority["permissions"], ["access.approval.decide"])
            self.assertEqual(authority["registration_snapshot_id"], "closed-snapshot")
            self.assertEqual(authority["registration_snapshot_digest"], "b" * 64)
            self.assertEqual((authority["writer_epoch"], authority["writer_generation"]), (1, 2))
            self.assertEqual(authority["grant_expires_at"] - authority["issued_at"], 691200)
            self.assertEqual(authority["expires_at"] - authority["issued_at"], 300)
            return self.receipts(authority, idempotency)

        run.sql = query
        run.signed_bootstrap = sign
        with patch.object(runtime.time, "sleep") as sleep, patch("builtins.print"):
            run.bootstrap_quorum()
        sleep.assert_called_once_with(1)
        self.assertEqual(projection_calls, 2)
        self.assertEqual(run.observations["quorum_genesis"]["status"], "pass")
        self.assertTrue(all("UPDATE " not in sql and "INSERT " not in sql for sql in queries))


if __name__ == "__main__":
    unittest.main()
