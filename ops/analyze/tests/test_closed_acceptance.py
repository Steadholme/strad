from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "l2-receipt.schema.json"
RECEIPT = ROOT / "evidence" / "l2-acceptance-v1.json"
FIXTURE = ROOT / "fixtures" / "oidc-browser-v1.json"
COMPOSE = ROOT / "compose.closed.yml"
HARNESS = ROOT / "run-l2-acceptance.sh"
VALIDATOR = ROOT / "validate-l2-receipt.py"

SCENARIOS = [
    "closed_topology",
    "application_approval",
    "oidc_browser",
    "mcp_four_tools",
    "authorization_negatives",
    "credential_rotation",
    "online_revocation",
    "final_fence_barrier",
    "fault_recovery",
]

MISSING_DEPENDENCIES = [
    "postgresql",
    "analyzer_ghidra",
    "ed25519_keyring",
    "application_credential_pepper",
    "approval_worker_signing_key",
    "strad_facade_token",
    "strad_governance_reporting_token",
]


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class ClosedAcceptanceTests(unittest.TestCase):
    maxDiff = None

    def _assert_artifact(self, path: Path) -> None:
        self.assertTrue(path.is_file(), f"required L2 artifact is absent: {path}")

    def _ajv(self, document: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            json.dump(document, handle, separators=(",", ":"), sort_keys=True)
            candidate = Path(handle.name)
        try:
            return subprocess.run(
                [
                    str(ROOT / "node_modules" / ".bin" / "ajv"),
                    "validate",
                    "--spec=draft2020",
                    "--strict=true",
                    "-s",
                    str(SCHEMA),
                    "-d",
                    str(candidate),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        finally:
            candidate.unlink(missing_ok=True)

    def test_fixed_receipt_schema_rejects_open_skip_secret_and_slow_revoke(self) -> None:
        self._assert_artifact(SCHEMA)
        self._assert_artifact(RECEIPT)
        receipt = load_json(RECEIPT)
        self.assertEqual(self._ajv(receipt).returncode, 0)

        mutations = []
        opened = copy.deepcopy(receipt)
        opened["ingress_closed"] = False
        mutations.append(opened)
        skipped = copy.deepcopy(receipt)
        skipped["scenarios"][0]["status"] = "skip"
        mutations.append(skipped)
        leaked = copy.deepcopy(receipt)
        leaked["runtime_secret"] = "app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        mutations.append(leaked)
        slow = copy.deepcopy(receipt)
        slow["revocation"]["enforced_within_seconds"] = 31
        mutations.append(slow)
        for candidate in mutations:
            result = self._ajv(candidate)
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_sponsor_system_decision_origin_rotation_and_nonallow_audit_scenarios_required(self) -> None:
        self._assert_artifact(RECEIPT)
        receipt = load_json(RECEIPT)
        self.assertEqual(
            [scenario["name"] for scenario in receipt["scenarios"]], SCENARIOS
        )
        self.assertTrue(all(scenario["status"] == "pass" for scenario in receipt["scenarios"]))
        self.assertEqual(receipt["approval"]["sponsor"]["producer"], "sluice_live_trusted_mfa")
        self.assertEqual(receipt["approval"]["sponsor"]["consumed_count"], 1)
        self.assertEqual(receipt["approval"]["system_decision"]["consumed_count"], 1)
        self.assertEqual(receipt["approval"]["system_decision"]["ttl_seconds"], 300)
        self.assertFalse(receipt["approval"]["filesystem_assertion"])
        self.assertFalse(receipt["approval"]["direct_decision_injection"])
        self.assertEqual(receipt["authorization"]["non_allow_audit_count_each"], 1)
        self.assertEqual(receipt["authorization"]["non_allow_dispatch_count"], 0)
        self.assertTrue(receipt["credential"]["original_session_only_overlap"])
        self.assertTrue(receipt["credential"]["source_grant_cascade"])

    def test_oidc_browser_fixture_has_exact_resume_csrf_and_sponsor_claims(self) -> None:
        self._assert_artifact(FIXTURE)
        fixture = load_json(FIXTURE)
        self.assertEqual(
            list(fixture),
            [
                "schema_version",
                "origin",
                "oidc",
                "resume_path",
                "csrf",
                "cookie",
                "sponsor_assertion",
                "application_projection",
                "dom",
                "privacy",
            ],
        )
        self.assertEqual(fixture["origin"], "https://analyze.w33d.xyz")
        self.assertEqual(fixture["oidc"]["issuer"], "https://id.w33d.xyz")
        self.assertEqual(fixture["oidc"]["audience"], "access-governance")
        self.assertTrue(fixture["oidc"]["state_required"])
        self.assertTrue(fixture["oidc"]["nonce_required"])
        self.assertEqual(fixture["resume_path"], "/applications/")
        self.assertEqual(fixture["csrf"], {"json_header": "X-CSRF-Token", "html_field": "csrf_token"})
        self.assertEqual(fixture["sponsor_assertion"]["auth_time_max_age_seconds"], 300)
        self.assertEqual(fixture["sponsor_assertion"]["ttl_seconds"], 300)
        self.assertEqual(fixture["sponsor_assertion"]["session_binding"], "lowerhex64")
        self.assertEqual(fixture["application_projection"], ["pending_approval", "approved"])
        self.assertEqual(
            fixture["privacy"]["forbidden_recordings"], ["passkey", "cookie_value", "token"]
        )

    def test_compose_is_internal_only_and_contains_exact_services(self) -> None:
        self._assert_artifact(COMPOSE)
        text = COMPOSE.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)^\s*ports\s*:")
        self.assertRegex(text, r"(?ms)^networks:\s+closed:\s+internal:\s+true\s*$")
        for service in [
            "postgres",
            "access",
            "sluice",
            "verdict",
            "facade",
            "strad",
            "analyzer",
            "acceptance",
        ]:
            self.assertRegex(text, rf"(?m)^  {service}:\s*$")
        self.assertIn("read_only: true", text)
        self.assertIn("cap_drop: [ALL]", text)

    def test_harness_has_atomic_private_output_and_no_skip_path(self) -> None:
        self._assert_artifact(HARNESS)
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("umask 077", text)
        self.assertIn("mktemp", text)
        self.assertIn("chmod 0600", text)
        self.assertIn("mv --", text)
        self.assertNotRegex(text, r"(?i)\bskip(ped)?\b")
        self.assertNotIn("--publish", text)
        self.assertNotIn("-p 127.0.0.1", text)

    def test_semantic_validator_accepts_only_private_regular_receipt(self) -> None:
        self._assert_artifact(VALIDATOR)
        self._assert_artifact(RECEIPT)
        mode = stat.S_IMODE(RECEIPT.stat().st_mode)
        self.assertEqual(mode, 0o600)
        result = subprocess.run(
            ["python3", str(VALIDATOR), "--input", str(RECEIPT)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_all_missing_dependency_variants_fail_without_pass_receipt(self) -> None:
        self._assert_artifact(HARNESS)
        for dependency in MISSING_DEPENDENCIES:
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as temp_dir:
                output = Path(temp_dir) / "receipt.json"
                environment = os.environ.copy()
                environment["L2_FAULT_MISSING"] = dependency
                result = subprocess.run(
                    [
                        "bash",
                        str(HARNESS),
                        "--check-dependencies-only",
                        "--output",
                        str(output),
                    ],
                    cwd=ROOT.parent.parent,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(output.exists(), result.stdout)


if __name__ == "__main__":
    unittest.main()
