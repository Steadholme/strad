from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
PERMISSIONS = sorted(
    {
        "rikune.analysis.create",
        "rikune.analysis.delete",
        "rikune.analysis.promote",
        "rikune.analysis.read",
        "rikune.console.enter",
        "rikune.conversation.use",
        "rikune.upload.cancel",
    }
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SignedEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="holdfast-signature-test-")
        self.root = Path(self.temp.name)
        self.private_key = self.root / "authority.key"
        self.public_key = self.root / "authority.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private_key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private_key), "-pubout", "-out", str(self.public_key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def sign(self, document: Path) -> Path:
        signature = document.with_suffix(document.suffix + ".sig")
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key), "-out", str(signature), str(document)],
            check=True,
        )
        return signature

    def test_supply_chain_requires_signature_registry_materials_and_access_build_input(self) -> None:
        image_keys = (
            "ACCESS_GOVERNANCE_IMAGE",
            "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
            "RIKUNE_ANALYZER_IMAGE",
            "STRAD_ANALYZER_IMAGE",
            "STRAD_IMAGE",
            "STRAD_VOLUME_INIT_IMAGE",
            "STRAD_RUST_BUILDER_IMAGE",
            "STRAD_RUNTIME_IMAGE",
            "STRAD_NODE_BUILDER_IMAGE",
            "VERDICT_IMAGE",
            "NEWAPI_IMAGE",
            "SLUICE_IMAGE",
        )
        release: dict[str, str] = {
            key: f"registry.example/w33d/{key.lower()}@sha256:{index:064x}"
            for index, key in enumerate(image_keys, 1)
        }
        release["RIKUNE_ANALYZER_IMAGE"] = "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:" + "c" * 64
        release.update(
            {
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "1" * 64,
                "PERMISSION_CATALOG_SHA256": "2" * 64,
                "PACKAGE_CATALOG_SHA256": "3" * 64,
                "STRAD_REVISION": "4" * 40,
                "STRAD_NEWAPI_MODEL": "exact-alias",
                "AUTHORITY_PUBLIC_KEY_SHA256": sha256(self.public_key),
                "SUPPLY_CHAIN_PUBLIC_KEY_SHA256": sha256(self.public_key),
                "SUPPLY_CHAIN_EVIDENCE_SHA256": "0" * 64,
                "SUPPLY_CHAIN_SIGNATURE_SHA256": "0" * 64,
            }
        )
        canonical = "".join(
            f"{key}={release[key]}\n"
            for key in sorted(release)
            if key not in {"SUPPLY_CHAIN_EVIDENCE_SHA256", "SUPPLY_CHAIN_SIGNATURE_SHA256"}
        )
        registry_images = {}
        for key in image_keys:
            image = release[key]
            subject = image.rsplit("@", 1)[1]
            registry_images[key] = {
                "image": image,
                "manifest_digest": subject,
                "registry": image.split("/", 1)[0],
                "subject_digest": subject,
                "sbom": {"uri": "oci://evidence/sbom", "sha256": "5" * 64},
                "provenance": {"uri": "oci://evidence/provenance", "sha256": "6" * 64, "builder_id": "builder:trusted"},
                "attestation": {"uri": "oci://evidence/attestation", "sha256": "7" * 64},
                "signature": {"identity": "release@example.invalid", "issuer": "https://issuer.example", "rekor_log_index": 1},
            }
        evidence_value = {
            "schema_version": 1,
            "issued_at": "2026-08-22T00:00:00Z",
            "platform": "linux/amd64",
            "release_pins_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "registry_verification": {"verified_at": "2026-08-22T00:00:00Z", "verifier": "cosign-policy-v1", "images": registry_images},
            "analyzer_overlay": {
                "base_image": release["RIKUNE_ANALYZER_IMAGE"],
                "overlay_image": release["STRAD_ANALYZER_IMAGE"],
                "dockerfile_sha256": sha256(OPS_ROOT.parents[1] / "Dockerfile.analyzer"),
                "bridge_lock_sha256": sha256(OPS_ROOT.parents[1] / "bridge/package-lock.json"),
                "static_lock_sha256": "32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef",
                "source_revision": release["STRAD_REVISION"],
            },
            "access_candidate": {
                "image": release["ACCESS_GOVERNANCE_IMAGE"],
                "build_input_sha256": release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
                "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
                "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
                "source_revision": release["STRAD_REVISION"],
            },
        }
        evidence = self.root / "supply.json"
        evidence.write_text(json.dumps(evidence_value, sort_keys=True), encoding="utf-8")
        signature = self.sign(evidence)
        release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = sha256(evidence)
        release["SUPPLY_CHAIN_SIGNATURE_SHA256"] = sha256(signature)
        release_env = self.root / "release.env"
        release_env.write_text("".join(f"{key}={value}\n" for key, value in release.items()), encoding="utf-8")
        command = [
            "python3",
            str(OPS_ROOT / "supply_chain_evidence.py"),
            "--release-env",
            str(release_env),
            "--evidence",
            str(evidence),
            "--signature",
            str(signature),
            "--public-key",
            str(self.public_key),
            "--dockerfile",
            str(OPS_ROOT.parents[1] / "Dockerfile.analyzer"),
            "--bridge-lock",
            str(OPS_ROOT.parents[1] / "bridge/package-lock.json"),
        ]
        valid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        evidence_value["access_candidate"]["build_input_sha256"] = "f" * 64
        evidence.write_text(json.dumps(evidence_value, sort_keys=True), encoding="utf-8")
        invalid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(invalid.returncode, 0)

    def test_authority_rollback_proves_route_close_then_same_grant_then_tombstones(self) -> None:
        release_env = self.root / "authority.release.env"
        release = {
            "AUTHORITY_PUBLIC_KEY_SHA256": sha256(self.public_key),
            "ACCESS_GOVERNANCE_IMAGE": "registry.example/access@sha256:" + "1" * 64,
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "2" * 64,
            "PERMISSION_CATALOG_SHA256": "3" * 64,
            "PACKAGE_CATALOG_SHA256": "4" * 64,
        }
        release_env.write_text("".join(f"{key}={value}\n" for key, value in release.items()), encoding="utf-8")
        release_evidence = self.root / "release-evidence.json"
        release_evidence.write_text(json.dumps({"release_env_sha256": sha256(release_env)}), encoding="utf-8")
        dry_receipt = self.root / "DRY-RUN.receipt"
        dry_receipt.write_text("cargo_gate=passed\n", encoding="utf-8")
        open_value = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-open-v2",
            "issued_at": "2026-08-22T00:10:00Z",
            "expires_at": "2026-09-21T00:10:00Z",
            "release_env_sha256": sha256(release_env),
            "release_evidence_sha256": sha256(release_evidence),
            "dry_run_receipt_sha256": sha256(dry_receipt),
            "signature_key_sha256": sha256(self.public_key),
            "candidate_image_digest": release["ACCESS_GOVERNANCE_IMAGE"],
            "build_input_sha256": release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "bootstrap_version": 6,
            "package_id": "pkg_rikune_analyst",
            "requestable_version": 2,
            "beneficiary": "user:rikune-acceptance",
            "promotion_ceremony_id": "promotion-ceremony-0001",
            "package_request_id": "package-request-0001",
            "source_grant_id": "source-grant-0001",
            "projection_edges": [
                {"permission": permission, "epoch": 1, "ack": True, "acknowledged_at": "2026-08-22T00:09:00Z"}
                for permission in PERMISSIONS
            ],
        }
        open_evidence = self.root / "open.json"
        open_evidence.write_text(json.dumps(open_value, sort_keys=True), encoding="utf-8")
        open_signature = self.sign(open_evidence)
        open_command = [
            "python3", str(OPS_ROOT / "authority_evidence.py"), "--mode", "open",
            "--evidence", str(open_evidence), "--signature", str(open_signature),
            "--public-key", str(self.public_key), "--release-env", str(release_env),
            "--release-evidence", str(release_evidence), "--dry-run-receipt", str(dry_receipt),
        ]
        opened = subprocess.run(open_command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(opened.returncode, 0, opened.stdout + opened.stderr)
        route_receipt = self.root / "ROUTE-CLOSE.receipt"
        route_receipt.write_text(
            f"route_closed_at=2026-08-22T01:00:00Z\nopen_evidence_sha256={sha256(open_evidence)}\nsource_grant_id=source-grant-0001\n",
            encoding="utf-8",
        )
        rollback_value = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-rollback-v2",
            "issued_at": "2026-08-22T01:20:00Z",
            "release_env_sha256": sha256(release_env),
            "release_evidence_sha256": sha256(release_evidence),
            "signature_key_sha256": sha256(self.public_key),
            "package_id": "pkg_rikune_analyst",
            "beneficiary": "user:rikune-acceptance",
            "source_grant_id": "source-grant-0001",
            "open_evidence_sha256": sha256(open_evidence),
            "route_close_receipt_sha256": sha256(route_receipt),
            "route_closed_at": "2026-08-22T01:00:00Z",
            "grant_revoked_at": "2026-08-22T01:10:00Z",
            "revocation_ceremony_id": "revocation-ceremony-0001",
            "projection_tombstones": [
                {"permission": permission, "epoch": 2, "ack": True, "acknowledged_at": "2026-08-22T01:15:00Z"}
                for permission in PERMISSIONS
            ],
        }
        rollback_evidence = self.root / "rollback.json"
        rollback_evidence.write_text(json.dumps(rollback_value, sort_keys=True), encoding="utf-8")
        rollback_signature = self.sign(rollback_evidence)
        command = [
            "python3", str(OPS_ROOT / "authority_evidence.py"), "--mode", "rollback",
            "--evidence", str(rollback_evidence), "--signature", str(rollback_signature),
            "--public-key", str(self.public_key), "--release-env", str(release_env),
            "--release-evidence", str(release_evidence), "--open-evidence", str(open_evidence),
            "--route-close-receipt", str(route_receipt),
        ]
        valid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        rollback_value["projection_tombstones"][0]["acknowledged_at"] = "2026-08-22T01:05:00Z"
        rollback_evidence.write_text(json.dumps(rollback_value, sort_keys=True), encoding="utf-8")
        rollback_signature = self.sign(rollback_evidence)
        command[command.index("--signature") + 1] = str(rollback_signature)
        invalid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("route close, grant revoke", invalid.stderr)

    def make_preopen_fixture(self):
        release_env = self.root / "edge.release.env"
        release_env.write_text(
            f"AUTHORITY_PUBLIC_KEY_SHA256={sha256(self.public_key)}\n", encoding="utf-8"
        )
        release_evidence = self.root / "edge-release-evidence.json"
        release_evidence.write_text("{}\n", encoding="utf-8")
        open_evidence = self.root / "edge-open.json"
        open_evidence.write_text(
            json.dumps({"source_grant_id": "source-grant-0001"}), encoding="utf-8"
        )
        prepare_receipt = self.root / "OPEN-PREPARE.receipt"
        prepare_receipt.write_text(
            "\n".join(
                (
                    "prepared_at=2026-08-22T02:00:00Z",
                    f"release_evidence_sha256={sha256(release_evidence)}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-0001",
                    "route_state=absent",
                    "public_host=analyze.w33d.xyz",
                    "edge_owner=existing-w33d-sluice",
                    "public_ipv4_ipv6_closed_status=404",
                    "db_public_db_bracket=absent-404-absent",
                    "external_edge_mutation=none",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        value = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-edge-preopen-v2",
            "issued_at": "2026-08-22T02:10:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "open_evidence_sha256": sha256(open_evidence),
            "source_grant_id": "source-grant-0001",
            "open_prepare_receipt_sha256": sha256(prepare_receipt),
            "host": "analyze.w33d.xyz",
            "edge_owner": "existing-w33d-sluice",
            "route_state": "absent",
            "external_edge_mutations": [],
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T02:05:00Z",
                    "url": "https://analyze.w33d.xyz/",
                    "status": 404,
                    "edge_owner": "existing-w33d-sluice",
                    "route_state": "absent",
                    "response_headers_sha256": digest * 64,
                }
                for family, digest in (("ipv4", "a"), ("ipv6", "b"))
            ],
        }
        evidence = self.root / "edge-preopen.json"
        command = [
            "python3",
            str(OPS_ROOT / "edge_evidence.py"),
            "--mode",
            "preopen",
            "--evidence",
            str(evidence),
            "--public-key",
            str(self.public_key),
            "--release-env",
            str(release_env),
            "--release-evidence",
            str(release_evidence),
            "--open-evidence",
            str(open_evidence),
            "--prepare-receipt",
            str(prepare_receipt),
        ]
        return value, evidence, command, release_env, release_evidence, open_evidence

    def run_signed_edge(self, value: dict[str, object], evidence: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
        evidence.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        signature = self.sign(evidence)
        return subprocess.run(
            [*command, "--signature", str(signature)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_edge_preopen_and_rollback_v2_bind_exact_dual_stack_404_state(self) -> None:
        value, evidence, command, release_env, release_evidence, open_evidence = self.make_preopen_fixture()
        valid = self.run_signed_edge(value, evidence, command)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        route_receipt = self.root / "EDGE-ROUTE-CLOSE.receipt"
        route_receipt.write_text(
            "\n".join(
                (
                    "route_closed_at=2026-08-22T03:00:00Z",
                    f"route_down_sha256={'c' * 64}",
                    f"route_down_execution_evidence_sha256={'9' * 64}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-0001",
                    "was_public_open=true",
                    f"preopen_edge_evidence_sha256={sha256(evidence)}",
                    f"route_preimage_sha256={'f' * 64}",
                    "route_conflict_cleanup=same-name-or-analyze-root",
                    "route_state=absent",
                    "public_host=analyze.w33d.xyz",
                    "edge_owner=existing-w33d-sluice",
                    "public_ipv4_ipv6_closed_status=404",
                    "db_public_db_bracket=absent-404-absent",
                    "external_edge_mutation=none",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        revocation = self.root / "edge-revocation.json"
        revocation.write_text(
            json.dumps(
                {
                    "issued_at": "2026-08-22T03:05:00Z",
                    "source_grant_id": "source-grant-0001",
                }
            ),
            encoding="utf-8",
        )
        rollback_value = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-edge-rollback-v2",
            "issued_at": "2026-08-22T03:15:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "preopen_edge_evidence_sha256": sha256(evidence),
            "route_close_receipt_sha256": sha256(route_receipt),
            "revocation_evidence_sha256": sha256(revocation),
            "source_grant_id": "source-grant-0001",
            "host": "analyze.w33d.xyz",
            "edge_owner": "existing-w33d-sluice",
            "route_state": "absent",
            "external_edge_mutations": [],
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T03:10:00Z",
                    "url": "https://analyze.w33d.xyz/",
                    "status": 404,
                    "edge_owner": "existing-w33d-sluice",
                    "route_state": "absent",
                    "response_headers_sha256": digest * 64,
                }
                for family, digest in (("ipv4", "d"), ("ipv6", "e"))
            ],
        }
        rollback_evidence = self.root / "edge-rollback.json"
        rollback_command = [
            "python3",
            str(OPS_ROOT / "edge_evidence.py"),
            "--mode",
            "rollback",
            "--evidence",
            str(rollback_evidence),
            "--public-key",
            str(self.public_key),
            "--release-env",
            str(release_env),
            "--release-evidence",
            str(release_evidence),
            "--open-edge-evidence",
            str(evidence),
            "--route-close-receipt",
            str(route_receipt),
            "--revocation-evidence",
            str(revocation),
        ]
        rolled_back = self.run_signed_edge(rollback_value, rollback_evidence, rollback_command)
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stdout + rolled_back.stderr)

    def test_edge_preopen_rejects_v1_pages_single_stack_wrong_status_host_and_mutation(self) -> None:
        value, evidence, command, *_ = self.make_preopen_fixture()
        cases: list[tuple[str, dict[str, object], str]] = []

        old_pages = json.loads(json.dumps(value))
        old_pages["schema_version"] = 1
        old_pages["ceremony"] = "holdfast-rikune-edge-cutover-v1"
        old_pages["github_pages_preflight"] = {
            "repository": "Last-emo-boy/rikune",
            "cname": "rikune.w33d.xyz",
        }
        cases.append(("old Pages schema", old_pages, "v2 ceremony"))

        single_stack = json.loads(json.dumps(value))
        single_stack["public_probes"] = single_stack["public_probes"][:1]
        cases.append(("single stack", single_stack, "exactly one IPv4 and one IPv6"))

        wrong_status = json.loads(json.dumps(value))
        wrong_status["public_probes"][0]["status"] = 200
        cases.append(("wrong closed status", wrong_status, "exact 404"))

        wrong_host = json.loads(json.dumps(value))
        wrong_host["host"] = "rikune.w33d.xyz"
        cases.append(("wrong host", wrong_host, "host is not analyze.w33d.xyz"))

        mutated_edge = json.loads(json.dumps(value))
        mutated_edge["external_edge_mutations"] = ["cloudflare-dns-patch"]
        cases.append(("external mutation", mutated_edge, "must not claim GitHub Pages"))

        for label, candidate, expected_error in cases:
            with self.subTest(label=label):
                invalid = self.run_signed_edge(candidate, evidence, command)
                self.assertNotEqual(invalid.returncode, 0)
                self.assertIn(expected_error, invalid.stderr)

    def test_finalize_persists_armed_state_and_compensates_before_route_insert(self) -> None:
        script = (OPS_ROOT / "open-ingress.sh").read_text(encoding="utf-8")
        prepare_start = script.index('if [[ "$phase" == "prepare" ]]')
        finalize_start = script.index('[[ -n "$edge_evidence" && -n "$edge_signature" ]]', prepare_start)
        prepare_section = script[prepare_start:finalize_start]
        self.assertNotIn("20260823_rikune_root_up.sql", prepare_section)
        self.assertIn("verify_closed_bracket", prepare_section)
        self.assertIn("db_public_db_bracket=absent-404-absent", prepare_section)

        evidence_check = script.index('edge_evidence.py\" --mode preopen')
        compensation_trap = script.index("trap 'compensate_finalize")
        armed_state = script.index('.state="finalizing_route_armed"')
        mutation_guard = script.index('route_mutation_started="true"')
        route_insert = script.index("PGAPPNAME=holdfast-rikune-open-finalize psql")
        self.assertLess(evidence_check, compensation_trap)
        self.assertLess(compensation_trap, armed_state)
        self.assertLess(armed_state, mutation_guard)
        self.assertLess(mutation_guard, route_insert)

        compensation = script[script.index("compensate_finalize()"):route_insert]
        self.assertIn("force_route_absent", compensation)
        self.assertGreaterEqual(compensation.count("verify_database_absent"), 2)
        self.assertIn('public-origin-verify.sh\" --mode closed', compensation)
        self.assertIn("record_interrupted_state", compensation)
        self.assertIn("mark_compensation_unverified", compensation)
        self.assertIn('state="ingress_compensation_unverified"', script)

        armed_recovery = script.index('if [[ "$current_state" == "finalizing_route_armed" ]]')
        release_validation = script.index("validate_release_evidence.py")
        self.assertLess(armed_recovery, release_validation)
        recover_function = script[script.index("recover_armed_open()"):armed_recovery]
        self.assertLess(recover_function.index("force_route_absent"), recover_function.index("open_armed_prepare_receipt_sha256"))
        self.assertIn('holdfast_die "armed open was compensated', script)
        self.assertIn('"closed-state-route-present"', script)

        self.assertGreater(script.index("verify_open_bracket", route_insert), route_insert)
        self.assertIn("verify_database_absent\n  \"$script_dir/public-origin-verify.sh\" --mode closed", script)
        self.assertIn("verify_database_open\n  \"$script_dir/public-origin-verify.sh\" --mode open", script)

        rollback = (OPS_ROOT / "rollback.sh").read_text(encoding="utf-8")
        close_phase = rollback[rollback.index('if [[ "$phase" == "close-route" ]]'):]
        self.assertLess(close_phase.index("execute_frozen_route_down"), close_phase.index("current_state=$(jq"))
        self.assertLess(close_phase.index("verify_closed_bracket"), close_phase.index("validate_backup_and_open_authority"))
        self.assertIn("ROUTE-CLOSE-PREIMAGE.jsonl", rollback)
        self.assertIn("20260823_rikune_root_down.sql", rollback)
        self.assertNotIn("DELETE FROM routes", rollback)
        self.assertNotIn("row_to_json(snapshot)", rollback)
        self.assertIn("db_public_db_bracket=absent-404-absent", rollback)

        verifier = (OPS_ROOT / "public-origin-verify.sh").read_text(encoding="utf-8")
        self.assertIn("max_attempts=15", verifier)
        self.assertIn("retry_seconds=5", verifier)
        self.assertIn("--disable", verifier)
        self.assertIn("--header 'Cookie:' --header 'Authorization:'", verifier)
        self.assertIn('if [[ "$status" != "404" ]]', verifier)
        self.assertIn('if [[ "$status" != "302" ]]', verifier)
        self.assertIn("sso_location_pattern", verifier)
        self.assertIn("cache_controls", verifier)
        self.assertIn("strict-transport-security", verifier)
        self.assertIn("pages-or-fastly-marker", verifier)

    def test_compensation_persistence_failure_cannot_restore_prepared_state(self) -> None:
        script = (OPS_ROOT / "open-ingress.sh").read_text(encoding="utf-8")
        force_start = script.index("force_route_absent() {")
        force_end = script.index("\n}\n\nwrite_interrupted_receipt()", force_start) + 3
        force_function = script[force_start:force_end]
        probe_dir = self.root / "force-route-persistence-fault"
        probe_dir.mkdir()
        harness = f"""#!/usr/bin/env bash
set -u
{force_function}
state_dir=$1
script_dir=$2
ROUTES_DATABASE_URL=test
psql() {{ printf 'frozen down output\\n'; return 0; }}
chmod() {{ return 73; }}
mv() {{ command mv "$@"; }}
holdfast_sha256() {{ printf '%064d\\n' 0; }}
set +e
force_route_absent
exit $?
"""
        failed = subprocess.run(
            ["bash", "-c", harness, "holdfast-test", str(probe_dir), str(OPS_ROOT)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn("could not protect frozen route-down output", failed.stderr)

        compensation_start = script.index("compensate_finalize() {")
        route_insert = script.index("PGAPPNAME=holdfast-rikune-open-finalize psql", compensation_start)
        compensation = script[compensation_start:route_insert]
        self.assertIn("interrupted_receipt_status", compensation)
        self.assertIn("state_restore_status", compensation)
        self.assertIn("&& $interrupted_receipt_status -eq 0 && $state_restore_status -eq 0", compensation)
        self.assertLess(compensation.index("write_interrupted_receipt"), compensation.index("record_interrupted_state"))
        self.assertIn("if mark_compensation_unverified", compensation)
        self.assertIn("finalizing_route_armed was retained", compensation)

    def test_public_origin_modes_enforce_same_round_headers_status_and_sso_location(self) -> None:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
headers=""
family=""
while (($#)); do
  case "$1" in
    -4) family="4"; shift ;;
    -6) family="6"; shift ;;
    --dump-header) headers=$2; shift 2 ;;
    --max-time|--connect-timeout|--output|--write-out|--header) shift 2 ;;
    --disable|--silent|--show-error) shift ;;
    *) shift ;;
  esac
done
contract=${FAKE_PUBLIC_CONTRACT:?}
status=404
location=""
cache=""
extra_cache=""
include_hsts=true
marker=""
case "$contract" in
  closed) ;;
  open)
    status=302
    location="https://sso.w33d.xyz/authorize?client_id=sluice"
    cache="private, no-store"
    ;;
  bad-location)
    status=302
    location="https://evil.example/authorize"
    cache="private, no-store"
    ;;
  unsafe-cache)
    status=302
    location="https://sso.w33d.xyz/authorize?client_id=sluice"
    cache="private, no-store"
    extra_cache="public, max-age=60"
    ;;
  pages) marker="x-github-request-id: pages-still-active" ;;
  unsafe-closed) include_hsts=false ;;
  split-stack) [[ "$family" == "6" ]] && status=200 ;;
  *) exit 9 ;;
esac
{
  printf 'HTTP/2 %s\r\n' "$status"
  if [[ "$include_hsts" == "true" ]]; then
    printf 'strict-transport-security: max-age=31536000; includeSubDomains\r\n'
  fi
  printf 'x-content-type-options: nosniff\r\n'
  printf 'x-frame-options: SAMEORIGIN\r\n'
  printf 'referrer-policy: strict-origin-when-cross-origin\r\n'
  [[ -z "$location" ]] || printf 'location: %s\r\n' "$location"
  [[ -z "$cache" ]] || printf 'cache-control: %s\r\n' "$cache"
  [[ -z "$extra_cache" ]] || printf 'cache-control: %s\r\n' "$extra_cache"
  [[ -z "$marker" ]] || printf '%s\r\n' "$marker"
  printf '\r\n'
} >"$headers"
printf '%s' "$status"
""",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        def verify(contract: str, mode: str) -> subprocess.CompletedProcess[str]:
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "HOLDFAST_TEST_MODE": "1",
                "FAKE_PUBLIC_CONTRACT": contract,
            }
            return subprocess.run(
                [
                    str(OPS_ROOT / "public-origin-verify.sh"),
                    "--mode",
                    mode,
                    "--url",
                    "https://analyze.w33d.xyz/",
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

        for contract, mode in (("closed", "closed"), ("open", "open")):
            with self.subTest(contract=contract):
                result = verify(contract, mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        for contract, mode, error in (
            ("bad-location", "open", "untrusted-or-duplicate-location"),
            ("unsafe-cache", "open", "unsafe-cache-control"),
            ("pages", "closed", "pages-or-fastly-marker"),
            ("unsafe-closed", "closed", "unsafe-or-duplicate-hsts"),
            ("split-stack", "closed", "expected=404"),
        ):
            with self.subTest(contract=contract):
                result = verify(contract, mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)


if __name__ == "__main__":
    unittest.main()
