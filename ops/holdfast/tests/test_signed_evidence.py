from __future__ import annotations

import hashlib
import json
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

    def test_edge_cutover_binds_pages_detach_cloudflare_purge_and_dual_stack_probes(self) -> None:
        release_env = self.root / "edge.release.env"
        release_env.write_text(
            f"AUTHORITY_PUBLIC_KEY_SHA256={sha256(self.public_key)}\n", encoding="utf-8"
        )
        release_evidence = self.root / "edge-release-evidence.json"
        release_evidence.write_text("{}\n", encoding="utf-8")
        open_evidence = self.root / "edge-open.json"
        open_evidence.write_text(json.dumps({"source_grant_id": "source-grant-0001"}), encoding="utf-8")
        prepare_receipt = self.root / "OPEN-PREPARE.receipt"
        prepare_receipt.write_text("prepared_at=2026-08-22T02:00:00Z\n", encoding="utf-8")
        value = {
            "schema_version": 1,
            "ceremony": "holdfast-rikune-edge-cutover-v1",
            "issued_at": "2026-08-22T02:30:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "open_evidence_sha256": sha256(open_evidence),
            "source_grant_id": "source-grant-0001",
            "open_prepare_receipt_sha256": sha256(prepare_receipt),
            "github_pages_preflight": {
                "repository": "Last-emo-boy/rikune",
                "source_branch": "main",
                "source_path": "/docs",
                "cname": "rikune.w33d.xyz",
                "status": "built",
                "api_response_sha256": "1" * 64,
                "observed_at": "2026-08-22T01:59:00Z",
            },
            "github_pages_detach": {
                "method": "PUT",
                "path": "/repos/Last-emo-boy/rikune/pages",
                "api_version": "2026-03-10",
                "request_body_sha256": "2" * 64,
                "response_status": 204,
                "completed_at": "2026-08-22T02:05:00Z",
                "post_get_sha256": "3" * 64,
                "post_cname": None,
            },
            "cloudflare": {
                "token_secret_path": "/secure/release/cloudflare-rikune.token",
                "token_scopes": ["Cache Purge", "DNS Write"],
                "zone_id_sha256": "4" * 64,
                "record_id_sha256": "5" * 64,
                "pre_record_sha256": "6" * 64,
                "post_record_sha256": "e" * 64,
                "patch_method": "PATCH",
                "patch_path_sha256": "7" * 64,
                "patch_request_sha256": "8" * 64,
                "patch_response_sha256": "9" * 64,
                "patched_at": "2026-08-22T02:10:00Z",
                "origin": "w33d-sluice-ingress",
                "pre_ttl_seconds": 300,
                "post_ttl_seconds": 300,
                "ttl_wait_seconds": 300,
                "ttl_converged_at": "2026-08-22T02:15:00Z",
                "purge_method": "POST",
                "purge_request_sha256": "a" * 64,
                "purge_response_id": "cloudflare-purge-0001",
                "purge_response_sha256": "b" * 64,
                "purged_at": "2026-08-22T02:12:00Z",
            },
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T02:20:00Z",
                    "status": 302,
                    "cache_control": "private, no-store",
                    "github_request_id": None,
                    "proxy_cache": None,
                    "fastly_via": None,
                    "origin": "sluice-strad",
                    "response_headers_sha256": digest * 64,
                }
                for family, digest in (("ipv4", "c"), ("ipv6", "d"))
            ],
        }
        evidence = self.root / "edge.json"
        evidence.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        signature = self.sign(evidence)
        command = [
            "python3", str(OPS_ROOT / "edge_evidence.py"), "--mode", "cutover",
            "--evidence", str(evidence), "--signature", str(signature),
            "--public-key", str(self.public_key), "--release-env", str(release_env),
            "--release-evidence", str(release_evidence), "--open-evidence", str(open_evidence),
            "--prepare-receipt", str(prepare_receipt),
        ]
        valid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        route_receipt = self.root / "EDGE-ROUTE-CLOSE.receipt"
        route_receipt.write_text("route_closed_at=2026-08-22T02:35:00Z\n", encoding="utf-8")
        revocation = self.root / "edge-revocation.json"
        revocation.write_text(json.dumps({"issued_at": "2026-08-22T02:40:00Z"}), encoding="utf-8")
        rollback_value = {
            "schema_version": 1,
            "ceremony": "holdfast-rikune-edge-rollback-v1",
            "issued_at": "2026-08-22T03:00:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "open_edge_evidence_sha256": sha256(evidence),
            "route_close_receipt_sha256": sha256(route_receipt),
            "revocation_evidence_sha256": sha256(revocation),
            "github_pages_restore": {
                "method": "PUT",
                "path": "/repos/Last-emo-boy/rikune/pages",
                "api_version": "2026-03-10",
                "request_body_sha256": "f" * 64,
                "response_status": 204,
                "completed_at": "2026-08-22T02:41:00Z",
                "post_get_sha256": "0" * 64,
                "post_cname": "rikune.w33d.xyz",
                "source_branch": "main",
                "source_path": "/docs",
            },
            "cloudflare_restore": {
                "token_secret_path": "/secure/release/cloudflare-rikune.token",
                "token_scopes": ["Cache Purge", "DNS Write"],
                "zone_id_sha256": "4" * 64,
                "record_id_sha256": "5" * 64,
                "pre_record_sha256": "e" * 64,
                "post_record_sha256": "6" * 64,
                "patch_method": "PATCH",
                "patch_path_sha256": "7" * 64,
                "patch_request_sha256": "1" * 64,
                "patch_response_sha256": "2" * 64,
                "patched_at": "2026-08-22T02:42:00Z",
                "origin": "github-pages-original",
                "pre_ttl_seconds": 60,
                "post_ttl_seconds": 60,
                "ttl_wait_seconds": 60,
                "ttl_converged_at": "2026-08-22T02:43:00Z",
                "purge_method": "POST",
                "purge_request_sha256": "3" * 64,
                "purge_response_id": "cloudflare-rollback-purge-0001",
                "purge_response_sha256": "4" * 64,
                "purged_at": "2026-08-22T02:42:30Z",
            },
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T02:45:00Z",
                    "origin": "github-pages",
                    "cname": "rikune.w33d.xyz",
                    "response_headers_sha256": digest * 64,
                }
                for family, digest in (("ipv4", "5"), ("ipv6", "6"))
            ],
        }
        rollback_evidence = self.root / "edge-rollback.json"
        rollback_evidence.write_text(json.dumps(rollback_value, sort_keys=True), encoding="utf-8")
        rollback_signature = self.sign(rollback_evidence)
        rollback_command = [
            "python3", str(OPS_ROOT / "edge_evidence.py"), "--mode", "rollback",
            "--evidence", str(rollback_evidence), "--signature", str(rollback_signature),
            "--public-key", str(self.public_key), "--release-env", str(release_env),
            "--release-evidence", str(release_evidence), "--open-edge-evidence", str(evidence),
            "--route-close-receipt", str(route_receipt), "--revocation-evidence", str(revocation),
        ]
        rolled_back = subprocess.run(
            rollback_command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stdout + rolled_back.stderr)
        rollback_value["cloudflare_restore"]["post_record_sha256"] = "9" * 64
        rollback_evidence.write_text(json.dumps(rollback_value, sort_keys=True), encoding="utf-8")
        rollback_signature = self.sign(rollback_evidence)
        rollback_command[rollback_command.index("--signature") + 1] = str(rollback_signature)
        wrong_record = subprocess.run(
            rollback_command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.assertNotEqual(wrong_record.returncode, 0)
        self.assertIn("exact pre-cutover record", wrong_record.stderr)

        value["public_probes"][0]["github_request_id"] = "still-pages"
        evidence.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        signature = self.sign(evidence)
        command[command.index("--signature") + 1] = str(signature)
        invalid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("GitHub Pages/Fastly", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
