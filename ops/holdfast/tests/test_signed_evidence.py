from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import authority_evidence  # noqa: E402
import edge_evidence  # noqa: E402
import supply_chain_evidence  # noqa: E402

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
SUPPLY_IMAGE_KEYS = (
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
ACCEPTANCE_SUBJECT = "user:usr_" + "A" * 43
OTHER_ACCEPTANCE_SUBJECT = "user:usr_" + "B" * 43


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

    def test_rikune_hostname_assets_preserve_route_resource_and_permissions(self) -> None:
        route_up = (OPS_ROOT / "assets/20260823_rikune_root_up.sql").read_text(
            encoding="utf-8"
        )
        route_down = (
            OPS_ROOT / "assets/20260823_rikune_root_down.sql"
        ).read_text(encoding="utf-8")
        verify_open = (OPS_ROOT / "assets/verify_rikune_root.sql").read_text(
            encoding="utf-8"
        )
        verify_absent = (
            OPS_ROOT / "assets/verify_rikune_root_absent.sql"
        ).read_text(encoding="utf-8")

        self.assertIn("'rikune-root', 'rikune.w33d.xyz', '/'", route_up)
        self.assertNotIn("'rikune-root', 'analyze.w33d.xyz', '/'", route_up)
        self.assertIn("'rikune.console.enter', 'route:rikune-root'", route_up)
        for asset in (route_up, route_down, verify_open, verify_absent):
            self.assertIn("rikune-root", asset)
            self.assertIn("rikune.w33d.xyz", asset)
            self.assertIn("analyze.w33d.xyz", asset)

        self.assertEqual(sorted(authority_evidence.PERMISSIONS), PERMISSIONS)
        self.assertEqual(len(PERMISSIONS), 7)

    def test_hostname_conflict_cleanup_and_absence_are_case_insensitive(self) -> None:
        assets = {
            name: (OPS_ROOT / f"assets/{name}").read_text(encoding="utf-8")
            for name in (
                "20260823_rikune_root_up.sql",
                "20260823_rikune_root_down.sql",
                "verify_rikune_root.sql",
                "verify_rikune_root_absent.sql",
            )
        }
        for name, sql in assets.items():
            with self.subTest(asset=name, variant="RiKuNe.W33D.XyZ"):
                self.assertIn("lower(", sql)
                self.assertIn("'rikune.w33d.xyz'", sql)
            with self.subTest(asset=name, variant="ANALYZE.W33D.XYZ"):
                self.assertIn("lower(", sql)
                self.assertIn("'analyze.w33d.xyz'", sql)

        route_up = assets["20260823_rikune_root_up.sql"]
        self.assertIn("lower(host) = 'rikune.w33d.xyz'", route_up)
        self.assertGreaterEqual(
            route_up.count("lower(host) = 'analyze.w33d.xyz'"), 2
        )
        route_down = assets["20260823_rikune_root_down.sql"]
        self.assertGreaterEqual(
            route_down.count("lower(route.host) = 'rikune.w33d.xyz'"), 1
        )
        self.assertGreaterEqual(
            route_down.count("lower(host) = 'rikune.w33d.xyz'"), 2
        )
        self.assertGreaterEqual(
            route_down.count("lower(host) = 'analyze.w33d.xyz'"), 2
        )
        verifier = assets["verify_rikune_root.sql"]
        self.assertIn(
            "lower(conflict.host) = 'rikune.w33d.xyz'", verifier
        )
        self.assertIn(
            "lower(conflict.host) = 'analyze.w33d.xyz'", verifier
        )
        absent = assets["verify_rikune_root_absent.sql"]
        self.assertIn("lower(host) = 'rikune.w33d.xyz'", absent)
        self.assertIn("lower(host) = 'analyze.w33d.xyz'", absent)

        # The one persisted canonical row remains exact lowercase; lower(host)
        # is only for collision, cleanup, and absence predicates.
        self.assertIn("AND host = 'rikune.w33d.xyz'", route_up)
        self.assertIn("host = 'rikune.w33d.xyz'", verifier)

    def test_edge_examples_have_exact_dual_host_v3_schemas(self) -> None:
        common_fields = {
            "schema_version",
            "ceremony",
            "issued_at",
            "signature_key_sha256",
            "release_evidence_sha256",
            "successor_policy_sha256",
            "source_grant_id",
            "host",
            "edge_owner",
            "route_state",
            "external_edge_mutations",
            "public_probes",
        }
        example_contracts = {
            "edge-preopen.example.json": (
                "holdfast-rikune-edge-preopen-v3",
                common_fields
                | {
                    "open_evidence_sha256",
                    "open_prepare_receipt_sha256",
                },
            ),
            "edge-rollback.example.json": (
                "holdfast-rikune-edge-rollback-v3",
                common_fields
                | {
                    "preopen_edge_evidence_sha256",
                    "route_close_receipt_sha256",
                    "revocation_evidence_sha256",
                },
            ),
        }
        expected_pairs = {
            ("https://rikune.w33d.xyz/", "ipv4"),
            ("https://rikune.w33d.xyz/", "ipv6"),
            ("https://analyze.w33d.xyz/", "ipv4"),
            ("https://analyze.w33d.xyz/", "ipv6"),
        }
        probe_fields = {
            "family",
            "observed_at",
            "url",
            "status",
            "edge_owner",
            "route_state",
            "response_headers_sha256",
        }

        for filename, (ceremony, fields) in example_contracts.items():
            with self.subTest(filename=filename):
                value = edge_evidence.load(OPS_ROOT / filename)
                self.assertEqual(set(value), fields)
                self.assertEqual(value["schema_version"], 3)
                self.assertEqual(value["ceremony"], ceremony)
                self.assertEqual(value["host"], "rikune.w33d.xyz")
                self.assertEqual(value["edge_owner"], "existing-w33d-sluice")
                self.assertEqual(value["route_state"], "absent")
                self.assertEqual(value["external_edge_mutations"], [])
                self.assertEqual(len(value["public_probes"]), 4)
                self.assertEqual(
                    {
                        (probe["url"], probe["family"])
                        for probe in value["public_probes"]
                    },
                    expected_pairs,
                )
                for probe in value["public_probes"]:
                    self.assertEqual(set(probe), probe_fields)
                    self.assertEqual(probe["status"], 404)
                    self.assertEqual(probe["edge_owner"], "existing-w33d-sluice")
                    self.assertEqual(probe["route_state"], "absent")

    def test_authority_route_close_receipt_dispatch_preserves_v2_and_v3(self) -> None:
        common = {
            "route_closed_at": "2026-08-22T03:00:00Z",
            "source_state": "ingress_open",
            "estate_root": str(self.root / "estate"),
            "backup_dir": str(self.root / "backup"),
            "control_sha256": "1" * 64,
            "state_before_sha256": "2" * 64,
            "route_down_sha256": "3" * 64,
            "route_down_execution_evidence_sha256": "4" * 64,
            "open_evidence_sha256": "5" * 64,
            "source_grant_id": "source-grant-0001",
            "was_public_open": "true",
            "preopen_edge_evidence_sha256": "6" * 64,
            "route_preimage_sha256": "7" * 64,
            "route_state": "absent",
            "edge_owner": "existing-w33d-sluice",
            "public_ipv4_ipv6_closed_status": "404",
            "db_public_db_bracket": "absent-404-absent",
            "external_edge_mutation": "none",
        }
        v2 = {
            field: (
                "2"
                if field == "schema_version"
                else "same-name-or-analyze-root"
                if field == "route_conflict_cleanup"
                else "analyze.w33d.xyz"
                if field == "public_host"
                else common[field]
            )
            for field in authority_evidence.ROUTE_CLOSE_V2_FIELDS
        }
        v3_values = dict(common)
        v3_values.update(
            {
                "route_conflict_cleanup": (
                    "same-name-or-rikune-root-or-analyze-host"
                ),
                "public_host": "rikune.w33d.xyz",
                "legacy_public_host": "analyze.w33d.xyz",
                "legacy_route_state": "absent",
                "legacy_public_ipv4_ipv6_closed_status": "404",
            }
        )
        v3 = {
            field: "3" if field == "schema_version" else v3_values[field]
            for field in authority_evidence.ROUTE_CLOSE_V3_FIELDS
        }
        authority_evidence.validate_route_close_receipt(v2)
        authority_evidence.validate_route_close_receipt(v3)

        for name, candidate in (
            ("v2-extra-dual", {**v2, "legacy_public_host": "analyze.w33d.xyz"}),
            ("v3-analyze-host", {**v3, "public_host": "analyze.w33d.xyz"}),
            ("v3-version-downgrade", {**v3, "schema_version": "2"}),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                authority_evidence.validate_route_close_receipt(candidate)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_supply_bundle_uses_one_safe_byte_snapshot(self) -> None:
        evidence = self.root / "snapshot-a.json"
        evidence.write_text('{"schema_version":1,"value":"a"}\n', encoding="utf-8")
        signature = self.sign(evidence)
        document, pins = supply_chain_evidence.read_verified_supply_chain_bundle(
            evidence, signature, self.public_key
        )
        self.assertEqual(document["value"], "a")
        self.assertEqual(
            pins["SUPPLY_CHAIN_EVIDENCE_SHA256"], sha256(evidence)
        )

        replacement_evidence = self.root / "snapshot-b.json"
        replacement_evidence.write_text(
            '{"schema_version":1,"value":"b"}\n', encoding="utf-8"
        )
        replacement_signature = self.sign(replacement_evidence)
        real_reader = supply_chain_evidence.read_safe_bytes
        swapped = False

        def racing_reader(
            path: Path, label: str, *, maximum_size: int = 2 * 1024 * 1024
        ) -> bytes:
            nonlocal swapped
            raw = real_reader(path, label, maximum_size=maximum_size)
            if path == evidence and not swapped:
                replacement_evidence.replace(evidence)
                replacement_signature.replace(signature)
                swapped = True
            return raw

        with mock.patch.object(
            supply_chain_evidence,
            "read_safe_bytes",
            side_effect=racing_reader,
        ), self.assertRaisesRegex(ValueError, "signature verification failed"):
            supply_chain_evidence.read_verified_supply_chain_bundle(
                evidence, signature, self.public_key
            )
        self.assertTrue(swapped)

    def test_supply_safe_reader_rejects_fifo_and_oversized_input(self) -> None:
        fifo = self.root / "supply.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ValueError, "regular file"):
            supply_chain_evidence.read_safe_bytes(fifo, "supply FIFO")

        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * 9)
        with self.assertRaisesRegex(ValueError, "maximum safe size|regular file"):
            supply_chain_evidence.read_safe_bytes(
                oversized, "oversized supply input", maximum_size=8
            )

    def sign(self, document: Path) -> Path:
        signature = document.with_suffix(document.suffix + ".sig")
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.private_key), "-out", str(signature), str(document)],
            check=True,
        )
        return signature

    def make_supply_fixture(self) -> tuple[dict[str, str], dict[str, object]]:
        release: dict[str, str] = {
            key: f"registry.example/w33d/{key.lower()}@sha256:{index:064x}"
            for index, key in enumerate(SUPPLY_IMAGE_KEYS, 1)
        }
        release["RIKUNE_ANALYZER_IMAGE"] = (
            "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:" + "c" * 64
        )
        release.update(
            {
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "1" * 64,
                "PERMISSION_CATALOG_SHA256": "2" * 64,
                "PACKAGE_CATALOG_SHA256": "3" * 64,
                "RIKUNE_ACCEPTANCE_SUBJECT": ACCEPTANCE_SUBJECT,
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
        for key in SUPPLY_IMAGE_KEYS:
            image = release[key]
            subject = image.rsplit("@", 1)[1]
            registry_images[key] = {
                "image": image,
                "manifest_digest": subject,
                "registry": image.split("/", 1)[0],
                "subject_digest": subject,
                "sbom": {"uri": "oci://evidence/sbom", "sha256": "5" * 64},
                "provenance": {
                    "uri": "oci://evidence/provenance",
                    "sha256": "6" * 64,
                    "builder_id": "builder:trusted",
                },
                "attestation": {"uri": "oci://evidence/attestation", "sha256": "7" * 64},
                "signature": {
                    "identity": "release@example.invalid",
                    "issuer": "https://issuer.example",
                    "rekor_log_index": 1,
                },
            }
        evidence_value: dict[str, object] = {
            "schema_version": 1,
            "issued_at": "2026-08-22T00:00:00Z",
            "platform": "linux/amd64",
            "release_pins_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "registry_verification": {
                "verified_at": "2026-08-22T00:00:00Z",
                "verifier": "cosign-policy-v1",
                "images": registry_images,
            },
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
        return release, evidence_value

    def test_release_env_uses_one_safe_root_owned_regular_file(self) -> None:
        release_env = self.root / "safe-release.env"
        raw = b"STRAD_REVISION=" + b"a" * 40 + b"\n"
        release_env.write_bytes(raw)
        values, observed_sha = supply_chain_evidence.release_env(release_env)
        self.assertEqual(values, {"STRAD_REVISION": "a" * 40})
        self.assertEqual(observed_sha, hashlib.sha256(raw).hexdigest())

        symlink = self.root / "release-symlink.env"
        symlink.symlink_to(release_env)
        with self.assertRaises((OSError, ValueError)):
            supply_chain_evidence.release_env(symlink)

        real_parent = self.root / "real-release-parent"
        real_parent.mkdir()
        nested_release = real_parent / "release.env"
        nested_release.write_bytes(raw)
        parent_symlink = self.root / "release-parent-symlink"
        parent_symlink.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            supply_chain_evidence.release_env(parent_symlink / "release.env")

        hardlink = self.root / "release-hardlink.env"
        os.link(release_env, hardlink)
        with self.assertRaisesRegex(ValueError, "single-link"):
            supply_chain_evidence.release_env(release_env)

        if os.geteuid() == 0:
            foreign = self.root / "release-foreign.env"
            foreign.write_bytes(raw)
            os.chown(foreign, 65534, 65534)
            with self.assertRaisesRegex(ValueError, "root-owned"):
                supply_chain_evidence.release_env(foreign)

    def run_supply_fixture(
        self,
        release: dict[str, str],
        evidence_value: dict[str, object],
        label: str,
        *,
        successor_policy: Path | None = None,
        release_evidence_value: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        evidence = self.root / f"supply-{label}.json"
        evidence.write_text(json.dumps(evidence_value, sort_keys=True), encoding="utf-8")
        signature = self.sign(evidence)
        bound_release = dict(release)
        bound_release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = sha256(evidence)
        bound_release["SUPPLY_CHAIN_SIGNATURE_SHA256"] = sha256(signature)
        release_env = self.root / f"release-{label}.env"
        release_env.write_text(
            "".join(f"{key}={value}\n" for key, value in bound_release.items()),
            encoding="utf-8",
        )
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
        if successor_policy is not None:
            command.extend(("--successor-policy", str(successor_policy)))
        if release_evidence_value is not None:
            release_evidence = self.root / f"release-evidence-{label}.json"
            release_evidence_document = json.loads(
                json.dumps(release_evidence_value)
            )
            release_evidence_document.setdefault("release", dict(bound_release))
            release_evidence_document.setdefault(
                "release_env_sha256", sha256(release_env)
            )
            release_evidence.write_text(
                json.dumps(release_evidence_document, sort_keys=True),
                encoding="utf-8",
            )
            command.extend(("--release-evidence", str(release_evidence)))
        return subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def make_supply_waiver(
        self,
        release: dict[str, str],
        image_key: str,
        missing_field: str,
        reason_code: str,
        *,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, object]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issued_at = issued_at or now - timedelta(minutes=1)
        expires_at = expires_at or now + timedelta(days=7)
        return {
            "image_key": image_key,
            "image": release[image_key],
            "missing_field": missing_field,
            "reason_code": reason_code,
            "ticket_uri": f"https://tickets.example.invalid/{image_key}",
            "ticket_sha256": "8" * 64,
            "approver_identity": "user:release-authority",
            "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "compensating_attestation": {
                "uri": f"oci://evidence/{image_key}/verification-attestation",
                "sha256": "9" * 64,
                "identity": "release@example.invalid",
                "issuer": "https://issuer.example",
                "rekor_log_index": 2,
            },
        }

    def make_supply_v2_fixture(self) -> tuple[dict[str, str], dict[str, object]]:
        release, evidence = self.make_supply_fixture()
        registry = evidence["registry_verification"]
        assert isinstance(registry, dict)
        images = registry["images"]
        assert isinstance(images, dict)
        waiver_policy = (
            (
                "STRAD_RUNTIME_IMAGE",
                "provenance",
                "upstream-provenance-unavailable",
            ),
            (
                "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
                "provenance.builder_id",
                "legacy-builder-id-unavailable",
            ),
            (
                "VERDICT_IMAGE",
                "provenance.builder_id",
                "legacy-builder-id-unavailable",
            ),
            (
                "NEWAPI_IMAGE",
                "provenance.builder_id",
                "legacy-builder-id-unavailable",
            ),
            (
                "SLUICE_IMAGE",
                "provenance.builder_id",
                "legacy-builder-id-unavailable",
            ),
        )
        waivers = []
        for image_key, missing_field, reason_code in waiver_policy:
            waivers.append(
                self.make_supply_waiver(
                    release, image_key, missing_field, reason_code
                )
            )
            image = images[image_key]
            assert isinstance(image, dict)
            if missing_field == "provenance":
                image["provenance"] = None
            else:
                provenance = image["provenance"]
                assert isinstance(provenance, dict)
                provenance["builder_id"] = None
        evidence["schema_version"] = 2
        evidence["waivers"] = waivers
        return release, evidence

    def make_supply_v3_fixture(
        self,
    ) -> tuple[dict[str, str], dict[str, object], dict[str, object]]:
        release, evidence = self.make_supply_v2_fixture()
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        policy["schema_version"] = 3
        policy["ceremony"] = "holdfast-rikune-successor-v3"
        policy["predecessor"].pop("apply_receipt_sha256", None)
        policy["predecessor"].pop("recovery_completion", None)
        policy["predecessor"]["completion"] = {
            "kind": "recovery-completion-attestation-v1",
            "attestation_sha256": "9" * 64,
            "signature_sha256": "a" * 64,
            "public_key_sha256": "b" * 64,
        }
        predecessor = policy["predecessor"]
        successor = policy["successor"]
        release.update(
            {
                "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": predecessor["access_image"],
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": successor[
                    "access_build_input_sha256"
                ],
                "PERMISSION_CATALOG_SHA256": predecessor[
                    "permission_catalog_sha256"
                ],
                "PACKAGE_CATALOG_SHA256": predecessor["package_catalog_sha256"],
                "HOLDFAST_RELEASE_TOOL_REVISION": "a" * 40,
            }
        )
        registry = evidence["registry_verification"]
        assert isinstance(registry, dict)
        images = registry["images"]
        assert isinstance(images, dict)
        rollback = images["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]
        assert isinstance(rollback, dict)
        rollback_digest = release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"].rsplit("@", 1)[1]
        rollback.update(
            {
                "image": release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"],
                "manifest_digest": rollback_digest,
                "registry": release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"].split(
                    "/", 1
                )[0],
                "subject_digest": rollback_digest,
            }
        )
        candidate = images["ACCESS_GOVERNANCE_IMAGE"]
        assert isinstance(candidate, dict)
        candidate_digest = release["ACCESS_GOVERNANCE_IMAGE"].rsplit("@", 1)[1]
        candidate.update(
            {
                "image": release["ACCESS_GOVERNANCE_IMAGE"],
                "manifest_digest": candidate_digest,
                "registry": release["ACCESS_GOVERNANCE_IMAGE"].split("/", 1)[0],
                "subject_digest": candidate_digest,
            }
        )
        waivers = evidence["waivers"]
        assert isinstance(waivers, list)
        for waiver in waivers:
            assert isinstance(waiver, dict)
            if waiver["image_key"] == "ACCESS_GOVERNANCE_ROLLBACK_IMAGE":
                waiver["image"] = release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]

        evidence["schema_version"] = 3
        evidence["successor_binding"] = json.loads(json.dumps(predecessor))
        evidence["access_candidate"] = {
            "image": release["ACCESS_GOVERNANCE_IMAGE"],
            "build_input_schema": "access-build-input/2",
            "build_input_sha256": release[
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"
            ],
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "tool_revision": release["HOLDFAST_RELEASE_TOOL_REVISION"],
        }
        canonical = "".join(
            f"{key}={release[key]}\n"
            for key in sorted(release)
            if key
            not in {
                "SUPPLY_CHAIN_EVIDENCE_SHA256",
                "SUPPLY_CHAIN_SIGNATURE_SHA256",
            }
        )
        evidence["release_pins_sha256"] = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()
        return release, evidence, policy

    def write_successor_policy(
        self, policy: dict[str, object], label: str
    ) -> Path:
        path = self.root / f"successor-policy-{label}.json"
        path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        return path

    def use_keyed_cosign(self, evidence: dict[str, object]) -> None:
        public_key_sha256 = sha256(self.public_key)
        registry = evidence["registry_verification"]
        assert isinstance(registry, dict)
        images = registry["images"]
        assert isinstance(images, dict)
        for image in images.values():
            assert isinstance(image, dict)
            signature = image["signature"]
            assert isinstance(signature, dict)
            image["signature"] = {
                "mode": "key",
                "public_key_sha256": public_key_sha256,
                "rekor_log_index": signature["rekor_log_index"],
            }
        waivers = evidence["waivers"]
        assert isinstance(waivers, list)
        for waiver in waivers:
            assert isinstance(waiver, dict)
            compensating = waiver["compensating_attestation"]
            assert isinstance(compensating, dict)
            waiver["compensating_attestation"] = {
                "uri": compensating["uri"],
                "sha256": compensating["sha256"],
                "mode": "key",
                "public_key_sha256": public_key_sha256,
                "rekor_log_index": compensating["rekor_log_index"],
            }

    def test_supply_chain_requires_signature_registry_materials_and_access_build_input(self) -> None:
        release, evidence_value = self.make_supply_fixture()
        valid = self.run_supply_fixture(release, evidence_value, "v1-valid")
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        release_evidence = {
            "schema_version": 1,
            "analyzer_image_binding": {
                "dockerfile_sha256": evidence_value["analyzer_overlay"][
                    "dockerfile_sha256"
                ],
                "bridge_lock_sha256": evidence_value["analyzer_overlay"][
                    "bridge_lock_sha256"
                ],
                "base_image": release["RIKUNE_ANALYZER_IMAGE"],
                "overlay_image": release["STRAD_ANALYZER_IMAGE"],
                "source_revision": release["STRAD_REVISION"],
            },
        }
        bound = self.run_supply_fixture(
            release,
            evidence_value,
            "v1-release-binding",
            release_evidence_value=release_evidence,
        )
        self.assertEqual(bound.returncode, 0, bound.stdout + bound.stderr)

        mismatched_release = json.loads(json.dumps(release_evidence))
        mismatched_release["release"] = dict(release)
        mismatched_release["release"]["STRAD_IMAGE"] = (
            "registry.example/w33d/base-pin-mismatch@sha256:" + "e" * 64
        )
        rejected_binding = self.run_supply_fixture(
            release,
            evidence_value,
            "v1-release-binding-mismatch",
            release_evidence_value=mismatched_release,
        )
        self.assertNotEqual(rejected_binding.returncode, 0)
        self.assertIn("selected release pins differ", rejected_binding.stderr)

        v1_with_waivers = json.loads(json.dumps(evidence_value))
        v1_with_waivers["waivers"] = []
        invalid = self.run_supply_fixture(
            release, v1_with_waivers, "v1-extra-waivers"
        )
        self.assertNotEqual(invalid.returncode, 0)

        boolean_schema = json.loads(json.dumps(evidence_value))
        boolean_schema["schema_version"] = True
        invalid = self.run_supply_fixture(
            release, boolean_schema, "v1-boolean-schema"
        )
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("unsupported supply-chain schema", invalid.stderr)

        evidence_value = json.loads(json.dumps(evidence_value))
        evidence_value["access_candidate"]["build_input_sha256"] = "f" * 64
        invalid = self.run_supply_fixture(
            release, evidence_value, "v1-access-binding-tamper"
        )
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("Access candidate build input differs", invalid.stderr)

    def test_supply_chain_v2_accepts_only_exact_short_lived_waivers(self) -> None:
        release, evidence = self.make_supply_v2_fixture()
        valid = self.run_supply_fixture(release, evidence, "v2-valid")
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        now = datetime.now(timezone.utc).replace(microsecond=0)
        cases: list[tuple[str, dict[str, object]]] = []

        expired = json.loads(json.dumps(evidence))
        expired["waivers"][0]["issued_at"] = (now - timedelta(days=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        expired["waivers"][0]["expires_at"] = (now - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cases.append(("expired", expired))

        too_long = json.loads(json.dumps(evidence))
        too_long["waivers"][0]["issued_at"] = (now - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        too_long["waivers"][0]["expires_at"] = (now + timedelta(days=31)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cases.append(("too-long", too_long))

        wrong_ref = json.loads(json.dumps(evidence))
        wrong_ref["waivers"][0]["image"] = (
            "registry.example/w33d/wrong@sha256:" + "a" * 64
        )
        cases.append(("wrong-ref", wrong_ref))

        duplicate = json.loads(json.dumps(evidence))
        duplicate["waivers"].append(json.loads(json.dumps(duplicate["waivers"][0])))
        cases.append(("duplicate", duplicate))

        wrong_reason = json.loads(json.dumps(evidence))
        wrong_reason["waivers"][0]["reason_code"] = "operator-convenience"
        cases.append(("wrong-reason", wrong_reason))

        wrong_field = json.loads(json.dumps(evidence))
        wrong_field["waivers"][0]["missing_field"] = "sbom"
        cases.append(("wrong-field", wrong_field))

        overbroad = json.loads(json.dumps(evidence))
        overbroad["waivers"][0]["missing_fields"] = ["provenance", "sbom"]
        cases.append(("overbroad", overbroad))

        unconsumed = json.loads(json.dumps(evidence))
        unconsumed_registry = unconsumed["registry_verification"]
        unconsumed_registry["images"]["VERDICT_IMAGE"]["provenance"][
            "builder_id"
        ] = "builder:unexpected"
        cases.append(("unconsumed", unconsumed))

        for label, candidate in cases:
            with self.subTest(label=label):
                invalid = self.run_supply_fixture(release, candidate, f"v2-{label}")
                self.assertNotEqual(
                    invalid.returncode, 0, invalid.stdout + invalid.stderr
                )

        for forbidden_key in (
            "ACCESS_GOVERNANCE_IMAGE",
            "STRAD_IMAGE",
            "STRAD_ANALYZER_IMAGE",
            "RIKUNE_ANALYZER_IMAGE",
        ):
            with self.subTest(forbidden_key=forbidden_key):
                forbidden = json.loads(json.dumps(evidence))
                forbidden["waivers"].append(
                    self.make_supply_waiver(
                        release,
                        forbidden_key,
                        "provenance",
                        "upstream-provenance-unavailable",
                    )
                )
                invalid = self.run_supply_fixture(
                    release, forbidden, f"v2-forbidden-{forbidden_key.lower()}"
                )
                self.assertNotEqual(
                    invalid.returncode, 0, invalid.stdout + invalid.stderr
                )

    def test_supply_chain_v3_accepts_exact_keyed_cosign_material(self) -> None:
        release, evidence, policy = self.make_supply_v3_fixture()
        self.use_keyed_cosign(evidence)
        policy_path = self.write_successor_policy(policy, "v3-keyed-cosign")
        valid = self.run_supply_fixture(
            release,
            evidence,
            "v3-keyed-cosign",
            successor_policy=policy_path,
        )
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

    def test_supply_chain_v3_rejects_malformed_keyed_cosign_material(self) -> None:
        release, evidence, policy = self.make_supply_v3_fixture()
        self.use_keyed_cosign(evidence)
        policy_path = self.write_successor_policy(policy, "v3-keyed-malformed")
        cases: list[tuple[str, dict[str, object], str]] = []

        registry_missing_hash = json.loads(json.dumps(evidence))
        registry_signature = registry_missing_hash["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]
        del registry_signature["public_key_sha256"]
        cases.append(("registry-missing-hash", registry_missing_hash, "field set is not exact"))

        registry_invalid_hash = json.loads(json.dumps(evidence))
        registry_invalid_hash["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]["public_key_sha256"] = "A" * 64
        cases.append(
            (
                "registry-invalid-hash",
                registry_invalid_hash,
                "must be lowercase SHA-256",
            )
        )

        registry_mixed = json.loads(json.dumps(evidence))
        registry_mixed["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]["issuer"] = "https://issuer.example"
        cases.append(("registry-mixed-fields", registry_mixed, "field set is not exact"))

        registry_fake_issuer = json.loads(json.dumps(evidence))
        registry_signature = registry_fake_issuer["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]
        del registry_signature["public_key_sha256"]
        registry_signature["issuer"] = "sha256:" + "a" * 64
        cases.append(
            (
                "registry-issuer-is-not-key-mode",
                registry_fake_issuer,
                "field set is not exact",
            )
        )

        registry_wrong_mode = json.loads(json.dumps(evidence))
        registry_wrong_mode["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]["mode"] = "keyless"
        cases.append(("registry-wrong-mode", registry_wrong_mode, "mode must be key"))

        registry_negative_index = json.loads(json.dumps(evidence))
        registry_negative_index["registry_verification"]["images"][
            "ACCESS_GOVERNANCE_IMAGE"
        ]["signature"]["rekor_log_index"] = -1
        cases.append(
            (
                "registry-negative-log-index",
                registry_negative_index,
                "transparency-log binding is invalid",
            )
        )

        waiver_missing_hash = json.loads(json.dumps(evidence))
        compensating = waiver_missing_hash["waivers"][0]["compensating_attestation"]
        del compensating["public_key_sha256"]
        cases.append(("waiver-missing-hash", waiver_missing_hash, "field set is not exact"))

        waiver_invalid_hash = json.loads(json.dumps(evidence))
        waiver_invalid_hash["waivers"][0]["compensating_attestation"][
            "public_key_sha256"
        ] = "not-a-sha256"
        cases.append(
            (
                "waiver-invalid-hash",
                waiver_invalid_hash,
                "must be lowercase SHA-256",
            )
        )

        waiver_mixed = json.loads(json.dumps(evidence))
        waiver_mixed["waivers"][0]["compensating_attestation"][
            "identity"
        ] = "release@example.invalid"
        cases.append(("waiver-mixed-fields", waiver_mixed, "field set is not exact"))

        waiver_fake_issuer = json.loads(json.dumps(evidence))
        compensating = waiver_fake_issuer["waivers"][0]["compensating_attestation"]
        del compensating["public_key_sha256"]
        compensating["issuer"] = "sha256:" + "b" * 64
        cases.append(
            (
                "waiver-issuer-is-not-key-mode",
                waiver_fake_issuer,
                "field set is not exact",
            )
        )

        waiver_wrong_mode = json.loads(json.dumps(evidence))
        waiver_wrong_mode["waivers"][0]["compensating_attestation"][
            "mode"
        ] = "keyless"
        cases.append(("waiver-wrong-mode", waiver_wrong_mode, "mode must be key"))

        waiver_negative_index = json.loads(json.dumps(evidence))
        waiver_negative_index["waivers"][0]["compensating_attestation"][
            "rekor_log_index"
        ] = -1
        cases.append(
            (
                "waiver-negative-log-index",
                waiver_negative_index,
                "transparency-log binding is invalid",
            )
        )

        for label, candidate, error in cases:
            with self.subTest(label=label):
                invalid = self.run_supply_fixture(
                    release,
                    candidate,
                    f"v3-keyed-{label}",
                    successor_policy=policy_path,
                )
                self.assertNotEqual(
                    invalid.returncode, 0, invalid.stdout + invalid.stderr
                )
                self.assertIn(error, invalid.stderr)

    def test_supply_chain_v3_binds_successor_without_claiming_strad_as_access_source(
        self,
    ) -> None:
        release, evidence, policy = self.make_supply_v3_fixture()
        policy_path = self.write_successor_policy(policy, "v3-valid")
        valid = self.run_supply_fixture(
            release,
            evidence,
            "v3-valid",
            successor_policy=policy_path,
        )
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        self.assertEqual(
            evidence["analyzer_overlay"]["source_revision"],
            release["STRAD_REVISION"],
        )
        self.assertNotIn("source_revision", evidence["access_candidate"])
        if policy["schema_version"] == 4:
            self.assertNotEqual(
                release["ACCESS_GOVERNANCE_IMAGE"],
                release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"],
            )
            self.assertEqual(
                evidence["access_candidate"]["tool_revision"],
                release["HOLDFAST_RELEASE_TOOL_REVISION"],
            )

        recovered_policy = json.loads(json.dumps(policy))
        recovered_policy["schema_version"] = 3
        recovered_policy["ceremony"] = "holdfast-rikune-successor-v3"
        recovered_policy["overlay"] = [
            {
                "path": "access-governance/src/recovered.rs",
                "before_sha256": "1" * 64,
                "after_sha256": "2" * 64,
            }
        ]
        recovered_predecessor = recovered_policy["predecessor"]
        recovered_predecessor.pop("apply_receipt_sha256", None)
        recovered_predecessor["access_image"] = (
            "registry.example/w33d/recovered-predecessor@sha256:" + "d" * 64
        )
        recovered_predecessor["completion"] = {
            "kind": "recovery-completion-attestation-v1",
            "attestation_sha256": "a" * 64,
            "signature_sha256": "b" * 64,
            "public_key_sha256": "c" * 64,
        }
        recovered_policy_path = self.root / "successor-policy-v3.json"
        recovered_policy_path.write_text(
            json.dumps(recovered_policy) + "\n", encoding="utf-8"
        )
        recovered_evidence = json.loads(json.dumps(evidence))
        recovered_release = dict(release)
        recovered_release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"] = (
            recovered_predecessor["access_image"]
        )
        recovered_evidence["successor_binding"] = json.loads(
            json.dumps(recovered_predecessor)
        )
        recovered_evidence["access_candidate"]["tool_revision"] = (
            recovered_release["HOLDFAST_RELEASE_TOOL_REVISION"]
        )
        recovered_rollback = recovered_evidence["registry_verification"][
            "images"
        ]["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]
        recovered_rollback_digest = recovered_release[
            "ACCESS_GOVERNANCE_ROLLBACK_IMAGE"
        ].rsplit("@", 1)[1]
        recovered_rollback.update(
            {
                "image": recovered_release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"],
                "manifest_digest": recovered_rollback_digest,
                "registry": "registry.example",
                "subject_digest": recovered_rollback_digest,
            }
        )
        for waiver in recovered_evidence["waivers"]:
            if waiver["image_key"] == "ACCESS_GOVERNANCE_ROLLBACK_IMAGE":
                waiver["image"] = recovered_release[
                    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE"
                ]
        recovered_canonical = "".join(
            f"{key}={recovered_release[key]}\n"
            for key in sorted(recovered_release)
            if key
            not in {
                "SUPPLY_CHAIN_EVIDENCE_SHA256",
                "SUPPLY_CHAIN_SIGNATURE_SHA256",
            }
        )
        recovered_evidence["release_pins_sha256"] = hashlib.sha256(
            recovered_canonical.encode("utf-8")
        ).hexdigest()
        recovered_valid = self.run_supply_fixture(
            recovered_release,
            recovered_evidence,
            "v3-recovered-valid",
            successor_policy=recovered_policy_path,
        )
        self.assertEqual(
            recovered_valid.returncode,
            0,
            recovered_valid.stdout + recovered_valid.stderr,
        )
        recovered_tamper = json.loads(json.dumps(recovered_evidence))
        recovered_tamper["successor_binding"]["completion"][
            "signature_sha256"
        ] = "d" * 64
        recovered_invalid = self.run_supply_fixture(
            recovered_release,
            recovered_tamper,
            "v3-recovered-tamper",
            successor_policy=recovered_policy_path,
        )
        self.assertNotEqual(recovered_invalid.returncode, 0)
        self.assertIn("immediate predecessor", recovered_invalid.stderr)

        missing_policy = self.run_supply_fixture(
            release,
            evidence,
            "v3-missing-policy",
        )
        self.assertNotEqual(missing_policy.returncode, 0)
        self.assertIn("requires --successor-policy", missing_policy.stderr)

        cases: list[tuple[str, dict[str, object], str]] = []

        legacy_source_claim = json.loads(json.dumps(evidence))
        legacy_source_claim["access_candidate"]["source_revision"] = release[
            "STRAD_REVISION"
        ]
        cases.append(("legacy-source-claim", legacy_source_claim, "field set is not exact"))

        old_build_schema = json.loads(json.dumps(evidence))
        old_build_schema["access_candidate"]["build_input_schema"] = (
            "access-build-input/1"
        )
        cases.append(("old-build-schema", old_build_schema, "build_input_schema"))

        wrong_tool = json.loads(json.dumps(evidence))
        wrong_tool["access_candidate"]["tool_revision"] = release["STRAD_REVISION"]
        cases.append(("wrong-tool", wrong_tool, "tool_revision"))

        wrong_analyzer_source = json.loads(json.dumps(evidence))
        wrong_analyzer_source["analyzer_overlay"]["source_revision"] = "b" * 40
        cases.append(
            (
                "wrong-analyzer-source",
                wrong_analyzer_source,
                "analyzer overlay revision differs",
            )
        )

        predecessor_tamper = json.loads(json.dumps(evidence))
        predecessor_tamper["successor_binding"]["control_sha256"] = "f" * 64
        cases.append(("predecessor-tamper", predecessor_tamper, "immediate predecessor"))

        binding_extra = json.loads(json.dumps(evidence))
        binding_extra["successor_binding"]["source_revision"] = release[
            "STRAD_REVISION"
        ]
        cases.append(("binding-extra", binding_extra, "field set is not exact"))

        for label, candidate, error in cases:
            with self.subTest(label=label):
                invalid = self.run_supply_fixture(
                    release,
                    candidate,
                    f"v3-{label}",
                    successor_policy=policy_path,
                )
                self.assertNotEqual(
                    invalid.returncode, 0, invalid.stdout + invalid.stderr
                )
                self.assertIn(error, invalid.stderr)

        wrong_rollback_release = dict(release)
        wrong_rollback_release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"] = (
            "registry.example/w33d/not-predecessor@sha256:" + "e" * 64
        )
        wrong_rollback_evidence = json.loads(json.dumps(evidence))
        wrong_rollback_registry = wrong_rollback_evidence["registry_verification"][
            "images"
        ]["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]
        wrong_rollback_digest = wrong_rollback_release[
            "ACCESS_GOVERNANCE_ROLLBACK_IMAGE"
        ].rsplit("@", 1)[1]
        wrong_rollback_registry.update(
            {
                "image": wrong_rollback_release[
                    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE"
                ],
                "manifest_digest": wrong_rollback_digest,
                "registry": "registry.example",
                "subject_digest": wrong_rollback_digest,
            }
        )
        for waiver in wrong_rollback_evidence["waivers"]:
            if waiver["image_key"] == "ACCESS_GOVERNANCE_ROLLBACK_IMAGE":
                waiver["image"] = wrong_rollback_release[
                    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE"
                ]
        canonical = "".join(
            f"{key}={wrong_rollback_release[key]}\n"
            for key in sorted(wrong_rollback_release)
            if key
            not in {
                "SUPPLY_CHAIN_EVIDENCE_SHA256",
                "SUPPLY_CHAIN_SIGNATURE_SHA256",
            }
        )
        wrong_rollback_evidence["release_pins_sha256"] = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()
        wrong_rollback = self.run_supply_fixture(
            wrong_rollback_release,
            wrong_rollback_evidence,
            "v3-wrong-rollback",
            successor_policy=policy_path,
        )
        self.assertNotEqual(wrong_rollback.returncode, 0)
        self.assertIn("immediate predecessor candidate", wrong_rollback.stderr)

        release_evidence = {
            "schema_version": 2,
            "release_mode": "successor",
            "access_governance_build_input_schema": "access-build-input/2",
            "access_governance_build_input_sha256": release[
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"
            ],
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "holdfast_release_tool_revision": release[
                "HOLDFAST_RELEASE_TOOL_REVISION"
            ],
            "predecessor_binding": json.loads(
                json.dumps(policy["predecessor"])
            ),
            "analyzer_image_binding": {
                "dockerfile_sha256": evidence["analyzer_overlay"][
                    "dockerfile_sha256"
                ],
                "bridge_lock_sha256": evidence["analyzer_overlay"][
                    "bridge_lock_sha256"
                ],
                "base_image": release["RIKUNE_ANALYZER_IMAGE"],
                "overlay_image": release["STRAD_ANALYZER_IMAGE"],
                "source_revision": release["STRAD_REVISION"],
            },
        }
        with_release = self.run_supply_fixture(
            release,
            evidence,
            "v3-release-binding",
            successor_policy=policy_path,
            release_evidence_value=release_evidence,
        )
        self.assertEqual(
            with_release.returncode,
            0,
            with_release.stdout + with_release.stderr,
        )

        mismatched_release = json.loads(json.dumps(release_evidence))
        mismatched_release["predecessor_binding"]["control_sha256"] = "f" * 64
        mismatch = self.run_supply_fixture(
            release,
            evidence,
            "v3-release-binding-mismatch",
            successor_policy=policy_path,
            release_evidence_value=mismatched_release,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("predecessor_binding", mismatch.stderr)

        mismatched_pins = json.loads(json.dumps(release_evidence))
        mismatched_pins["release"] = dict(release)
        mismatched_pins["release"]["STRAD_IMAGE"] = (
            "registry.example/w33d/not-the-release@sha256:" + "d" * 64
        )
        pin_mismatch = self.run_supply_fixture(
            release,
            evidence,
            "v3-release-pin-mismatch",
            successor_policy=policy_path,
            release_evidence_value=mismatched_pins,
        )
        self.assertNotEqual(pin_mismatch.returncode, 0)
        self.assertIn("selected release pins differ", pin_mismatch.stderr)

    def test_authority_rollback_proves_route_close_then_same_grant_then_tombstones(self) -> None:
        release_env = self.root / "authority.release.env"
        release = {
            "AUTHORITY_PUBLIC_KEY_SHA256": sha256(self.public_key),
            "ACCESS_GOVERNANCE_IMAGE": "registry.example/access@sha256:" + "1" * 64,
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "2" * 64,
            "PERMISSION_CATALOG_SHA256": "3" * 64,
            "PACKAGE_CATALOG_SHA256": "4" * 64,
            "RIKUNE_ACCEPTANCE_SUBJECT": ACCEPTANCE_SUBJECT,
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
            "bootstrap_version": 7,
            "package_id": "pkg_rikune_analyst",
            "requestable_version": 2,
            "beneficiary": ACCEPTANCE_SUBJECT,
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
        for bootstrap_version in (6, 8):
            invalid_bootstrap_value = dict(open_value)
            invalid_bootstrap_value["bootstrap_version"] = bootstrap_version
            invalid_bootstrap = self.root / f"open-bootstrap-{bootstrap_version}.json"
            invalid_bootstrap.write_text(
                json.dumps(invalid_bootstrap_value, sort_keys=True), encoding="utf-8"
            )
            invalid_bootstrap_signature = self.sign(invalid_bootstrap)
            invalid_bootstrap_command = list(open_command)
            invalid_bootstrap_command[
                invalid_bootstrap_command.index("--evidence") + 1
            ] = str(invalid_bootstrap)
            invalid_bootstrap_command[
                invalid_bootstrap_command.index("--signature") + 1
            ] = str(invalid_bootstrap_signature)
            rejected_bootstrap = subprocess.run(
                invalid_bootstrap_command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.subTest(bootstrap_version=bootstrap_version):
                self.assertNotEqual(rejected_bootstrap.returncode, 0)
                self.assertIn(
                    "bootstrap/requestable version evidence is incomplete",
                    rejected_bootstrap.stderr,
                )
        invalid_pin_cases: tuple[tuple[str, str | None], ...] = (
            ("missing", None),
            ("placeholder", "user:usr_<43-char-base64url-sub>"),
            ("malformed", "user:usr_too-short"),
            ("privileged-u-admin", "user:u_admin"),
            ("privileged-w33d", "user:w33d"),
        )
        for label, invalid_subject in invalid_pin_cases:
            invalid_release = dict(release)
            if invalid_subject is None:
                invalid_release.pop("RIKUNE_ACCEPTANCE_SUBJECT")
            else:
                invalid_release["RIKUNE_ACCEPTANCE_SUBJECT"] = invalid_subject
            invalid_pin_env = self.root / f"authority-{label}.release.env"
            invalid_pin_env.write_text(
                "".join(f"{key}={value}\n" for key, value in invalid_release.items()),
                encoding="utf-8",
            )
            invalid_pin_command = list(open_command)
            invalid_pin_command[
                invalid_pin_command.index("--release-env") + 1
            ] = str(invalid_pin_env)
            invalid_pin = subprocess.run(
                invalid_pin_command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.subTest(label=label):
                self.assertNotEqual(invalid_pin.returncode, 0)
                self.assertIn("RIKUNE_ACCEPTANCE_SUBJECT", invalid_pin.stderr)

        mismatched_open_value = dict(open_value)
        mismatched_open_value["beneficiary"] = OTHER_ACCEPTANCE_SUBJECT
        mismatched_open = self.root / "open-beneficiary-mismatch.json"
        mismatched_open.write_text(
            json.dumps(mismatched_open_value, sort_keys=True), encoding="utf-8"
        )
        mismatched_open_signature = self.sign(mismatched_open)
        mismatch_command = list(open_command)
        mismatch_command[mismatch_command.index("--evidence") + 1] = str(
            mismatched_open
        )
        mismatch_command[mismatch_command.index("--signature") + 1] = str(
            mismatched_open_signature
        )
        mismatch = subprocess.run(
            mismatch_command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("release-pinned acceptance subject", mismatch.stderr)
        route_receipt = self.root / "ROUTE-CLOSE.receipt"
        route_receipt.write_text(
            "".join(
                (
                    "schema_version=2\n",
                    "route_closed_at=2026-08-22T01:00:00Z\n",
                    "source_state=ingress_open\n",
                    f"estate_root={self.root / 'estate'}\n",
                    f"backup_dir={self.root / 'backup'}\n",
                    f"control_sha256={'1' * 64}\n",
                    f"state_before_sha256={'2' * 64}\n",
                    f"route_down_sha256={'3' * 64}\n",
                    f"route_down_execution_evidence_sha256={'4' * 64}\n",
                    f"route_preimage_sha256={'5' * 64}\n",
                    "route_conflict_cleanup=same-name-or-analyze-root\n",
                    f"open_evidence_sha256={sha256(open_evidence)}\n",
                    "source_grant_id=source-grant-0001\n",
                    "was_public_open=true\n",
                    f"preopen_edge_evidence_sha256={'6' * 64}\n",
                    "route_state=absent\n",
                    "public_host=analyze.w33d.xyz\n",
                    "edge_owner=existing-w33d-sluice\n",
                    "public_ipv4_ipv6_closed_status=404\n",
                    "db_public_db_bracket=absent-404-absent\n",
                    "external_edge_mutation=none\n",
                )
            ),
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
            "beneficiary": ACCEPTANCE_SUBJECT,
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
        mismatched_rollback_value = dict(rollback_value)
        mismatched_rollback_value["beneficiary"] = OTHER_ACCEPTANCE_SUBJECT
        mismatched_rollback = self.root / "rollback-beneficiary-mismatch.json"
        mismatched_rollback.write_text(
            json.dumps(mismatched_rollback_value, sort_keys=True), encoding="utf-8"
        )
        mismatched_rollback_signature = self.sign(mismatched_rollback)
        mismatch_command = list(command)
        mismatch_command[mismatch_command.index("--evidence") + 1] = str(
            mismatched_rollback
        )
        mismatch_command[mismatch_command.index("--signature") + 1] = str(
            mismatched_rollback_signature
        )
        mismatch = subprocess.run(
            mismatch_command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("release-pinned acceptance subject", mismatch.stderr)
        rollback_value["projection_tombstones"][0]["acknowledged_at"] = "2026-08-22T01:05:00Z"
        rollback_evidence.write_text(json.dumps(rollback_value, sort_keys=True), encoding="utf-8")
        rollback_signature = self.sign(rollback_evidence)
        command[command.index("--signature") + 1] = str(rollback_signature)
        invalid = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("route close, grant revoke", invalid.stderr)

    def make_preopen_fixture(
        self,
        *,
        successor_policy: Path | None = None,
        release_generation: int | None = None,
    ):
        release_env = self.root / "edge.release.env"
        release_env.write_text(
            f"AUTHORITY_PUBLIC_KEY_SHA256={sha256(self.public_key)}\n", encoding="utf-8"
        )
        release_evidence = self.root / "edge-release-evidence.json"
        successor_policy = successor_policy or OPS_ROOT / "successor-policy.json"
        policy = json.loads(successor_policy.read_text(encoding="utf-8"))
        if release_generation is None:
            release_generation = (
                policy["schema_version"] + 1
                if policy["schema_version"] in (4, 5)
                else 5
            )
        release_evidence.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "release_mode": "successor",
                    "predecessor_binding": policy["predecessor"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        open_evidence = self.root / "edge-open.json"
        open_evidence.write_text(
            json.dumps({"source_grant_id": "source-grant-0001"}), encoding="utf-8"
        )
        prepare_receipt = self.root / "OPEN-PREPARE.receipt"
        prepare_receipt.write_text(
            "\n".join(
                (
                    "schema_version=3",
                    "prepared_at=2026-08-22T02:00:00Z",
                    f"release_generation={release_generation}",
                    f"release_evidence_sha256={sha256(release_evidence)}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-0001",
                    "route_state=absent",
                    "public_host=rikune.w33d.xyz",
                    "legacy_public_host=analyze.w33d.xyz",
                    "legacy_route_state=absent",
                    "legacy_public_ipv4_ipv6_closed_status=404",
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
            "schema_version": 3,
            "ceremony": "holdfast-rikune-edge-preopen-v3",
            "issued_at": "2026-08-22T02:10:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "successor_policy_sha256": sha256(successor_policy),
            "open_evidence_sha256": sha256(open_evidence),
            "source_grant_id": "source-grant-0001",
            "open_prepare_receipt_sha256": sha256(prepare_receipt),
            "host": "rikune.w33d.xyz",
            "edge_owner": "existing-w33d-sluice",
            "route_state": "absent",
            "external_edge_mutations": [],
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T02:05:00Z",
                    "url": url,
                    "status": 404,
                    "edge_owner": "existing-w33d-sluice",
                    "route_state": "absent",
                    "response_headers_sha256": digest * 64,
                }
                for url, family, digest in (
                    ("https://rikune.w33d.xyz/", "ipv4", "a"),
                    ("https://rikune.w33d.xyz/", "ipv6", "b"),
                    ("https://analyze.w33d.xyz/", "ipv4", "c"),
                    ("https://analyze.w33d.xyz/", "ipv6", "d"),
                )
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
            "--successor-policy",
            str(successor_policy),
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

    def test_edge_preopen_and_rollback_v3_bind_exact_dual_stack_404_state(self) -> None:
        value, evidence, command, release_env, release_evidence, open_evidence = self.make_preopen_fixture()
        valid = self.run_signed_edge(value, evidence, command)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        route_receipt = self.root / "EDGE-ROUTE-CLOSE.receipt"
        route_receipt.write_text(
            "\n".join(
                (
                    "schema_version=3",
                    "route_closed_at=2026-08-22T03:00:00Z",
                    "source_state=ingress_open",
                    "estate_root=/srv/w33d_infra",
                    "backup_dir=/var/lib/holdfast-rikune/backups/test",
                    f"control_sha256={'a' * 64}",
                    f"state_before_sha256={'b' * 64}",
                    f"route_down_sha256={'c' * 64}",
                    f"route_down_execution_evidence_sha256={'9' * 64}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-0001",
                    "was_public_open=true",
                    f"preopen_edge_evidence_sha256={sha256(evidence)}",
                    f"route_preimage_sha256={'f' * 64}",
                    "route_conflict_cleanup=same-name-or-rikune-root-or-analyze-host",
                    "route_state=absent",
                    "public_host=rikune.w33d.xyz",
                    "legacy_public_host=analyze.w33d.xyz",
                    "legacy_route_state=absent",
                    "legacy_public_ipv4_ipv6_closed_status=404",
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
            "schema_version": 3,
            "ceremony": "holdfast-rikune-edge-rollback-v3",
            "issued_at": "2026-08-22T03:15:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "successor_policy_sha256": sha256(OPS_ROOT / "successor-policy.json"),
            "preopen_edge_evidence_sha256": sha256(evidence),
            "route_close_receipt_sha256": sha256(route_receipt),
            "revocation_evidence_sha256": sha256(revocation),
            "source_grant_id": "source-grant-0001",
            "host": "rikune.w33d.xyz",
            "edge_owner": "existing-w33d-sluice",
            "route_state": "absent",
            "external_edge_mutations": [],
            "public_probes": [
                {
                    "family": family,
                    "observed_at": "2026-08-22T03:10:00Z",
                    "url": url,
                    "status": 404,
                    "edge_owner": "existing-w33d-sluice",
                    "route_state": "absent",
                    "response_headers_sha256": digest * 64,
                }
                for url, family, digest in (
                    ("https://rikune.w33d.xyz/", "ipv4", "d"),
                    ("https://rikune.w33d.xyz/", "ipv6", "e"),
                    ("https://analyze.w33d.xyz/", "ipv4", "f"),
                    ("https://analyze.w33d.xyz/", "ipv6", "0"),
                )
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
            "--successor-policy",
            str(OPS_ROOT / "successor-policy.json"),
            "--open-edge-evidence",
            str(evidence),
            "--route-close-receipt",
            str(route_receipt),
            "--revocation-evidence",
            str(revocation),
        ]
        rolled_back = self.run_signed_edge(rollback_value, rollback_evidence, rollback_command)
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stdout + rolled_back.stderr)

    def test_schema5_policy_reuses_dual_host_v3_for_gen6(self) -> None:
        policy_path = self.root / "successor-policy-v5.json"
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        policy["schema_version"] = 5
        policy["ceremony"] = "holdfast-rikune-successor-v5"
        policy["predecessor"].pop("apply_receipt_sha256", None)
        policy["predecessor"]["recovery_completion"] = {
            "kind": "holdfast-rikune-recovery-resume-completion-v1",
            "archive": "APPLY-RECOVERY-COMPLETE-20260830T120000Z-6.json",
            "archive_sha256": "1" * 64,
            "receipt": "APPLY-RECOVERY-COMPLETE-20260830T120000Z-6.receipt",
            "receipt_sha256": "2" * 64,
            "armed_receipt": "APPLY-RECOVERY-ARMED-20260830T120000Z-6.receipt",
            "armed_receipt_sha256": "3" * 64,
            "failure_receipt": "APPLY-ACTIVATION-FAILED-20260830T115900Z-5.receipt",
            "failure_receipt_sha256": "4" * 64,
        }
        policy_path.write_text(
            json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8"
        )

        value, evidence, command, *_ = self.make_preopen_fixture(
            successor_policy=policy_path,
            release_generation=6,
        )
        valid = self.run_signed_edge(value, evidence, command)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        self.assertIn("rikune-dual-v3", valid.stdout)

        prepare_receipt = Path(
            command[command.index("--prepare-receipt") + 1]
        )
        prepare_receipt.write_text(
            prepare_receipt.read_text(encoding="utf-8").replace(
                "release_generation=6", "release_generation=5"
            ),
            encoding="utf-8",
        )
        value["open_prepare_receipt_sha256"] = sha256(prepare_receipt)
        wrong_generation = self.run_signed_edge(value, evidence, command)
        self.assertNotEqual(wrong_generation.returncode, 0)
        self.assertIn(
            "dual-host open prepare receipt does not prove the exact closed edge",
            wrong_generation.stderr,
        )

    def test_legacy_v2_analyze_only_preopen_and_route_close_remain_valid(self) -> None:
        release_env = self.root / "legacy-edge.release.env"
        release_env.write_text(
            f"AUTHORITY_PUBLIC_KEY_SHA256={sha256(self.public_key)}\n",
            encoding="utf-8",
        )
        legacy_policy = self.root / "legacy-successor-policy.json"
        legacy_policy_value = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        legacy_policy_value["schema_version"] = 3
        legacy_policy_value["ceremony"] = "holdfast-rikune-successor-v3"
        legacy_policy_value["predecessor"].pop("apply_receipt_sha256", None)
        legacy_policy_value["predecessor"].pop("recovery_completion", None)
        legacy_policy_value["predecessor"]["completion"] = {
            "kind": "recovery-completion-attestation-v1",
            "attestation_sha256": "a" * 64,
            "signature_sha256": "b" * 64,
            "public_key_sha256": "c" * 64,
        }
        legacy_policy.write_text(
            json.dumps(legacy_policy_value, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        release_evidence = self.root / "legacy-edge-release.json"
        release_evidence.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "release_mode": "successor",
                    "predecessor_binding": legacy_policy_value["predecessor"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        open_evidence = self.root / "legacy-edge-open.json"
        open_evidence.write_text(
            json.dumps({"source_grant_id": "source-grant-legacy"}),
            encoding="utf-8",
        )
        prepare_receipt = self.root / "LEGACY-OPEN-PREPARE.receipt"
        prepare_receipt.write_text(
            "\n".join(
                (
                    "prepared_at=2026-08-22T02:00:00Z",
                    f"release_evidence_sha256={sha256(release_evidence)}",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-legacy",
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
        preopen_value = {
            "schema_version": 2,
            "ceremony": "holdfast-rikune-edge-preopen-v2",
            "issued_at": "2026-08-22T02:10:00Z",
            "signature_key_sha256": sha256(self.public_key),
            "release_evidence_sha256": sha256(release_evidence),
            "open_evidence_sha256": sha256(open_evidence),
            "source_grant_id": "source-grant-legacy",
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
        preopen = self.root / "legacy-edge-preopen.json"
        preopen_command = [
            "python3",
            str(OPS_ROOT / "edge_evidence.py"),
            "--mode",
            "preopen",
            "--evidence",
            str(preopen),
            "--public-key",
            str(self.public_key),
            "--release-env",
            str(release_env),
            "--release-evidence",
            str(release_evidence),
            "--successor-policy",
            str(legacy_policy),
            "--open-evidence",
            str(open_evidence),
            "--prepare-receipt",
            str(prepare_receipt),
        ]
        valid_preopen = self.run_signed_edge(
            preopen_value, preopen, preopen_command
        )
        self.assertEqual(
            valid_preopen.returncode,
            0,
            valid_preopen.stdout + valid_preopen.stderr,
        )

        route_receipt = self.root / "LEGACY-ROUTE-CLOSE.receipt"
        route_receipt.write_text(
            "\n".join(
                (
                    "schema_version=2",
                    "route_closed_at=2026-08-22T03:00:00Z",
                    "source_state=ingress_open",
                    "estate_root=/srv/w33d_infra",
                    "backup_dir=/var/lib/holdfast-rikune/backups/legacy",
                    f"control_sha256={'a' * 64}",
                    f"state_before_sha256={'b' * 64}",
                    f"route_down_sha256={'c' * 64}",
                    f"route_down_execution_evidence_sha256={'d' * 64}",
                    f"route_preimage_sha256={'e' * 64}",
                    "route_conflict_cleanup=same-name-or-analyze-root",
                    f"open_evidence_sha256={sha256(open_evidence)}",
                    "source_grant_id=source-grant-legacy",
                    "was_public_open=true",
                    f"preopen_edge_evidence_sha256={sha256(preopen)}",
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
        revocation = self.root / "legacy-edge-revocation.json"
        revocation.write_text(
            json.dumps(
                {
                    "issued_at": "2026-08-22T03:05:00Z",
                    "source_grant_id": "source-grant-legacy",
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
            "preopen_edge_evidence_sha256": sha256(preopen),
            "route_close_receipt_sha256": sha256(route_receipt),
            "revocation_evidence_sha256": sha256(revocation),
            "source_grant_id": "source-grant-legacy",
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
                for family, digest in (("ipv4", "c"), ("ipv6", "d"))
            ],
        }
        rollback = self.root / "legacy-edge-rollback.json"
        rollback_command = [
            "python3",
            str(OPS_ROOT / "edge_evidence.py"),
            "--mode",
            "rollback",
            "--evidence",
            str(rollback),
            "--public-key",
            str(self.public_key),
            "--release-env",
            str(release_env),
            "--release-evidence",
            str(release_evidence),
            "--successor-policy",
            str(legacy_policy),
            "--open-edge-evidence",
            str(preopen),
            "--route-close-receipt",
            str(route_receipt),
            "--revocation-evidence",
            str(revocation),
        ]
        valid_rollback = self.run_signed_edge(
            rollback_value, rollback, rollback_command
        )
        self.assertEqual(
            valid_rollback.returncode,
            0,
            valid_rollback.stdout + valid_rollback.stderr,
        )

    def test_schema4_policy_dispatch_rejects_legacy_v2_or_unbound_v3(self) -> None:
        value, evidence, command, *_ = self.make_preopen_fixture()
        legacy = json.loads(json.dumps(value))
        legacy["schema_version"] = 2
        legacy["ceremony"] = "holdfast-rikune-edge-preopen-v2"
        legacy["host"] = "analyze.w33d.xyz"
        legacy.pop("successor_policy_sha256")
        legacy["public_probes"] = [
            probe
            for probe in legacy["public_probes"]
            if probe["url"] == "https://analyze.w33d.xyz/"
        ]
        wrong_schema = self.run_signed_edge(legacy, evidence, command)
        self.assertNotEqual(wrong_schema.returncode, 0)
        self.assertIn("v3 ceremony", wrong_schema.stderr)

        unbound_command = list(command)
        policy_index = unbound_command.index("--successor-policy")
        del unbound_command[policy_index : policy_index + 2]
        unbound = self.run_signed_edge(value, evidence, unbound_command)
        self.assertNotEqual(unbound.returncode, 0)
        self.assertIn("requires its frozen successor policy", unbound.stderr)

        wrong_policy_hash = json.loads(json.dumps(value))
        wrong_policy_hash["successor_policy_sha256"] = "f" * 64
        mismatched = self.run_signed_edge(wrong_policy_hash, evidence, command)
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertIn("policy binding differs", mismatched.stderr)

    def test_actual_route_close_receipt_is_accepted_by_edge_rollback_validator(
        self,
    ) -> None:
        from ops.holdfast.tests.test_rollback_lifecycle import RollbackLifecycleTests

        value, evidence, command, release_env, release_evidence, open_evidence = (
            self.make_preopen_fixture()
        )
        legacy_policy = self.root / "actual-route-legacy-policy.json"
        legacy_policy_value = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        legacy_policy_value["schema_version"] = 3
        legacy_policy_value["ceremony"] = "holdfast-rikune-successor-v3"
        legacy_policy_value["predecessor"].pop("apply_receipt_sha256", None)
        legacy_policy_value["predecessor"].pop("recovery_completion", None)
        legacy_policy_value["predecessor"]["completion"] = {
            "kind": "recovery-completion-attestation-v1",
            "attestation_sha256": "a" * 64,
            "signature_sha256": "b" * 64,
            "public_key_sha256": "c" * 64,
        }
        legacy_policy.write_text(
            json.dumps(legacy_policy_value, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        release_value = json.loads(release_evidence.read_text(encoding="utf-8"))
        release_value["predecessor_binding"] = legacy_policy_value["predecessor"]
        release_evidence.write_text(
            json.dumps(release_value, sort_keys=True) + "\n", encoding="utf-8"
        )
        prepare_receipt = Path(
            command[command.index("--prepare-receipt") + 1]
        )
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
        value["schema_version"] = 2
        value["ceremony"] = "holdfast-rikune-edge-preopen-v2"
        value.pop("successor_policy_sha256")
        value["release_evidence_sha256"] = sha256(release_evidence)
        value["open_prepare_receipt_sha256"] = sha256(prepare_receipt)
        value["host"] = "analyze.w33d.xyz"
        value["public_probes"] = [
            probe
            for probe in value["public_probes"]
            if probe["url"] == "https://analyze.w33d.xyz/"
        ]
        command[command.index("--successor-policy") + 1] = str(legacy_policy)
        valid = self.run_signed_edge(value, evidence, command)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

        lifecycle = RollbackLifecycleTests(
            methodName="test_route_close_receipt_crash_is_adopted_without_external_evidence"
        )
        lifecycle.setUp()
        try:
            lifecycle.route_receipt.unlink()
            lifecycle.route_preimage.unlink()
            open_receipt = lifecycle.state_dir / "OPEN.receipt"
            open_receipt.write_text(
                f"edge_evidence_sha256={sha256(evidence)}\n", encoding="utf-8"
            )
            state = json.loads(lifecycle.state_file.read_text(encoding="utf-8"))
            state["state"] = "ingress_open"
            state["open_receipt_sha256"] = sha256(open_receipt)
            state["ingress_opened"] = True
            for key in (
                "route_close_receipt",
                "route_close_receipt_sha256",
                "route_close_preimage",
                "route_close_preimage_sha256",
            ):
                state.pop(key, None)
            lifecycle.state_file.write_text(
                json.dumps(state) + "\n", encoding="utf-8"
            )
            lifecycle.open_evidence = open_evidence
            lifecycle.open_signature = self.sign(open_evidence)
            lifecycle.public_key = self.public_key

            closed = lifecycle.run_close_route()
            self.assertEqual(closed.returncode, 0, closed.stdout + closed.stderr)
            closed_state = json.loads(
                lifecycle.state_file.read_text(encoding="utf-8")
            )
            route_receipt = (
                lifecycle.state_dir / closed_state["route_close_receipt"]
            )
            receipt_values = dict(
                line.split("=", 1)
                for line in route_receipt.read_text(encoding="utf-8").splitlines()
            )
            route_closed_at = datetime.fromisoformat(
                receipt_values["route_closed_at"].removesuffix("Z") + "+00:00"
            )

            def utc_after(minutes: int) -> str:
                return (
                    (route_closed_at + timedelta(minutes=minutes))
                    .isoformat()
                    .replace("+00:00", "Z")
                )

            revocation = self.root / "actual-route-edge-revocation.json"
            revocation.write_text(
                json.dumps(
                    {
                        "issued_at": utc_after(5),
                        "source_grant_id": "source-grant-0001",
                    }
                ),
                encoding="utf-8",
            )
            rollback_value = {
                "schema_version": 2,
                "ceremony": "holdfast-rikune-edge-rollback-v2",
                "issued_at": utc_after(15),
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
                        "observed_at": utc_after(10),
                        "url": url,
                        "status": 404,
                        "edge_owner": "existing-w33d-sluice",
                        "route_state": "absent",
                        "response_headers_sha256": digest * 64,
                    }
                    for url, family, digest in (
                        ("https://analyze.w33d.xyz/", "ipv4", "f"),
                        ("https://analyze.w33d.xyz/", "ipv6", "0"),
                    )
                ],
            }
            rollback_evidence = self.root / "actual-route-edge-rollback.json"
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
                "--successor-policy",
                str(legacy_policy),
                "--open-edge-evidence",
                str(evidence),
                "--route-close-receipt",
                str(route_receipt),
                "--revocation-evidence",
                str(revocation),
            ]
            rolled_back = self.run_signed_edge(
                rollback_value, rollback_evidence, rollback_command
            )
            self.assertEqual(
                rolled_back.returncode,
                0,
                rolled_back.stdout + rolled_back.stderr,
            )
        finally:
            lifecycle.tearDown()

    def test_edge_preopen_v3_rejects_pages_single_stack_wrong_status_host_and_mutation(self) -> None:
        value, evidence, command, *_ = self.make_preopen_fixture()
        cases: list[tuple[str, dict[str, object], str]] = []

        old_pages = json.loads(json.dumps(value))
        old_pages["schema_version"] = 1
        old_pages["ceremony"] = "holdfast-rikune-edge-cutover-v1"
        old_pages["github_pages_preflight"] = {
            "repository": "Last-emo-boy/rikune",
            "cname": "rikune.w33d.xyz",
        }
        cases.append(("old Pages schema", old_pages, "v3 ceremony"))

        single_stack = json.loads(json.dumps(value))
        single_stack["public_probes"] = single_stack["public_probes"][:1]
        cases.append(("single stack", single_stack, "one IPv4 and one IPv6 probe per host"))

        wrong_status = json.loads(json.dumps(value))
        wrong_status["public_probes"][0]["status"] = 200
        cases.append(("wrong closed status", wrong_status, "exact 404"))

        wrong_host = json.loads(json.dumps(value))
        wrong_host["host"] = "analyze.w33d.xyz"
        cases.append(("wrong host", wrong_host, "host is not rikune.w33d.xyz"))

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
        self.assertIn("verify_public_closed", compensation)
        self.assertIn("record_interrupted_state", compensation)
        self.assertIn("mark_compensation_unverified", compensation)
        self.assertIn('state="ingress_compensation_unverified"', script)

        armed_recovery = script.index('if [[ "$current_state" == "finalizing_route_armed" ]]')
        release_validation = script.index("validate_release_evidence.py", armed_recovery)
        self.assertLess(armed_recovery, release_validation)
        recover_function = script[script.index("recover_armed_open()"):armed_recovery]
        self.assertLess(recover_function.index("force_route_absent"), recover_function.index("open_armed_prepare_receipt_sha256"))
        self.assertIn("validate_armed_open_contract", recover_function)
        self.assertIn('holdfast_die "armed open was compensated', script)
        self.assertIn('"closed-state-route-present"', script)

        armed_contract = script[
            script.index("validate_armed_open_contract()") : script.index(
                "recover_armed_open()"
            )
        ]
        self.assertIn("successor-policy.json", armed_contract)
        self.assertIn("frozen route assets differ from release evidence", armed_contract)
        self.assertIn('policy_schema" -ge 4', armed_contract)
        self.assertIn(
            '.open_armed_public_host == "rikune.w33d.xyz"', armed_contract
        )
        self.assertIn(
            '.open_armed_public_host == "analyze.w33d.xyz"', armed_contract
        )
        self.assertIn(
            '(has("open_armed_legacy_public_host") | not)', armed_contract
        )

        self.assertGreater(script.index("verify_open_bracket", route_insert), route_insert)
        self.assertIn("verify_database_absent\n  verify_public_closed", script)
        self.assertIn(
            'verify_database_open\n  "$script_dir/public-origin-verify.sh" --mode open --url https://rikune.w33d.xyz/',
            script,
        )
        self.assertIn(
            'public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/',
            script,
        )

        rollback = (OPS_ROOT / "rollback.sh").read_text(encoding="utf-8")
        close_phase = rollback[rollback.index('if [[ "$phase" == "close-route" ]]'):]
        self.assertLess(close_phase.index("execute_frozen_route_down"), close_phase.index("current_state=$(jq"))
        self.assertLess(close_phase.index("verify_closed_bracket"), close_phase.index("validate_backup_and_open_authority"))
        self.assertIn(
            'route_preimage_name="ROUTE-CLOSE-PREIMAGE-${route_generation_identity}.jsonl"',
            rollback,
        )
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

        def verify(
            contract: str,
            mode: str,
            url: str = "https://rikune.w33d.xyz/",
        ) -> subprocess.CompletedProcess[str]:
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
                    url,
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

        tombstone = verify(
            "closed", "closed", "https://analyze.w33d.xyz/"
        )
        self.assertEqual(tombstone.returncode, 0, tombstone.stdout + tombstone.stderr)
        tombstone_open = verify(
            "open", "open", "https://analyze.w33d.xyz/"
        )
        self.assertEqual(tombstone_open.returncode, 2)
        self.assertIn("permanently closed tombstone", tombstone_open.stderr)

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
