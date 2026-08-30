from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


OPS_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = OPS_ROOT.parents[1]

import sys

sys.path.insert(0, str(OPS_ROOT))

import assemble_supply_chain_v4 as assembler  # noqa: E402
import supply_chain_evidence as validator  # noqa: E402
import validate_release_evidence as release_validator  # noqa: E402


def image(name: str, digit: str) -> str:
    return f"registry.example/w33d/{name}@sha256:{digit * 64}"


class SupplyChainV4AssemblerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="holdfast-supply-v4-test-", dir="/root"
        )
        self.root = Path(self.temp.name)
        source_root = self.root / "sources"
        source_root.mkdir(mode=0o700)
        self.dockerfile = source_root / "Dockerfile.analyzer"
        self.dockerfile.write_bytes(
            (REPOSITORY_ROOT / "Dockerfile.analyzer").read_bytes()
        )
        self.dockerfile.chmod(0o644)
        self.bridge_lock = source_root / "bridge-package-lock.json"
        self.bridge_lock.write_bytes(
            (REPOSITORY_ROOT / "bridge/package-lock.json").read_bytes()
        )
        self.bridge_lock.chmod(0o644)
        self.policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        self.revision = "c" * 40
        self.issued_at = (
            datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.previous_release = self.make_previous_release()
        self.previous_document = self.make_previous_document()
        self.records = {
            "ACCESS_GOVERNANCE_IMAGE": self.make_record(
                image("access-fresh", "d"),
                keyed=True,
                builder=(
                    "https://w33d.xyz/holdfast/builders/local-root/v1?"
                    "cosign-sha256="
                    f"{validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256}"
                ),
            ),
            "STRAD_IMAGE": self.make_record(image("strad-fresh", "e")),
            "STRAD_ANALYZER_IMAGE": self.make_record(
                image("strad-analyzer-fresh", "f")
            ),
        }
        self.receipt = {
            "schema": "holdfast-access-candidate-build/1",
            "platform": "linux/amd64",
            "image": self.records["ACCESS_GOVERNANCE_IMAGE"]["image"],
            "build_input_schema": "access-build-input/2",
            "build_input_sha256": assembler.GEN5_ACCESS_BUILD_INPUT_SHA256,
            "candidate_evidence_sha256": "1" * 64,
            "candidate_targets_sha256": "2" * 64,
            "render_inputs_sha256": "3" * 64,
            "metadata_sha256": "4" * 64,
            "holdfast_release_tool_revision": self.revision,
            "provenance": "mode.max",
            "provenance_builder_id": (
                "https://w33d.xyz/holdfast/builders/local-root/v1?"
                "cosign-sha256="
                f"{validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256}"
            ),
            "sbom": "enabled",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_previous_release(self) -> dict[str, str]:
        release = {
            key: image(key.lower(), format(index + 1, "x")[-1])
            for index, key in enumerate(validator.IMAGE_KEYS)
        }
        release["RIKUNE_ANALYZER_IMAGE"] = (
            "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:" + "c" * 64
        )
        predecessor = self.policy["predecessor"]
        release.update(
            {
                "ACCESS_GOVERNANCE_IMAGE": predecessor["access_image"],
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": predecessor[
                    "access_build_input_sha256"
                ],
                "PERMISSION_CATALOG_SHA256": predecessor[
                    "permission_catalog_sha256"
                ],
                "PACKAGE_CATALOG_SHA256": predecessor["package_catalog_sha256"],
                "RIKUNE_ACCEPTANCE_SUBJECT": "user:usr_" + "A" * 43,
                "STRAD_REVISION": "b" * 40,
                "STRAD_NEWAPI_MODEL": "glm-5.2",
                "AUTHORITY_PUBLIC_KEY_SHA256": "5" * 64,
                "SUPPLY_CHAIN_PUBLIC_KEY_SHA256": "6" * 64,
                "SUPPLY_CHAIN_EVIDENCE_SHA256": "7" * 64,
                "SUPPLY_CHAIN_SIGNATURE_SHA256": "8" * 64,
                "HOLDFAST_RELEASE_TOOL_REVISION": "b" * 40,
            }
        )
        return release

    def make_record(
        self, pinned_image: str, *, keyed: bool = False, builder: str = "builder:github"
    ) -> dict[str, object]:
        digest = pinned_image.rsplit("@", 1)[1]
        signature: dict[str, object] = (
            {
                "mode": "key",
                "public_key_sha256": validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256,
                "rekor_log_index": 1,
            }
            if keyed
            else {
                "identity": assembler.COSIGN_IDENTITY,
                "issuer": assembler.COSIGN_ISSUER,
                "rekor_log_index": 1,
            }
        )
        return {
            "image": pinned_image,
            "manifest_digest": digest,
            "registry": pinned_image.split("/", 1)[0],
            "subject_digest": digest,
            "sbom": {"uri": f"oci://{pinned_image}#sbom", "sha256": "a" * 64},
            "provenance": {
                "uri": f"oci://{pinned_image}#provenance",
                "sha256": "b" * 64,
                "builder_id": builder,
            },
            "attestation": {
                "uri": f"oci://{pinned_image}#attestation",
                "sha256": "c" * 64,
            },
            "signature": signature,
        }

    def make_previous_document(self) -> dict[str, object]:
        records = {
            key: self.make_record(self.previous_release[key], keyed=True)
            for key in validator.IMAGE_KEYS
        }
        return {
            "registry_verification": {
                "verified_at": "2026-08-29T20:15:25Z",
                "verifier": "previous-production-verifier",
                "images": records,
            },
            "waivers": [],
        }

    def write_private(self, path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)

    def make_signed_previous_bundle(
        self, label: str, *, newapi_digit: str | None = None
    ) -> dict[str, bytes]:
        private_key = self.root / f"{label}.key"
        public_key = self.root / f"{label}.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_raw = public_key.read_bytes()
        release, document = self.assemble(
            supply_public_key_sha256=hashlib.sha256(public_raw).hexdigest()
        )
        if newapi_digit is not None:
            replacement = image(f"newapi-{label}", newapi_digit)
            release["NEWAPI_IMAGE"] = replacement
            record = document["registry_verification"]["images"]["NEWAPI_IMAGE"]
            digest = replacement.rsplit("@", 1)[1]
            record.update(
                {
                    "image": replacement,
                    "manifest_digest": digest,
                    "registry": replacement.split("/", 1)[0],
                    "subject_digest": digest,
                }
            )
            document["release_pins_sha256"] = validator.release_pins_sha256(
                release
            )
        evidence_raw = assembler.json_bytes(document)
        evidence_path = self.root / f"{label}.SUPPLY-CHAIN.json"
        evidence_path.write_bytes(evidence_raw)
        signature_path = self.root / f"{label}.SUPPLY-CHAIN.sig"
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature_path),
                str(evidence_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signature_raw = signature_path.read_bytes()
        release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = hashlib.sha256(
            evidence_raw
        ).hexdigest()
        release["SUPPLY_CHAIN_SIGNATURE_SHA256"] = hashlib.sha256(
            signature_raw
        ).hexdigest()
        release_raw = assembler.canonical_env_bytes(
            release, set(validator.SUCCESSOR_RELEASE_KEYS)
        )
        expected_delta = "".join(
            f"{item['before_sha256'] or '0' * 64}  "
            f"{item['after_sha256']}  {item['path']}\n"
            for item in self.policy["overlay"]
        )
        overlay = document["analyzer_overlay"]
        release_evidence = {
            "schema_version": 2,
            "generator": self.policy["successor"]["generator"],
            "catalog_only": False,
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "access_governance_build_input_sha256": release[
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"
            ],
            "route_up_sha256": "1" * 64,
            "route_down_sha256": "2" * 64,
            "authz_manifest_sha256": "3" * 64,
            "secret_references": list(release_validator.SECRET_REFERENCES),
            "release": release,
            "release_mode": "successor",
            "access_governance_build_input_schema": "access-build-input/2",
            "predecessor_binding": copy.deepcopy(self.policy["predecessor"]),
            "successor_delta_sha256": hashlib.sha256(
                expected_delta.encode("utf-8")
            ).hexdigest(),
            "holdfast_release_tool_revision": release[
                "HOLDFAST_RELEASE_TOOL_REVISION"
            ],
            "release_env_sha256": hashlib.sha256(release_raw).hexdigest(),
            "supply_chain_binding": {
                "evidence_sha256": release["SUPPLY_CHAIN_EVIDENCE_SHA256"],
                "signature_sha256": release["SUPPLY_CHAIN_SIGNATURE_SHA256"],
                "public_key_sha256": release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"],
                "platform": "linux/amd64",
            },
            "analyzer_image_binding": {
                "schema_version": 1,
                "relation": "strad-bridge-overlay-built-from-rikune-static-base",
                "base_build_arg": "RIKUNE_ANALYZER_IMAGE",
                "base_image": release["RIKUNE_ANALYZER_IMAGE"],
                "overlay_image": release["STRAD_ANALYZER_IMAGE"],
                "dockerfile": "strad/Dockerfile.analyzer",
                "bridge_lock": "strad/bridge/package-lock.json",
                "source_revision": release["STRAD_REVISION"],
                "dockerfile_sha256": overlay["dockerfile_sha256"],
                "bridge_lock_sha256": overlay["bridge_lock_sha256"],
            },
        }
        release_evidence_raw = assembler.json_bytes(release_evidence)
        validator.verify_signature_bytes(evidence_raw, signature_raw, public_raw)
        validator.validate_document(document, release, hashlib.sha256(release_raw).hexdigest(), self.policy)
        return {
            "release_env": release_raw,
            "supply_evidence": evidence_raw,
            "supply_signature": signature_raw,
            "supply_public_key": public_raw,
            "release_evidence": release_evidence_raw,
        }

    def assemble(
        self,
        *,
        previous_release: dict[str, str] | None = None,
        previous_document: dict[str, object] | None = None,
        records: dict[str, dict[str, object]] | None = None,
        receipt: dict[str, str] | None = None,
        revision: str | None = None,
        supply_public_key_sha256: str = "d" * 64,
    ) -> tuple[dict[str, str], dict[str, object]]:
        selected_revision = revision or self.revision
        return assembler.assemble_release(
            copy.deepcopy(previous_release or self.previous_release),
            copy.deepcopy(previous_document or self.previous_document),
            copy.deepcopy(self.policy),
            copy.deepcopy(records or self.records),
            copy.deepcopy(receipt or self.receipt),
            "e" * 64,
            "f" * 64,
            selected_revision,
            self.issued_at,
            self.revision,
            supply_public_key_sha256,
            (
                "cosign-offline-oci-layout/v1;"
                f"image={validator.COSIGN_VERIFIER_IMAGE};"
                "trusted_root_sha256="
                f"{validator.SIGSTORE_TRUSTED_ROOT_SHA256};"
                f"strad_release_manifest_sha256={'f' * 64}"
            ),
            dockerfile=self.dockerfile,
            bridge_lock=self.bridge_lock,
        )

    def test_positive_assembly_binds_three_fresh_records_and_carries_others(self) -> None:
        release, document = self.assemble()
        self.assertEqual(document["schema_version"], 4)
        self.assertEqual(
            document["successor_binding"]["apply_receipt_sha256"],
            self.policy["predecessor"]["apply_receipt_sha256"],
        )
        self.assertEqual(
            set(document["fresh_image_bindings"]), assembler.FRESH_IMAGE_KEYS
        )
        self.assertEqual(
            release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
            assembler.GEN5_ACCESS_BUILD_INPUT_SHA256,
        )
        self.assertEqual(
            document["registry_verification"]["images"]["NEWAPI_IMAGE"],
            self.previous_document["registry_verification"]["images"][
                "NEWAPI_IMAGE"
            ],
        )
        validator.validate_document(document, release, "0" * 64, self.policy)

    def test_missing_or_extra_fresh_record_is_rejected(self) -> None:
        for label, records in (
            (
                "missing",
                {
                    key: value
                    for key, value in self.records.items()
                    if key != "STRAD_IMAGE"
                },
            ),
            ("extra", {**self.records, "NEWAPI_IMAGE": self.make_record(image("x", "1"))}),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, "fresh registry record set is not exact"
            ):
                self.assemble(records=records)

        extra_field = copy.deepcopy(self.records)
        extra_field["STRAD_IMAGE"]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "field set is not exact"):
            self.assemble(records=extra_field)

    def test_wrong_image_or_source_revision_is_rejected(self) -> None:
        wrong_receipt = dict(self.receipt)
        wrong_receipt["image"] = image("wrong-access", "1")
        with self.assertRaisesRegex(ValueError, "fresh Access image"):
            self.assemble(receipt=wrong_receipt)

        with self.assertRaisesRegex(ValueError, "revision.*must match"):
            self.assemble(revision="a" * 40)

        release, document = self.assemble()
        document["fresh_image_bindings"]["STRAD_IMAGE"][
            "source_revision"
        ] = "a" * 40
        with self.assertRaisesRegex(ValueError, "fresh STRAD_IMAGE binding differs"):
            validator.validate_document(document, release, "0" * 64, self.policy)

    def test_carry_forward_record_drift_is_rejected(self) -> None:
        previous_document = copy.deepcopy(self.previous_document)
        previous_document["registry_verification"]["images"]["NEWAPI_IMAGE"][
            "image"
        ] = image("drifted-newapi", "1")
        with self.assertRaisesRegex(ValueError, "previous registry record differs"):
            self.assemble(previous_document=previous_document)

    def test_access_builder_must_bind_the_exact_cosign_key(self) -> None:
        key = b"test-access-public-key\n"
        digest = hashlib.sha256(key).hexdigest()
        canonical = (
            "https://w33d.xyz/holdfast/builders/local-root/v1?"
            f"cosign-sha256={digest}"
        )
        with mock.patch.object(
            assembler, "ACCESS_COSIGN_PUBLIC_KEY_SHA256", digest
        ), mock.patch.object(
            validator, "ACCESS_COSIGN_PUBLIC_KEY_SHA256", digest
        ):
            self.assertEqual(
                assembler.validate_access_builder_key_binding(canonical, key),
                digest,
            )
            invalid = (
                f"https://evil.example/holdfast/builders/local-root/v1?cosign-sha256={digest}",
                f"https://user@w33d.xyz/holdfast/builders/local-root/v1?cosign-sha256={digest}",
                f"https://w33d.xyz:443/holdfast/builders/local-root/v1?cosign-sha256={digest}",
                f"https://w33d.xyz/holdfast/builders/local/v1?cosign-sha256={digest}",
                canonical + "#fragment",
                canonical.replace("cosign-sha256", "cosign%2dsha256"),
                canonical + "&purpose=release",
                canonical + f"&cosign-sha256={digest}",
                canonical + f"&cosign-sha256={'0' * 64}",
                canonical.replace(digest, digest.upper()),
                canonical.replace(digest, digest[:-1]),
                canonical + ".suffix",
            )
            for builder in invalid:
                with self.subTest(builder=builder), self.assertRaises(ValueError):
                    assembler.validate_access_builder_key_binding(builder, key)

        with self.assertRaisesRegex(ValueError, "canonical authority"):
            assembler.validate_access_builder_key_binding(canonical, b"alternate-key")

    def test_checkout_revision_rejects_head_or_worktree_drift(self) -> None:
        expected = "a" * 40
        clean_head = SimpleNamespace(returncode=0, stdout=(expected + "\n").encode())
        dirty = SimpleNamespace(returncode=0, stdout=b" M ops/holdfast/tool.py\n")
        with mock.patch.object(
            assembler.subprocess,
            "run",
            side_effect=[clean_head, dirty],
        ), self.assertRaisesRegex(ValueError, "checkout contains"):
            assembler.validate_checkout_revision(expected)

        wrong_head = SimpleNamespace(returncode=0, stdout=("b" * 40 + "\n").encode())
        with mock.patch.object(
            assembler.subprocess, "run", return_value=wrong_head
        ), self.assertRaisesRegex(ValueError, "current Strad HEAD"):
            assembler.validate_checkout_revision(expected)

    def test_schema4_workflow_authority_matches_release_workflow(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"COSIGN_IDENTITY: {validator.STRAD_COSIGN_IDENTITY}", workflow
        )
        self.assertIn(f"COSIGN_ISSUER: {validator.STRAD_COSIGN_ISSUER}", workflow)
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"', workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"', workflow)

    def test_gen5_readme_and_cli_lock_the_complete_image_ceremony(self) -> None:
        readme = (OPS_ROOT / "README.md").read_text(encoding="utf-8")
        access_tag = (
            "registry.w33d.xyz/steadholme/access-governance:"
            "holdfast-successor-<release-id>"
        )
        self.assertIn(access_tag, readme)
        self.assertNotIn(
            "registry.w33d.xyz/steadholme/access-governance:<release-id>",
            readme,
        )
        sign_at = readme.index(
            '"$cosign_image" sign --yes --use-signing-config=true'
        )
        access_save_at = readme.index(
            '"$cosign_image" save --dir /oci "$access_ref"'
        )
        strad_save_at = readme.index(
            '"$cosign_image" save --dir /oci "$strad_ref"'
        )
        analyzer_save_at = readme.index(
            '"$cosign_image" save --dir /oci "$analyzer_ref"'
        )
        assemble_at = readme.index("./assemble_supply_chain_v4.py build-evidence")
        self.assertLess(sign_at, access_save_at)
        self.assertLess(access_save_at, strad_save_at)
        self.assertLess(strad_save_at, analyzer_save_at)
        self.assertLess(analyzer_save_at, assemble_at)
        self.assertNotIn("--timestamp-server-url", readme)
        self.assertNotIn("--tlog-upload=true", readme)
        self.assertIn("--use-signing-config=true", readme)
        self.assertIn("--use-signed-timestamps", readme)
        self.assertIn("--trusted-root /release/SIGSTORE-TRUSTED-ROOT.json", readme)
        self.assertIn("--env COSIGN_PASSWORD", readme)
        self.assertNotIn("--env COSIGN_PASSWORD=", readme)
        self.assertIn("--current-state /var/lib/holdfast-rikune/CURRENT.json", readme)
        self.assertIn("--estate-root /root/w33d_infra", readme)

        parsed = assembler.parser().parse_args(
            [
                "build-evidence",
                "--previous-release-root",
                "/secure/release/predecessor",
                "--previous-successor-policy",
                "/secure/backups/predecessor/successor-authority/successor-policy.json",
                "--current-state",
                "/var/lib/holdfast-rikune/CURRENT.json",
                "--estate-root",
                "/root/w33d_infra",
                "--release-root",
                "/secure/release/holdfast-successor-test",
                "--candidate-root",
                "/secure/release/holdfast-successor-test/rikune-candidate-source",
                "--successor-policy",
                "/root/w33d_infra/strad/ops/holdfast/successor-policy.json",
                "--strad-revision",
                "a" * 40,
                "--release-tool-revision",
                "a" * 40,
                "--issued-at",
                "2026-08-30T00:00:00Z",
                "--access-oci-layout",
                "/secure/release/holdfast-successor-test/access.oci",
                "--strad-oci-layout",
                "/secure/release/holdfast-successor-test/strad.oci",
                "--strad-analyzer-oci-layout",
                "/secure/release/holdfast-successor-test/strad-analyzer.oci",
                "--strad-release-manifest",
                "/secure/release/holdfast-successor-test/release-images.json",
                "--strad-release-bundle",
                "/secure/release/holdfast-successor-test/release-images.sigstore.json",
                "--access-cosign-public-key",
                "/secure/release/holdfast-successor-test/holdfast-cosign.pub",
                "--sigstore-trusted-root",
                "/secure/release/holdfast-successor-test/SIGSTORE-TRUSTED-ROOT.json",
                "--supply-chain-public-key",
                "/secure/release/holdfast-successor-test/release-authority.pub",
                "--output-release-env",
                "/secure/release/holdfast-successor-test/rikune.release.env.unsigned",
                "--output-evidence",
                "/secure/release/holdfast-successor-test/SUPPLY-CHAIN.json",
            ]
        )
        self.assertEqual(parsed.current_state, Path("/var/lib/holdfast-rikune/CURRENT.json"))
        self.assertEqual(parsed.estate_root, Path("/root/w33d_infra"))

    def test_previous_release_is_one_authenticated_signed_snapshot(self) -> None:
        authentic = self.make_signed_previous_bundle("authentic")
        alternate = self.make_signed_previous_bundle(
            "alternate", newapi_digit="7"
        )
        previous_root = self.root / "previous-release"
        previous_root.mkdir(mode=0o700)
        estate = self.root / "estate"
        estate.mkdir(mode=0o700)

        with tempfile.TemporaryDirectory(
            prefix="holdfast-rikune-test-", dir="/secure/backups"
        ) as backup_name:
            backup = Path(backup_name)
            backup.chmod(0o700)
            previous_policy_path = (
                backup / "successor-authority/successor-policy.json"
            )
            previous_policy_raw = assembler.json_bytes(self.policy)
            dockerfile_raw = self.dockerfile.read_bytes()
            bridge_lock_raw = self.bridge_lock.read_bytes()
            for path, raw in (
                (backup / "release.env", authentic["release_env"]),
                (
                    backup / "RELEASE-EVIDENCE.json",
                    authentic["release_evidence"],
                ),
                (backup / "SUPPLY-CHAIN.json", authentic["supply_evidence"]),
                (backup / "SUPPLY-CHAIN.sig", authentic["supply_signature"]),
                (backup / "SUPPLY-CHAIN.pub", authentic["supply_public_key"]),
                (previous_policy_path, previous_policy_raw),
                (
                    backup / "successor-authority/Dockerfile.analyzer",
                    dockerfile_raw,
                ),
                (
                    backup / "successor-authority/bridge-package-lock.json",
                    bridge_lock_raw,
                ),
            ):
                self.write_private(path, raw)
            runtime_raw = b"synthetic-runtime-manifest\n"
            apply_raw = b"schema=synthetic-gen4-apply\n"
            self.write_private(backup / "runtime/SHA256SUMS", runtime_raw)
            self.write_private(backup / "APPLY.receipt", apply_raw)
            control_sources = {
                "RELEASE-EVIDENCE.json": authentic["release_evidence"],
                "release.env": authentic["release_env"],
                "SUPPLY-CHAIN.json": authentic["supply_evidence"],
                "SUPPLY-CHAIN.sig": authentic["supply_signature"],
                "SUPPLY-CHAIN.pub": authentic["supply_public_key"],
                "successor-authority/successor-policy.json": previous_policy_raw,
                "successor-authority/Dockerfile.analyzer": dockerfile_raw,
                "successor-authority/bridge-package-lock.json": bridge_lock_raw,
            }
            control_raw = "".join(
                f"{hashlib.sha256(raw).hexdigest()}  {relative}\n"
                for relative, raw in control_sources.items()
            ).encode("utf-8")
            self.write_private(backup / "CONTROL.sha256", control_raw)

            current = {
                "backup_dir": str(backup),
                "apply_receipt_sha256": hashlib.sha256(apply_raw).hexdigest(),
                "control_sha256": hashlib.sha256(control_raw).hexdigest(),
                "release_evidence_sha256": hashlib.sha256(
                    authentic["release_evidence"]
                ).hexdigest(),
                "runtime_backup_manifest_sha256": hashlib.sha256(
                    runtime_raw
                ).hexdigest(),
            }
            current_raw = assembler.json_bytes(current)
            current_path = self.root / "CURRENT.json"
            self.write_private(current_path, current_raw)
            current_policy = copy.deepcopy(self.policy)
            current_policy["predecessor"].update(
                {
                    "current_state_sha256": hashlib.sha256(
                        current_raw
                    ).hexdigest(),
                    "apply_receipt_sha256": hashlib.sha256(
                        apply_raw
                    ).hexdigest(),
                    "control_sha256": hashlib.sha256(control_raw).hexdigest(),
                    "release_evidence_sha256": hashlib.sha256(
                        authentic["release_evidence"]
                    ).hexdigest(),
                    "runtime_manifest_sha256": hashlib.sha256(
                        runtime_raw
                    ).hexdigest(),
                }
            )
            current_policy_raw = assembler.json_bytes(current_policy)
            carrier_names = {
                "rikune.release.env": "release_env",
                "SUPPLY-CHAIN.json": "supply_evidence",
                "SUPPLY-CHAIN.sig": "supply_signature",
                "release-authority.pub": "supply_public_key",
            }

            def write_carrier(bundle: dict[str, bytes]) -> None:
                for filename, key in carrier_names.items():
                    path = previous_root / filename
                    path.write_bytes(bundle[key])
                    path.chmod(0o600)

            write_carrier(authentic)
            completion = {
                "release_env_sha256": hashlib.sha256(
                    authentic["release_env"]
                ).hexdigest(),
                "release_evidence_sha256": hashlib.sha256(
                    authentic["release_evidence"]
                ).hexdigest(),
                "control_sha256": hashlib.sha256(control_raw).hexdigest(),
                "runtime_backup_manifest_sha256": hashlib.sha256(
                    runtime_raw
                ).hexdigest(),
            }
            with mock.patch.object(
                assembler.successor_binding,
                "validate_gen4_current",
                side_effect=lambda value, **_kwargs: value,
            ), mock.patch.object(
                assembler.successor_binding,
                "validate_gen4_apply_completion",
                return_value=completion,
            ) as completion_validator:
                previous_release, previous_document = (
                    assembler.validate_previous_release(
                        previous_root,
                        previous_policy_path,
                        current_path,
                        estate,
                        current_policy,
                        current_policy_raw,
                        self.root,
                    )
                )
                self.assertEqual(
                    previous_release["NEWAPI_IMAGE"],
                    json.loads(
                        authentic["release_evidence"].decode("utf-8")
                    )["release"]["NEWAPI_IMAGE"],
                )
                self.assertEqual(previous_document["schema_version"], 4)
                completion_validator.assert_called_once()

                real_run = subprocess.run
                observed_command: list[str] = []

                def swap_carrier_then_validate_snapshot(
                    command: list[str], **kwargs: object
                ) -> subprocess.CompletedProcess[bytes]:
                    observed_command.extend(command)
                    write_carrier(alternate)
                    return real_run(command, **kwargs)

                completion_validator.reset_mock()
                with mock.patch.object(
                    assembler.subprocess,
                    "run",
                    side_effect=swap_carrier_then_validate_snapshot,
                ):
                    swapped_release, _ = assembler.validate_previous_release(
                        previous_root,
                        previous_policy_path,
                        current_path,
                        estate,
                        current_policy,
                        current_policy_raw,
                        self.root,
                    )
                self.assertEqual(
                    swapped_release["NEWAPI_IMAGE"],
                    previous_release["NEWAPI_IMAGE"],
                )
                self.assertIn("--release-evidence", observed_command)
                for option in (
                    "--release-env",
                    "--evidence",
                    "--signature",
                    "--public-key",
                    "--successor-policy",
                    "--release-evidence",
                ):
                    selected = Path(observed_command[observed_command.index(option) + 1])
                    self.assertIn("holdfast-supply-v4-snapshot-", selected.parent.name)
                    self.assertNotEqual(selected.parent, previous_root)

                with self.assertRaisesRegex(ValueError, "authenticated backup"):
                    assembler.validate_previous_release(
                        previous_root,
                        previous_policy_path,
                        current_path,
                        estate,
                        current_policy,
                        current_policy_raw,
                        self.root,
                    )

    def test_oci_blob_graph_rejects_missing_or_tampered_runtime_layer(self) -> None:
        layout = self.root / "layout"
        blob_root = layout / "blobs" / "sha256"
        blob_root.mkdir(parents=True)
        layout.chmod(0o700)
        (layout / "blobs").chmod(0o700)
        blob_root.chmod(0o700)
        raw = b"runtime-layer-bytes"
        digest = hashlib.sha256(raw).hexdigest()
        blob = blob_root / digest
        blob.write_bytes(raw)
        blob.chmod(0o600)
        descriptor = {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": f"sha256:{digest}",
            "size": len(raw),
        }
        assembler.verify_layout_blob(
            layout, descriptor, "runtime layer", maximum_size=1024
        )
        blob.write_bytes(b"Runtime-layer-bytes")
        with self.assertRaisesRegex(ValueError, "content differs"):
            assembler.verify_layout_blob(
                layout, descriptor, "runtime layer", maximum_size=1024
            )
        blob.unlink()
        with self.assertRaises(OSError):
            assembler.verify_layout_blob(
                layout, descriptor, "runtime layer", maximum_size=1024
            )

    def test_signature_shape_and_schema_downgrade_are_rejected(self) -> None:
        release, document = self.assemble()
        document["registry_verification"]["images"]["STRAD_IMAGE"]["signature"][
            "mode"
        ] = "key"
        with self.assertRaisesRegex(ValueError, "field set is not exact"):
            validator.validate_document(document, release, "0" * 64, self.policy)

        _, downgraded = self.assemble()
        downgraded["schema_version"] = 3
        downgraded.pop("fresh_image_bindings")
        with self.assertRaisesRegex(ValueError, "schema.*policy schema differ"):
            validator.validate_document(downgraded, release, "0" * 64, self.policy)

    def test_schema4_fresh_signer_roles_cannot_be_recomputed_away(self) -> None:
        mutations = (
            (
                "access-keyless",
                "ACCESS_GOVERNANCE_IMAGE",
                lambda record: record.__setitem__(
                    "signature",
                    {
                        "identity": validator.STRAD_COSIGN_IDENTITY,
                        "issuer": validator.STRAD_COSIGN_ISSUER,
                        "rekor_log_index": 1,
                    },
                ),
            ),
            (
                "access-alternate-key",
                "ACCESS_GOVERNANCE_IMAGE",
                lambda record: (
                    record.__setitem__(
                        "signature",
                        {
                            "mode": "key",
                            "public_key_sha256": "0" * 64,
                            "rekor_log_index": 1,
                        },
                    ),
                    record["provenance"].__setitem__(
                        "builder_id",
                        "https://w33d.xyz/holdfast/builders/local-root/v1?"
                        f"cosign-sha256={'0' * 64}",
                    ),
                ),
            ),
            (
                "strad-keyed",
                "STRAD_IMAGE",
                lambda record: record.__setitem__(
                    "signature",
                    {
                        "mode": "key",
                        "public_key_sha256": validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256,
                        "rekor_log_index": 1,
                    },
                ),
            ),
            (
                "analyzer-identity",
                "STRAD_ANALYZER_IMAGE",
                lambda record: record["signature"].__setitem__(
                    "identity", "https://github.com/example/other/release.yml@main"
                ),
            ),
            (
                "analyzer-issuer",
                "STRAD_ANALYZER_IMAGE",
                lambda record: record["signature"].__setitem__(
                    "issuer", "https://issuer.example"
                ),
            ),
        )
        for label, image_key, mutate in mutations:
            release, document = self.assemble()
            images = document["registry_verification"]["images"]
            record = images[image_key]
            mutate(record)
            document["fresh_image_bindings"][image_key]["record_sha256"] = (
                validator.canonical_object_sha256(record)
            )
            with self.subTest(label=label), self.assertRaises(ValueError):
                validator.validate_document(document, release, "0" * 64, self.policy)

    def test_schema4_verifier_is_pinned_and_manifest_cross_bound(self) -> None:
        mutations = (
            (
                "image",
                validator.COSIGN_VERIFIER_IMAGE,
                "ghcr.io/example/cosign@sha256:" + "0" * 64,
            ),
            (
                "trusted-root",
                validator.SIGSTORE_TRUSTED_ROOT_SHA256,
                "0" * 64,
            ),
            ("manifest", "f" * 64, "0" * 64),
        )
        for label, original, replacement in mutations:
            release, document = self.assemble()
            registry = document["registry_verification"]
            registry["verifier"] = registry["verifier"].replace(
                original, replacement
            )
            with self.subTest(label=label), self.assertRaises(ValueError):
                validator.validate_document(document, release, "0" * 64, self.policy)

    def test_finalize_rejects_invalid_detached_signature_without_output(self) -> None:
        private_key = self.root / "authority.key"
        public_key = self.root / "authority.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_sha = hashlib.sha256(public_key.read_bytes()).hexdigest()
        release, document = self.assemble(supply_public_key_sha256=public_sha)
        evidence = self.root / "SUPPLY-CHAIN.json"
        evidence.write_bytes(assembler.json_bytes(document))
        evidence.chmod(0o600)
        release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = hashlib.sha256(
            evidence.read_bytes()
        ).hexdigest()
        unsigned = self.root / "rikune.release.env.unsigned"
        unsigned.write_bytes(
            assembler.unsigned_env_bytes(
                release, set(validator.SUCCESSOR_RELEASE_KEYS)
            )
        )
        unsigned.chmod(0o600)
        invalid_signature = self.root / "SUPPLY-CHAIN.sig"
        invalid_signature.write_bytes(b"not-a-valid-signature\n")
        invalid_signature.chmod(0o600)
        valid_signature = self.root / "SUPPLY-CHAIN.valid.sig"
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(valid_signature),
                str(evidence),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        destination = self.root / "rikune.release.env"
        args = SimpleNamespace(
            release_root=self.root,
            unsigned_release_env=unsigned,
            evidence=evidence,
            signature=invalid_signature,
            public_key=public_key,
            successor_policy=OPS_ROOT / "successor-policy.json",
            dockerfile=self.dockerfile,
            bridge_lock=self.bridge_lock,
            output_release_env=destination,
        )
        real_run = subprocess.run

        def swap_original_then_validate_snapshot(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            invalid_signature.write_bytes(valid_signature.read_bytes())
            invalid_signature.chmod(0o600)
            return real_run(command, **kwargs)

        with mock.patch.object(
            assembler, "validate_checkout_revision"
        ), mock.patch.object(
            assembler.subprocess,
            "run",
            side_effect=swap_original_then_validate_snapshot,
        ), self.assertRaisesRegex(ValueError, "production schema-v4 validation"):
            assembler.finalize_env(args)
        self.assertFalse(destination.exists())

    def test_finalize_rejects_valid_bundle_swap_after_snapshot_validation(self) -> None:
        private_key = self.root / "swap-authority.key"
        public_key = self.root / "swap-authority.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_sha = hashlib.sha256(public_key.read_bytes()).hexdigest()
        release, document_a = self.assemble(supply_public_key_sha256=public_sha)
        evidence = self.root / "SWAP-SUPPLY-CHAIN.json"
        evidence.write_bytes(assembler.json_bytes(document_a))
        evidence.chmod(0o600)
        signature = self.root / "SWAP-SUPPLY-CHAIN.sig"
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature),
                str(evidence),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = hashlib.sha256(
            evidence.read_bytes()
        ).hexdigest()
        unsigned = self.root / "swap.release.env.unsigned"
        unsigned.write_bytes(
            assembler.unsigned_env_bytes(
                release, set(validator.SUCCESSOR_RELEASE_KEYS)
            )
        )
        unsigned.chmod(0o600)

        document_b = copy.deepcopy(document_a)
        document_b["issued_at"] = "2026-08-30T00:00:01Z"
        alternate_evidence = self.root / "alternate-SUPPLY-CHAIN.json"
        alternate_evidence.write_bytes(assembler.json_bytes(document_b))
        alternate_signature = self.root / "alternate-SUPPLY-CHAIN.sig"
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(alternate_signature),
                str(alternate_evidence),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        destination = self.root / "rikune.release.env"
        args = SimpleNamespace(
            release_root=self.root,
            unsigned_release_env=unsigned,
            evidence=evidence,
            signature=signature,
            public_key=public_key,
            successor_policy=OPS_ROOT / "successor-policy.json",
            dockerfile=self.dockerfile,
            bridge_lock=self.bridge_lock,
            output_release_env=destination,
        )
        real_run = subprocess.run

        def swap_valid_bundle(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            evidence.write_bytes(alternate_evidence.read_bytes())
            signature.write_bytes(alternate_signature.read_bytes())
            evidence.chmod(0o600)
            signature.chmod(0o600)
            return real_run(command, **kwargs)

        with mock.patch.object(
            assembler, "validate_checkout_revision"
        ), mock.patch.object(
            assembler.subprocess, "run", side_effect=swap_valid_bundle
        ), self.assertRaisesRegex(ValueError, "changed after snapshot validation"):
            assembler.finalize_env(args)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
