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

import assemble_supply_chain_v5 as assembler  # noqa: E402
import supply_chain_evidence as validator  # noqa: E402


def image(name: str, digit: str) -> str:
    return f"registry.example/w33d/{name}@sha256:{digit * 64}"


class SupplyChainV5AssemblerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="holdfast-supply-v5-test-", dir="/root"
        )
        self.root = Path(self.temp.name)
        source_root = self.root / "sources"
        source_root.mkdir(mode=0o700)
        self.successor_policy = source_root / "successor-policy.json"
        self.successor_policy.write_bytes(
            (OPS_ROOT / "successor-policy.json").read_bytes()
        )
        self.successor_policy.chmod(0o644)
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
        self.revision = "c" * 40
        self.issued_at = (
            datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.recovery_completion = {
            "kind": "holdfast-rikune-recovery-resume-completion-v1",
            "archive": "APPLY-RECOVERY-COMPLETE-20260830T152436Z-2647919.json",
            "archive_sha256": "1" * 64,
            "receipt": "APPLY-RECOVERY-COMPLETE-20260830T152436Z-2647919.receipt",
            "receipt_sha256": "2" * 64,
            "armed_receipt": "APPLY-RECOVERY-ARMED-20260830T152436Z-2647919.receipt",
            "armed_receipt_sha256": "3" * 64,
            "failure_receipt": (
                "APPLY-ACTIVATION-FAILED-20260830T152125Z-2600245.receipt"
            ),
            "failure_receipt_sha256": "4" * 64,
        }
        self.policy = {
            "schema_version": 5,
            "ceremony": "holdfast-rikune-successor-v5",
            "predecessor": {
                "current_state_sha256": "5" * 64,
                "control_sha256": "6" * 64,
                "release_evidence_sha256": "7" * 64,
                "runtime_manifest_sha256": "8" * 64,
                "candidate_evidence_sha256": "9" * 64,
                "candidate_targets_sha256": "a" * 64,
                "access_image": image("access-predecessor", "b"),
                "access_build_input_schema": "access-build-input/2",
                "access_build_input_sha256": "c" * 64,
                "permission_catalog_sha256": "d" * 64,
                "package_catalog_sha256": "e" * 64,
                "recovery_completion": copy.deepcopy(self.recovery_completion),
            },
            "successor": {
                "generator": "holdfast-rikune-estate/2.0.0",
                "access_build_input_schema": "access-build-input/2",
                "source_access_build_input_sha256": (
                    assembler.GEN6_ACCESS_BUILD_INPUT_SHA256
                ),
                "access_build_input_sha256": assembler.GEN6_ACCESS_BUILD_INPUT_SHA256,
            },
            "overlay": [],
        }
        self.previous_release = self.make_previous_release()
        self.previous_document = self.make_previous_document()
        access_builder = (
            "https://w33d.xyz/holdfast/builders/local-root/v1?"
            "cosign-sha256="
            f"{validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256}"
        )
        self.records = {
            "ACCESS_GOVERNANCE_IMAGE": self.make_record(
                image("access-fresh", "1"),
                keyed=True,
                builder=access_builder,
            ),
            "STRAD_IMAGE": self.make_record(image("strad-fresh", "2")),
            "STRAD_ANALYZER_IMAGE": self.make_record(
                image("strad-analyzer-fresh", "3")
            ),
        }
        self.access_receipt = {
            "image": self.records["ACCESS_GOVERNANCE_IMAGE"]["image"],
            "build_input_sha256": assembler.GEN6_ACCESS_BUILD_INPUT_SHA256,
            "holdfast_release_tool_revision": self.revision,
            "provenance_builder_id": access_builder,
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_previous_release(self) -> dict[str, str]:
        release = {
            key: image(key.lower(), format(index + 1, "x")[-1])
            for index, key in enumerate(validator.IMAGE_KEYS)
        }
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
                "AUTHORITY_PUBLIC_KEY_SHA256": "1" * 64,
                "SUPPLY_CHAIN_PUBLIC_KEY_SHA256": "2" * 64,
                "SUPPLY_CHAIN_EVIDENCE_SHA256": "3" * 64,
                "SUPPLY_CHAIN_SIGNATURE_SHA256": "4" * 64,
                "HOLDFAST_RELEASE_TOOL_REVISION": "b" * 40,
            }
        )
        return release

    def make_record(
        self,
        pinned_image: str,
        *,
        keyed: bool = False,
        builder: str = "builder:github",
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
                "identity": validator.STRAD_COSIGN_IDENTITY,
                "issuer": validator.STRAD_COSIGN_ISSUER,
                "rekor_log_index": 1,
            }
        )
        return {
            "image": pinned_image,
            "manifest_digest": digest,
            "registry": pinned_image.split("/", 1)[0],
            "subject_digest": digest,
            "sbom": {"uri": f"oci://{pinned_image}#sbom", "sha256": "5" * 64},
            "provenance": {
                "uri": f"oci://{pinned_image}#provenance",
                "sha256": "6" * 64,
                "builder_id": builder,
            },
            "attestation": {
                "uri": f"oci://{pinned_image}#attestation",
                "sha256": "7" * 64,
            },
            "signature": signature,
        }

    def make_previous_document(self) -> dict[str, object]:
        return {
            "registry_verification": {
                "verified_at": "2026-08-30T15:24:36Z",
                "verifier": "previous-production-verifier",
                "images": {
                    key: self.make_record(self.previous_release[key], keyed=True)
                    for key in validator.IMAGE_KEYS
                },
            },
            "waivers": [],
        }

    def assemble(self) -> tuple[dict[str, str], dict[str, object]]:
        return assembler.assemble_release(
            copy.deepcopy(self.previous_release),
            copy.deepcopy(self.previous_document),
            copy.deepcopy(self.policy),
            copy.deepcopy(self.records),
            copy.deepcopy(self.access_receipt),
            "8" * 64,
            "9" * 64,
            self.revision,
            self.issued_at,
            self.revision,
            "a" * 64,
            (
                "cosign-offline-oci-layout/v1;"
                f"image={validator.COSIGN_VERIFIER_IMAGE};"
                f"trusted_root_sha256={validator.SIGSTORE_TRUSTED_ROOT_SHA256};"
                f"strad_release_manifest_sha256={'9' * 64}"
            ),
            dockerfile=self.dockerfile,
            bridge_lock=self.bridge_lock,
        )

    def test_positive_assembly_binds_gen5_recovery_and_gen6_generation(self) -> None:
        release, document = self.assemble()
        self.assertEqual(document["schema_version"], 5)
        self.assertEqual(
            document["predecessor_current_sha256"],
            self.policy["predecessor"]["current_state_sha256"],
        )
        self.assertEqual(
            document["predecessor_recovery_completion"],
            self.recovery_completion,
        )
        self.assertEqual(document["predecessor_release_generation"], 5)
        self.assertEqual(document["release_generation"], 6)
        self.assertEqual(
            release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
            assembler.GEN6_ACCESS_BUILD_INPUT_SHA256,
        )
        self.assertEqual(
            document["registry_verification"]["images"]["NEWAPI_IMAGE"],
            self.previous_document["registry_verification"]["images"][
                "NEWAPI_IMAGE"
            ],
        )
        validator.validate_document(document, release, "0" * 64, self.policy)

    def test_recovery_authority_and_generation_tampering_is_rejected(self) -> None:
        mutations = (
            (
                "current",
                lambda value: value.__setitem__(
                    "predecessor_current_sha256", "0" * 64
                ),
            ),
            (
                "receipt",
                lambda value: value["predecessor_recovery_completion"].__setitem__(
                    "receipt_sha256", "0" * 64
                ),
            ),
            (
                "predecessor-generation",
                lambda value: value.__setitem__("predecessor_release_generation", 4),
            ),
            (
                "successor-generation",
                lambda value: value.__setitem__("release_generation", 7),
            ),
        )
        for label, mutate in mutations:
            release, document = self.assemble()
            mutate(document)
            with self.subTest(label=label), self.assertRaises(ValueError):
                validator.validate_document(document, release, "0" * 64, self.policy)

    def test_recovery_completion_binding_is_exact_and_attempt_linked(self) -> None:
        validator.validate_recovery_completion_binding_v5(self.recovery_completion)
        for label, mutate in (
            ("extra", lambda value: value.__setitem__("extra", True)),
            (
                "wrong-attempt",
                lambda value: value.__setitem__(
                    "armed_receipt",
                    "APPLY-RECOVERY-ARMED-20260830T152436Z-1.receipt",
                ),
            ),
            (
                "hybrid",
                lambda value: value.__setitem__("apply_receipt_sha256", "0" * 64),
            ),
        ):
            value = copy.deepcopy(self.recovery_completion)
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ValueError):
                validator.validate_recovery_completion_binding_v5(value)

    def test_signed_predecessor_release_must_match_policy_catalogs(self) -> None:
        assembler.validate_predecessor_release_bindings(
            self.previous_release, self.policy["predecessor"]
        )
        bindings = {
            "ACCESS_GOVERNANCE_IMAGE": image("wrong-access", "f"),
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "f" * 64,
            "PERMISSION_CATALOG_SHA256": "f" * 64,
            "PACKAGE_CATALOG_SHA256": "f" * 64,
        }
        for field, replacement in bindings.items():
            release = copy.deepcopy(self.previous_release)
            release[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, field
            ):
                assembler.validate_predecessor_release_bindings(
                    release, self.policy["predecessor"]
                )

    def test_signed_predecessor_receipt_binds_candidate_artifacts(self) -> None:
        evidence_raw = b'{"schema_version":2}\n'
        targets_raw = b"f" * 64 + b"  access-governance/src/lib.rs\n"
        predecessor = copy.deepcopy(self.policy["predecessor"])
        predecessor["candidate_evidence_sha256"] = hashlib.sha256(
            evidence_raw
        ).hexdigest()
        predecessor["candidate_targets_sha256"] = hashlib.sha256(
            targets_raw
        ).hexdigest()
        fields = {
            "schema": "holdfast-access-candidate-build/1",
            "platform": "linux/amd64",
            "image": predecessor["access_image"],
            "build_input_schema": predecessor["access_build_input_schema"],
            "build_input_sha256": predecessor["access_build_input_sha256"],
            "candidate_evidence_sha256": predecessor[
                "candidate_evidence_sha256"
            ],
            "candidate_targets_sha256": predecessor["candidate_targets_sha256"],
            "render_inputs_sha256": "1" * 64,
            "metadata_sha256": "2" * 64,
            "holdfast_release_tool_revision": self.previous_release[
                "HOLDFAST_RELEASE_TOOL_REVISION"
            ],
            "provenance": "mode.max",
            "provenance_builder_id": "https://w33d.xyz/holdfast/builders/test",
            "sbom": "enabled",
        }
        receipt_raw = "".join(
            f"{field}={fields[field]}\n"
            for field in (
                "schema",
                "platform",
                "image",
                "build_input_schema",
                "build_input_sha256",
                "candidate_evidence_sha256",
                "candidate_targets_sha256",
                "render_inputs_sha256",
                "metadata_sha256",
                "holdfast_release_tool_revision",
                "provenance",
                "provenance_builder_id",
                "sbom",
            )
        ).encode()
        document = {
            "fresh_image_bindings": {
                "ACCESS_GOVERNANCE_IMAGE": {
                    "record_sha256": "3" * 64,
                    "build_input_sha256": predecessor[
                        "access_build_input_sha256"
                    ],
                    "candidate_receipt_sha256": hashlib.sha256(
                        receipt_raw
                    ).hexdigest(),
                },
                "STRAD_IMAGE": {},
                "STRAD_ANALYZER_IMAGE": {},
            }
        }
        with tempfile.TemporaryDirectory(
            prefix="holdfast-supply-v5-predecessor-", dir="/root"
        ) as name:
            root = Path(name)
            root.chmod(0o700)
            candidate = root / "rikune-candidate-source"
            candidate.mkdir(mode=0o700)
            paths = {
                root / "ACCESS-BUILD.receipt": receipt_raw,
                candidate / "RELEASE-EVIDENCE.json": evidence_raw,
                candidate / "TARGETS.sha256": targets_raw,
            }
            for path, raw in paths.items():
                path.write_bytes(raw)
                path.chmod(0o600)
            assembler.validate_predecessor_candidate_binding(
                root,
                self.previous_release,
                document,
                predecessor,
            )

            tampered = copy.deepcopy(predecessor)
            tampered["candidate_targets_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "candidate_targets_sha256"):
                assembler.validate_predecessor_candidate_binding(
                    root,
                    self.previous_release,
                    document,
                    tampered,
                )

            (candidate / "TARGETS.sha256").write_bytes(
                targets_raw.replace(b"f", b"e", 1)
            )
            (candidate / "TARGETS.sha256").chmod(0o600)
            with self.assertRaisesRegex(ValueError, "candidate artifact differs"):
                assembler.validate_predecessor_candidate_binding(
                    root,
                    self.previous_release,
                    document,
                    predecessor,
                )

    def test_fresh_set_and_signer_roles_remain_fail_closed(self) -> None:
        missing = copy.deepcopy(self.records)
        missing.pop("STRAD_IMAGE")
        with self.assertRaisesRegex(
            ValueError, "fresh registry record set is not exact"
        ):
            assembler.assemble_release(
                copy.deepcopy(self.previous_release),
                copy.deepcopy(self.previous_document),
                copy.deepcopy(self.policy),
                missing,
                copy.deepcopy(self.access_receipt),
                "8" * 64,
                "9" * 64,
                self.revision,
                self.issued_at,
                self.revision,
                "a" * 64,
                "cosign-offline-oci-layout/v1;invalid",
            )

        release, document = self.assemble()
        document["registry_verification"]["images"]["STRAD_IMAGE"]["signature"] = {
            "mode": "key",
            "public_key_sha256": validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256,
            "rekor_log_index": 1,
        }
        document["fresh_image_bindings"]["STRAD_IMAGE"]["record_sha256"] = (
            validator.canonical_object_sha256(
                document["registry_verification"]["images"]["STRAD_IMAGE"]
            )
        )
        with self.assertRaisesRegex(ValueError, "GitHub keyless authority"):
            validator.validate_document(document, release, "0" * 64, self.policy)

    def test_finalize_accepts_signed_schema5_with_exact_policy(self) -> None:
        self.policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        self.previous_release = self.make_previous_release()
        self.previous_document = self.make_previous_document()
        release, document = self.assemble()

        with tempfile.TemporaryDirectory(
            prefix="holdfast-supply-v5-finalize-", dir="/root"
        ) as name:
            release_root = Path(name)
            release_root.chmod(0o700)
            unsigned = release_root / "rikune.release.env.unsigned"
            evidence = release_root / "SUPPLY-CHAIN.json"
            private_key = release_root / "release-authority.key"
            public_key = release_root / "release-authority.pub"
            signature = release_root / "SUPPLY-CHAIN.sig"
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
            public_key.chmod(0o600)
            release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"] = hashlib.sha256(
                public_key.read_bytes()
            ).hexdigest()
            document["release_pins_sha256"] = validator.release_pins_sha256(
                release
            )
            evidence_raw = assembler.json_bytes(document)
            evidence.write_bytes(evidence_raw)
            release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = hashlib.sha256(
                evidence_raw
            ).hexdigest()
            unsigned.write_bytes(
                assembler.unsigned_env_bytes(
                    release, set(validator.SUCCESSOR_RELEASE_KEYS)
                )
            )
            for path in (unsigned, evidence):
                path.chmod(0o600)
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
            signature.chmod(0o600)
            output = release_root / "rikune.release.env"
            args = SimpleNamespace(
                release_root=release_root,
                unsigned_release_env=unsigned,
                evidence=evidence,
                signature=signature,
                public_key=public_key,
                successor_policy=self.successor_policy,
                dockerfile=self.dockerfile,
                bridge_lock=self.bridge_lock,
                output_release_env=output,
            )
            with mock.patch.object(assembler, "validate_checkout_revision"):
                self.assertEqual(assembler.finalize_env(args), 0)
            final = assembler.parse_release_env_bytes(
                output.read_bytes(),
                set(validator.SUCCESSOR_RELEASE_KEYS),
                "final release env",
            )
            self.assertEqual(
                final["SUPPLY_CHAIN_SIGNATURE_SHA256"],
                hashlib.sha256(signature.read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
