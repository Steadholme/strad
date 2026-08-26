from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


OPS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS_ROOT))

import render  # noqa: E402
import validate_release_evidence  # noqa: E402


class AnalyzerImageBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = render.parse_env(Path(__file__).with_name("release.test.env"))

    def evidence(self) -> dict:
        base = self.release["RIKUNE_ANALYZER_IMAGE"]
        overlay = self.release["STRAD_ANALYZER_IMAGE"]
        return {
            "schema_version": 1,
            "catalog_only": False,
            "release_env_sha256": "9" * 64,
            "release": copy.deepcopy(self.release),
            "supply_chain_binding": {
                "evidence_sha256": self.release["SUPPLY_CHAIN_EVIDENCE_SHA256"],
                "signature_sha256": self.release["SUPPLY_CHAIN_SIGNATURE_SHA256"],
                "public_key_sha256": self.release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"],
                "platform": "linux/amd64",
            },
            "analyzer_image_binding": {
                "schema_version": 1,
                "relation": "strad-bridge-overlay-built-from-rikune-static-base",
                "base_build_arg": "RIKUNE_ANALYZER_IMAGE",
                "base_image": base,
                "overlay_image": overlay,
                "dockerfile": "strad/Dockerfile.analyzer",
                "dockerfile_sha256": "1" * 64,
                "bridge_lock": "strad/bridge/package-lock.json",
                "bridge_lock_sha256": "2" * 64,
                "source_revision": self.release["STRAD_REVISION"],
            },
        }

    def successor_evidence(self, *, catalog_only: bool = False) -> dict:
        policy = json.loads(
            (OPS_ROOT / "successor-policy.json").read_text(encoding="utf-8")
        )
        release = copy.deepcopy(self.release)
        release.update(
            {
                "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": policy["predecessor"][
                    "access_image"
                ],
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": policy["successor"][
                    "access_build_input_sha256"
                ],
                "PERMISSION_CATALOG_SHA256": policy["predecessor"][
                    "permission_catalog_sha256"
                ],
                "PACKAGE_CATALOG_SHA256": policy["predecessor"][
                    "package_catalog_sha256"
                ],
                "HOLDFAST_RELEASE_TOOL_REVISION": "a" * 40,
            }
        )
        successor_delta = "".join(
            f"{item['before_sha256'] or '0' * 64}  {item['after_sha256']}  {item['path']}\n"
            for item in policy["overlay"]
        )
        value = {
            "schema_version": 2,
            "generator": "holdfast-rikune-estate/2.0.0",
            "catalog_only": catalog_only,
            "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
            "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
            "access_governance_build_input_sha256": release[
                "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"
            ],
            "route_up_sha256": "3" * 64,
            "route_down_sha256": "4" * 64,
            "authz_manifest_sha256": "5" * 64,
            "secret_references": [
                "STRAD_DATABASE_URL",
                "STRAD_BRIDGE_TOKEN",
                "RIKUNE_FILE_SERVER_API_KEY",
                "STRAD_NEWAPI_KEY",
            ],
            "release": {} if catalog_only else release,
            "release_mode": "successor",
            "access_governance_build_input_schema": "access-build-input/2",
            "predecessor_binding": copy.deepcopy(policy["predecessor"]),
            "successor_delta_sha256": hashlib.sha256(
                successor_delta.encode("utf-8")
            ).hexdigest(),
            "holdfast_release_tool_revision": "a" * 40,
        }
        if not catalog_only:
            base = release["RIKUNE_ANALYZER_IMAGE"]
            overlay = release["STRAD_ANALYZER_IMAGE"]
            value.update(
                {
                    "release_env_sha256": "9" * 64,
                    "supply_chain_binding": {
                        "evidence_sha256": release[
                            "SUPPLY_CHAIN_EVIDENCE_SHA256"
                        ],
                        "signature_sha256": release[
                            "SUPPLY_CHAIN_SIGNATURE_SHA256"
                        ],
                        "public_key_sha256": release[
                            "SUPPLY_CHAIN_PUBLIC_KEY_SHA256"
                        ],
                        "platform": "linux/amd64",
                    },
                    "analyzer_image_binding": {
                        "schema_version": 1,
                        "relation": "strad-bridge-overlay-built-from-rikune-static-base",
                        "base_build_arg": "RIKUNE_ANALYZER_IMAGE",
                        "base_image": base,
                        "overlay_image": overlay,
                        "dockerfile": "strad/Dockerfile.analyzer",
                        "dockerfile_sha256": "1" * 64,
                        "bridge_lock": "strad/bridge/package-lock.json",
                        "bridge_lock_sha256": "2" * 64,
                        "source_revision": release["STRAD_REVISION"],
                    },
                }
            )
        return value

    def test_release_accepts_distinct_digest_bound_base_and_overlay(self) -> None:
        render.validate_release(self.release, False)
        validate_release_evidence.validate_evidence(self.evidence())

    def test_release_rejects_equal_base_and_overlay(self) -> None:
        invalid = copy.deepcopy(self.release)
        invalid["STRAD_ANALYZER_IMAGE"] = invalid["RIKUNE_ANALYZER_IMAGE"]
        with self.assertRaises(SystemExit):
            render.validate_release(invalid, False)

        evidence = self.evidence()
        evidence["release"]["STRAD_ANALYZER_IMAGE"] = evidence["release"][
            "RIKUNE_ANALYZER_IMAGE"
        ]
        evidence["analyzer_image_binding"]["overlay_image"] = evidence["release"][
            "RIKUNE_ANALYZER_IMAGE"
        ]
        with self.assertRaisesRegex(ValueError, "must differ"):
            validate_release_evidence.validate_evidence(evidence)

    def test_release_rejects_tags_for_either_image(self) -> None:
        for key in ("RIKUNE_ANALYZER_IMAGE", "STRAD_ANALYZER_IMAGE"):
            invalid = copy.deepcopy(self.release)
            invalid[key] = "registry.invalid/w33d/image:1.0.0"
            with self.subTest(key=key), self.assertRaises(SystemExit):
                render.validate_release(invalid, False)

    def test_release_rejects_missing_acceptance_subject(self) -> None:
        invalid = copy.deepcopy(self.release)
        invalid.pop("RIKUNE_ACCEPTANCE_SUBJECT")
        with self.assertRaisesRegex(SystemExit, "RIKUNE_ACCEPTANCE_SUBJECT"):
            render.validate_release(invalid, False)

    def test_release_rejects_model_alias_outside_runtime_policy(self) -> None:
        for model in (
            "",
            "bad model",
            "model?query",
            "model\\alias",
            "模型",
            "a" * 129,
            "REQUIRED_existing_newapi_alias",
        ):
            invalid = copy.deepcopy(self.release)
            invalid["STRAD_NEWAPI_MODEL"] = model
            with self.subTest(model=model), self.assertRaisesRegex(
                SystemExit, "STRAD_NEWAPI_MODEL"
            ):
                render.validate_release(invalid, False)

    def test_release_rejects_malformed_placeholder_or_privileged_acceptance_subject(
        self,
    ) -> None:
        for subject in (
            "user:usr_<43-char-base64url-sub>",
            "REQUIRED_RIKUNE_ACCEPTANCE_SUBJECT",
            "user:usr_too-short",
            "user:usr_" + "A" * 42,
            "user:usr_" + "A" * 44,
            "user:usr_" + "A" * 42 + "+",
            "user:u_admin",
            "user:w33d",
        ):
            invalid = copy.deepcopy(self.release)
            invalid["RIKUNE_ACCEPTANCE_SUBJECT"] = subject
            with self.subTest(subject=subject), self.assertRaisesRegex(
                SystemExit, "RIKUNE_ACCEPTANCE_SUBJECT"
            ):
                render.validate_release(invalid, False)

    def test_evidence_rejects_unbound_overlay_claim(self) -> None:
        evidence = self.evidence()
        evidence["analyzer_image_binding"]["overlay_image"] = (
            "registry.invalid/w33d/other@sha256:" + "9" * 64
        )
        with self.assertRaisesRegex(ValueError, "overlay_image"):
            validate_release_evidence.validate_evidence(evidence)

    def test_successor_evidence_accepts_exact_catalog_and_full_contracts(self) -> None:
        validate_release_evidence.validate_evidence(
            self.successor_evidence(catalog_only=True)
        )
        validate_release_evidence.validate_evidence(self.successor_evidence())

    def test_successor_evidence_rejects_non_exact_mode_policy_and_tool_binding(
        self,
    ) -> None:
        cases: list[tuple[str, dict, str]] = []

        extra = self.successor_evidence()
        extra["unexpected"] = True
        cases.append(("extra-root", extra, "field set is not exact"))

        old_build_schema = self.successor_evidence()
        old_build_schema["access_governance_build_input_schema"] = (
            "access-build-input/1"
        )
        cases.append(("old-build-schema", old_build_schema, "build-input schema"))

        policy_tamper = self.successor_evidence()
        policy_tamper["predecessor_binding"]["control_sha256"] = "f" * 64
        cases.append(("policy-tamper", policy_tamper, "frozen policy"))

        catalog_build_tamper = self.successor_evidence(catalog_only=True)
        catalog_build_tamper["access_governance_build_input_sha256"] = "f" * 64
        cases.append(
            (
                "catalog-build-policy-tamper",
                catalog_build_tamper,
                "access_governance_build_input_sha256",
            )
        )

        full_build_tamper = self.successor_evidence()
        full_build_tamper["access_governance_build_input_sha256"] = "f" * 64
        full_build_tamper["release"][
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"
        ] = "f" * 64
        cases.append(
            (
                "full-self-consistent-build-policy-tamper",
                full_build_tamper,
                "access_governance_build_input_sha256",
            )
        )

        catalog_permission_tamper = self.successor_evidence(catalog_only=True)
        catalog_permission_tamper["permission_catalog_sha256"] = "f" * 64
        cases.append(
            (
                "catalog-permission-policy-tamper",
                catalog_permission_tamper,
                "permission_catalog_sha256",
            )
        )

        catalog_package_tamper = self.successor_evidence(catalog_only=True)
        catalog_package_tamper["package_catalog_sha256"] = "f" * 64
        cases.append(
            (
                "catalog-package-policy-tamper",
                catalog_package_tamper,
                "package_catalog_sha256",
            )
        )

        delta_tamper = self.successor_evidence(catalog_only=True)
        delta_tamper["successor_delta_sha256"] = "f" * 64
        cases.append(("catalog-delta-policy-tamper", delta_tamper, "delta checksum"))

        invalid_tool = self.successor_evidence()
        invalid_tool["holdfast_release_tool_revision"] = "not-a-commit"
        cases.append(("invalid-tool", invalid_tool, "release-tool revision"))

        mismatched_tool = self.successor_evidence()
        mismatched_tool["release"]["HOLDFAST_RELEASE_TOOL_REVISION"] = "b" * 40
        cases.append(("mismatched-tool", mismatched_tool, "differs from the release pin"))

        wrong_rollback = self.successor_evidence()
        wrong_rollback["release"]["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"] = (
            "registry.invalid/w33d/other@sha256:" + "7" * 64
        )
        cases.append(("wrong-rollback", wrong_rollback, "immediate predecessor"))

        catalog_claim = self.successor_evidence(catalog_only=True)
        catalog_claim["release"] = {
            "HOLDFAST_RELEASE_TOOL_REVISION": "a" * 40
        }
        cases.append(("catalog-release-claim", catalog_claim, "must not contain release pins"))

        for label, evidence, error in cases:
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, error):
                validate_release_evidence.validate_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
