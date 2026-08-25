from __future__ import annotations

import copy
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

    def test_evidence_rejects_unbound_overlay_claim(self) -> None:
        evidence = self.evidence()
        evidence["analyzer_image_binding"]["overlay_image"] = (
            "registry.invalid/w33d/other@sha256:" + "9" * 64
        )
        with self.assertRaisesRegex(ValueError, "overlay_image"):
            validate_release_evidence.validate_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
