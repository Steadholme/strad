#!/usr/bin/env python3
"""Validate checksum-bound Holdfast release evidence without contacting live systems."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
UPSTREAM_PREFIX = "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:"
RELATION = "strad-bridge-overlay-built-from-rikune-static-base"


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_evidence(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail("evidence must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read evidence: {error}")
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value


def validate_evidence(value: dict[str, Any]) -> None:
    if value.get("schema_version") != 1:
        fail("unsupported evidence schema")
    catalog_only = value.get("catalog_only")
    if not isinstance(catalog_only, bool):
        fail("catalog_only must be a boolean")
    release = value.get("release")
    if not isinstance(release, dict):
        fail("release must be an object")
    if catalog_only:
        if release or "analyzer_image_binding" in value or "supply_chain_binding" in value:
            fail("catalog-only evidence must not claim an analyzer image binding")
        return

    if not isinstance(value.get("release_env_sha256"), str) or not HEX64.fullmatch(
        value["release_env_sha256"]
    ):
        fail("release env identity is absent")
    supply = value.get("supply_chain_binding")
    if not isinstance(supply, dict) or set(supply) != {
        "evidence_sha256",
        "signature_sha256",
        "public_key_sha256",
        "platform",
    }:
        fail("supply-chain binding field set is not exact")
    expected_supply = {
        "evidence_sha256": release.get("SUPPLY_CHAIN_EVIDENCE_SHA256"),
        "signature_sha256": release.get("SUPPLY_CHAIN_SIGNATURE_SHA256"),
        "public_key_sha256": release.get("SUPPLY_CHAIN_PUBLIC_KEY_SHA256"),
        "platform": "linux/amd64",
    }
    for key, expected_value in expected_supply.items():
        if supply.get(key) != expected_value:
            fail(f"supply-chain binding differs: {key}")
    for key in ("evidence_sha256", "signature_sha256", "public_key_sha256"):
        if not isinstance(supply[key], str) or not HEX64.fullmatch(supply[key]):
            fail(f"invalid supply-chain checksum: {key}")

    base = release.get("RIKUNE_ANALYZER_IMAGE")
    overlay = release.get("STRAD_ANALYZER_IMAGE")
    for label, image in (("RIKUNE_ANALYZER_IMAGE", base), ("STRAD_ANALYZER_IMAGE", overlay)):
        if not isinstance(image, str) or not IMAGE_DIGEST.fullmatch(image):
            fail(f"{label} must be an immutable lowercase sha256 repository digest")
    if not base.startswith(UPSTREAM_PREFIX):
        fail("RIKUNE_ANALYZER_IMAGE must use the authoritative static repository")
    if base == overlay:
        fail("upstream analyzer base and Strad bridge overlay must differ")

    binding = value.get("analyzer_image_binding")
    if not isinstance(binding, dict):
        fail("analyzer image binding is absent")
    expected = {
        "schema_version": 1,
        "relation": RELATION,
        "base_build_arg": "RIKUNE_ANALYZER_IMAGE",
        "base_image": base,
        "overlay_image": overlay,
        "dockerfile": "strad/Dockerfile.analyzer",
        "bridge_lock": "strad/bridge/package-lock.json",
        "source_revision": release.get("STRAD_REVISION"),
    }
    for key, expected_value in expected.items():
        if binding.get(key) != expected_value:
            fail(f"analyzer image binding field mismatch: {key}")
    if set(binding) != {
        *expected,
        "dockerfile_sha256",
        "bridge_lock_sha256",
    }:
        fail("analyzer image binding contains an unexpected field set")
    for key in ("dockerfile_sha256", "bridge_lock_sha256"):
        if not isinstance(binding.get(key), str) or not HEX64.fullmatch(binding[key]):
            fail(f"invalid analyzer binding checksum: {key}")
    if not isinstance(binding["source_revision"], str) or not HEX40.fullmatch(
        binding["source_revision"]
    ):
        fail("invalid analyzer binding source revision")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_evidence(read_evidence(args.evidence.absolute()))
    except ValueError as error:
        print(f"holdfast evidence: {error}", file=sys.stderr)
        return 1
    print("Holdfast release evidence is structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
