#!/usr/bin/env python3
"""Validate checksum-bound Holdfast release evidence without contacting live systems."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

from successor_binding import validate_policy as validate_successor_policy


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
UPSTREAM_PREFIX = "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:"
RELATION = "strad-bridge-overlay-built-from-rikune-static-base"
SUCCESSOR_POLICY = Path(__file__).with_name("successor-policy.json")
SUCCESSOR_GENERATOR = "holdfast-rikune-estate/2.0.0"
SUCCESSOR_BUILD_INPUT_SCHEMA = "access-build-input/2"
SUCCESSOR_ROOT_FIELDS = {
    "schema_version",
    "generator",
    "catalog_only",
    "permission_catalog_sha256",
    "package_catalog_sha256",
    "access_governance_build_input_sha256",
    "route_up_sha256",
    "route_down_sha256",
    "authz_manifest_sha256",
    "secret_references",
    "release",
    "release_mode",
    "access_governance_build_input_schema",
    "predecessor_binding",
    "successor_delta_sha256",
    "holdfast_release_tool_revision",
}
SUCCESSOR_FULL_FIELDS = {
    "release_env_sha256",
    "supply_chain_binding",
    "analyzer_image_binding",
}
BASE_RELEASE_KEYS = {
    "ACCESS_GOVERNANCE_IMAGE",
    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
    "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256",
    "PERMISSION_CATALOG_SHA256",
    "PACKAGE_CATALOG_SHA256",
    "RIKUNE_ACCEPTANCE_SUBJECT",
    "RIKUNE_ANALYZER_IMAGE",
    "STRAD_ANALYZER_IMAGE",
    "STRAD_IMAGE",
    "STRAD_VOLUME_INIT_IMAGE",
    "STRAD_REVISION",
    "STRAD_NEWAPI_MODEL",
    "STRAD_RUST_BUILDER_IMAGE",
    "STRAD_RUNTIME_IMAGE",
    "STRAD_NODE_BUILDER_IMAGE",
    "VERDICT_IMAGE",
    "NEWAPI_IMAGE",
    "SLUICE_IMAGE",
    "AUTHORITY_PUBLIC_KEY_SHA256",
    "SUPPLY_CHAIN_PUBLIC_KEY_SHA256",
    "SUPPLY_CHAIN_EVIDENCE_SHA256",
    "SUPPLY_CHAIN_SIGNATURE_SHA256",
}
SUCCESSOR_RELEASE_KEYS = BASE_RELEASE_KEYS | {"HOLDFAST_RELEASE_TOOL_REVISION"}
SUCCESSOR_SEMANTIC_HASH_FIELDS = {
    "permission_catalog_sha256",
    "package_catalog_sha256",
    "access_governance_build_input_sha256",
    "route_up_sha256",
    "route_down_sha256",
    "authz_manifest_sha256",
}
SECRET_REFERENCES = [
    "STRAD_DATABASE_URL",
    "STRAD_BRIDGE_TOKEN",
    "RIKUNE_FILE_SERVER_API_KEY",
    "STRAD_NEWAPI_KEY",
]


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


def validate_successor_evidence(
    value: dict[str, Any],
    catalog_only: bool,
    release: dict[str, Any],
    successor_policy_path: Path,
) -> None:
    policy = validate_successor_policy(successor_policy_path)
    policy_version = policy["schema_version"]
    expected_root = set(SUCCESSOR_ROOT_FIELDS)
    if not catalog_only:
        expected_root.update(SUCCESSOR_FULL_FIELDS)
    if set(value) != expected_root:
        fail("successor release evidence field set is not exact")
    if (
        value.get("generator") != SUCCESSOR_GENERATOR
        or value.get("release_mode") != "successor"
        or value.get("access_governance_build_input_schema")
        != SUCCESSOR_BUILD_INPUT_SCHEMA
    ):
        fail("successor release mode, generator, or build-input schema differs")
    for field in SUCCESSOR_SEMANTIC_HASH_FIELDS | {"successor_delta_sha256"}:
        if not isinstance(value.get(field), str) or not HEX64.fullmatch(value[field]):
            fail(f"invalid successor release checksum: {field}")
    tool_revision = value.get("holdfast_release_tool_revision")
    if not isinstance(tool_revision, str) or not HEX40.fullmatch(tool_revision):
        fail("invalid Holdfast release-tool revision")
    if value.get("secret_references") != SECRET_REFERENCES:
        fail("successor secret reference set or order differs")

    predecessor_policy = policy["predecessor"]
    successor_policy = policy["successor"]
    predecessor = value.get("predecessor_binding")
    if not isinstance(predecessor, dict) or predecessor != predecessor_policy:
        fail("successor predecessor binding differs from the frozen policy")
    policy_bindings = {
        "generator": successor_policy["generator"],
        "access_governance_build_input_schema": successor_policy[
            "access_build_input_schema"
        ],
        "access_governance_build_input_sha256": successor_policy[
            "access_build_input_sha256"
        ],
        "permission_catalog_sha256": predecessor_policy[
            "permission_catalog_sha256"
        ],
        "package_catalog_sha256": predecessor_policy["package_catalog_sha256"],
    }
    for field, expected in policy_bindings.items():
        if value.get(field) != expected:
            fail(f"successor evidence differs from frozen policy: {field}")
    expected_delta = "".join(
        f"{item['before_sha256'] or '0' * 64}  {item['after_sha256']}  {item['path']}\n"
        for item in policy["overlay"]
    )
    if value.get("successor_delta_sha256") != hashlib.sha256(
        expected_delta.encode("utf-8")
    ).hexdigest():
        fail("successor delta checksum differs from the frozen policy")

    if catalog_only:
        if release:
            fail("catalog-only successor evidence must not contain release pins")
        return
    if set(release) != SUCCESSOR_RELEASE_KEYS:
        fail("successor release pin field set is not exact")
    if release.get("HOLDFAST_RELEASE_TOOL_REVISION") != tool_revision:
        fail("successor release-tool revision differs from the release pin")
    if release.get("ACCESS_GOVERNANCE_ROLLBACK_IMAGE") != predecessor["access_image"]:
        fail("successor rollback image is not the immediate predecessor candidate")
    if policy_version == 4 and release.get(
        "ACCESS_GOVERNANCE_IMAGE"
    ) == release.get("ACCESS_GOVERNANCE_ROLLBACK_IMAGE"):
        fail("schema 4 Access candidate and rollback images must differ")
    semantic_release_fields = {
        "access_governance_build_input_sha256": "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256",
        "permission_catalog_sha256": "PERMISSION_CATALOG_SHA256",
        "package_catalog_sha256": "PACKAGE_CATALOG_SHA256",
    }
    for evidence_field, release_field in semantic_release_fields.items():
        if value[evidence_field] != release.get(release_field):
            fail(f"successor release semantic binding differs: {evidence_field}")


def validate_evidence(
    value: dict[str, Any], successor_policy_path: Path = SUCCESSOR_POLICY
) -> None:
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version not in (1, 2):
        fail("unsupported evidence schema")
    catalog_only = value.get("catalog_only")
    if not isinstance(catalog_only, bool):
        fail("catalog_only must be a boolean")
    release = value.get("release")
    if not isinstance(release, dict):
        fail("release must be an object")
    if schema_version == 2:
        validate_successor_evidence(
            value, catalog_only, release, successor_policy_path.absolute()
        )
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
    parser.add_argument("--successor-policy", type=Path)
    args = parser.parse_args()
    try:
        policy_path = (
            args.successor_policy.absolute()
            if args.successor_policy is not None
            else SUCCESSOR_POLICY
        )
        validate_evidence(read_evidence(args.evidence.absolute()), policy_path)
    except (OSError, ValueError) as error:
        print(f"holdfast evidence: {error}", file=sys.stderr)
        return 1
    print("Holdfast release evidence is structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
