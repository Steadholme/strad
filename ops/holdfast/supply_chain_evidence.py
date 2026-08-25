#!/usr/bin/env python3
"""Validate signed registry provenance and build-input evidence for every release image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
IMAGE_KEYS = (
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
STATIC_LOCK_SHA256 = "32e3ea5103ff73c413062b17ad3bb4e7270fbcd6fd1325f6a7f3dc831bee83ef"


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or path.is_symlink() or mode.st_nlink != 1:
        fail(f"unsafe JSON evidence: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value


def release_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            fail("malformed release env")
        key, value = line.split("=", 1)
        if key in result:
            fail(f"duplicate release key: {key}")
        result[key] = value
    return result


def release_pins_sha256(values: dict[str, str]) -> str:
    excluded = {"SUPPLY_CHAIN_EVIDENCE_SHA256", "SUPPLY_CHAIN_SIGNATURE_SHA256"}
    canonical = "".join(
        f"{key}={values[key]}\n" for key in sorted(values) if key not in excluded
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} field set is not exact")
    return value


def require_hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def validate_document(value: dict[str, Any], release: dict[str, str], release_sha: str) -> None:
    expected_root = {
        "schema_version",
        "issued_at",
        "platform",
        "release_pins_sha256",
        "registry_verification",
        "analyzer_overlay",
        "access_candidate",
    }
    exact_keys(value, expected_root, "evidence")
    if value["schema_version"] != 1 or value["platform"] != "linux/amd64":
        fail("unsupported supply-chain schema or platform")
    if value["release_pins_sha256"] != release_pins_sha256(release):
        fail("supply-chain evidence is not bound to the canonical release pins")
    if not isinstance(value["issued_at"], str) or not value["issued_at"].endswith("Z"):
        fail("issued_at must be an immutable UTC timestamp")

    registry = exact_keys(
        value["registry_verification"], {"verified_at", "verifier", "images"}, "registry"
    )
    if not isinstance(registry["verified_at"], str) or not registry["verified_at"].endswith("Z"):
        fail("registry verification timestamp is invalid")
    if not isinstance(registry["verifier"], str) or len(registry["verifier"]) < 8:
        fail("registry verifier identity is absent")
    images = exact_keys(registry["images"], set(IMAGE_KEYS), "registry images")
    image_fields = {
        "image",
        "manifest_digest",
        "registry",
        "subject_digest",
        "sbom",
        "provenance",
        "attestation",
        "signature",
    }
    material_fields = {"uri", "sha256"}
    for key in IMAGE_KEYS:
        expected_image = release.get(key)
        if not expected_image or not IMAGE.fullmatch(expected_image):
            fail(f"release image pin is invalid: {key}")
        item = exact_keys(images[key], image_fields, key)
        expected_digest = expected_image.rsplit("@", 1)[1]
        if item["image"] != expected_image or item["manifest_digest"] != expected_digest:
            fail(f"registry manifest binding differs for {key}")
        if item["subject_digest"] != expected_digest:
            fail(f"attested subject digest differs for {key}")
        if not isinstance(item["registry"], str) or not expected_image.startswith(
            f"{item['registry']}/"
        ):
            fail(f"registry identity differs for {key}")
        for material_name in ("sbom", "attestation"):
            material = exact_keys(item[material_name], material_fields, f"{key} {material_name}")
            if not isinstance(material["uri"], str) or not material["uri"].startswith(
                ("https://", "oci://")
            ):
                fail(f"{key} {material_name} URI is invalid")
            require_hex(material["sha256"], f"{key} {material_name}")
        provenance = exact_keys(
            item["provenance"], {"uri", "sha256", "builder_id"}, f"{key} provenance"
        )
        if not isinstance(provenance["uri"], str) or not provenance["uri"].startswith(
            ("https://", "oci://")
        ):
            fail(f"{key} provenance URI is invalid")
        require_hex(provenance["sha256"], f"{key} provenance")
        if not isinstance(provenance["builder_id"], str) or len(provenance["builder_id"]) < 8:
            fail(f"{key} builder identity is absent")
        signature = exact_keys(
            item["signature"], {"identity", "issuer", "rekor_log_index"}, f"{key} signature"
        )
        if not all(isinstance(signature[name], str) and signature[name] for name in ("identity", "issuer")):
            fail(f"{key} signature identity is incomplete")
        if not isinstance(signature["rekor_log_index"], int) or signature["rekor_log_index"] < 0:
            fail(f"{key} transparency-log binding is invalid")

    overlay = exact_keys(
        value["analyzer_overlay"],
        {
            "base_image",
            "overlay_image",
            "dockerfile_sha256",
            "bridge_lock_sha256",
            "static_lock_sha256",
            "source_revision",
        },
        "analyzer overlay",
    )
    if overlay["base_image"] != release["RIKUNE_ANALYZER_IMAGE"]:
        fail("analyzer overlay base material is not the release base")
    if overlay["overlay_image"] != release["STRAD_ANALYZER_IMAGE"]:
        fail("analyzer overlay output is not the release overlay")
    if overlay["base_image"] == overlay["overlay_image"]:
        fail("analyzer base and overlay must differ")
    for key in ("dockerfile_sha256", "bridge_lock_sha256", "static_lock_sha256"):
        require_hex(overlay[key], f"analyzer overlay {key}")
    if overlay["source_revision"] != release["STRAD_REVISION"] or not HEX40.fullmatch(
        str(overlay["source_revision"])
    ):
        fail("analyzer overlay revision differs from release")

    access = exact_keys(
        value["access_candidate"],
        {
            "image",
            "build_input_sha256",
            "permission_catalog_sha256",
            "package_catalog_sha256",
            "source_revision",
        },
        "Access candidate",
    )
    expected_access = {
        "image": release["ACCESS_GOVERNANCE_IMAGE"],
        "build_input_sha256": release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"],
        "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
        "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
        "source_revision": release["STRAD_REVISION"],
    }
    for key, expected in expected_access.items():
        if access[key] != expected:
            fail(f"Access candidate build input differs: {key}")


def validate_local_binding(value: dict[str, Any], args: argparse.Namespace) -> None:
    overlay = value["analyzer_overlay"]
    if overlay["dockerfile_sha256"] != sha256(args.dockerfile):
        fail("analyzer provenance differs from the local Dockerfile.analyzer")
    if overlay["bridge_lock_sha256"] != sha256(args.bridge_lock):
        fail("analyzer provenance differs from the local bridge lockfile")
    if overlay["static_lock_sha256"] != STATIC_LOCK_SHA256:
        fail("analyzer provenance differs from the frozen Rikune static lock")
    if args.release_evidence is not None:
        release_evidence = load_json(args.release_evidence)
        binding = release_evidence.get("analyzer_image_binding")
        if not isinstance(binding, dict):
            fail("RELEASE-EVIDENCE lacks the analyzer build binding")
        expected = {
            "dockerfile_sha256": overlay["dockerfile_sha256"],
            "bridge_lock_sha256": overlay["bridge_lock_sha256"],
            "base_image": overlay["base_image"],
            "overlay_image": overlay["overlay_image"],
            "source_revision": overlay["source_revision"],
        }
        for field, wanted in expected.items():
            if binding.get(field) != wanted:
                fail(f"supply chain and RELEASE-EVIDENCE differ: {field}")


def verify_signature(evidence: Path, signature: Path, public_key: Path) -> None:
    if sha256(public_key) == "0" * 64:
        fail("public key digest is invalid")
    completed = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(evidence),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0 or "Verified OK" not in completed.stdout:
        fail("detached supply-chain signature verification failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-env", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--dockerfile", required=True, type=Path)
    parser.add_argument("--bridge-lock", required=True, type=Path)
    parser.add_argument("--release-evidence", type=Path)
    args = parser.parse_args()
    try:
        release = release_env(args.release_env)
        pins = {
            "SUPPLY_CHAIN_EVIDENCE_SHA256": sha256(args.evidence),
            "SUPPLY_CHAIN_SIGNATURE_SHA256": sha256(args.signature),
            "SUPPLY_CHAIN_PUBLIC_KEY_SHA256": sha256(args.public_key),
        }
        for key, observed in pins.items():
            if release.get(key) != observed:
                fail(f"{key} differs from the release pin")
        verify_signature(args.evidence, args.signature, args.public_key)
        document = load_json(args.evidence)
        validate_document(document, release, sha256(args.release_env))
        validate_local_binding(document, args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"supply-chain evidence: {error}", file=sys.stderr)
        return 1
    print("signed supply-chain evidence is exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
