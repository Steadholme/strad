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
from datetime import datetime, timedelta, timezone
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
MAX_WAIVER_LIFETIME = timedelta(days=30)
MAX_WAIVER_CLOCK_SKEW = timedelta(minutes=5)
WAIVER_POLICY = {
    ("STRAD_RUNTIME_IMAGE", "provenance"): "upstream-provenance-unavailable",
    (
        "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
        "provenance.builder_id",
    ): "legacy-builder-id-unavailable",
    ("VERDICT_IMAGE", "provenance.builder_id"): "legacy-builder-id-unavailable",
    ("NEWAPI_IMAGE", "provenance.builder_id"): "legacy-builder-id-unavailable",
    ("SLUICE_IMAGE", "provenance.builder_id"): "legacy-builder-id-unavailable",
}


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


def require_uri(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith(("https://", "oci://")):
        fail(f"{label} URI is invalid")
    return value


def require_utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        fail(f"{label} must be an RFC3339 UTC timestamp")
    return parsed


def validate_waivers(
    value: object, release: dict[str, str], now: datetime
) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(value, list):
        fail("waivers must be an array")
    waiver_fields = {
        "image_key",
        "image",
        "missing_field",
        "reason_code",
        "ticket_uri",
        "ticket_sha256",
        "approver_identity",
        "issued_at",
        "expires_at",
        "compensating_attestation",
    }
    compensating_fields = {
        "uri",
        "sha256",
        "identity",
        "issuer",
        "rekor_log_index",
    }
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(value):
        waiver = exact_keys(raw, waiver_fields, f"waiver {index}")
        image_key = waiver["image_key"]
        missing_field = waiver["missing_field"]
        if not isinstance(image_key, str) or not isinstance(missing_field, str):
            fail(f"waiver {index} policy key is invalid")
        policy_key = (image_key, missing_field)
        expected_reason = WAIVER_POLICY.get(policy_key)
        if expected_reason is None:
            fail(f"waiver is not permitted for {image_key}.{missing_field}")
        if policy_key in result:
            fail(f"duplicate waiver for {image_key}.{missing_field}")
        expected_image = release.get(image_key)
        if waiver["image"] != expected_image or not isinstance(
            expected_image, str
        ) or not IMAGE.fullmatch(expected_image):
            fail(f"waiver image binding differs for {image_key}")
        if waiver["reason_code"] != expected_reason:
            fail(f"waiver reason differs for {image_key}.{missing_field}")
        ticket_uri = waiver["ticket_uri"]
        if not isinstance(ticket_uri, str) or not ticket_uri.startswith("https://"):
            fail(f"waiver ticket URI is invalid for {image_key}.{missing_field}")
        require_hex(waiver["ticket_sha256"], f"waiver ticket for {image_key}")
        approver = waiver["approver_identity"]
        if not isinstance(approver, str) or len(approver) < 8:
            fail(f"waiver approver identity is absent for {image_key}")
        issued_at = require_utc_timestamp(
            waiver["issued_at"], f"waiver issued_at for {image_key}"
        )
        expires_at = require_utc_timestamp(
            waiver["expires_at"], f"waiver expires_at for {image_key}"
        )
        if expires_at <= issued_at:
            fail(f"waiver expiry is not after issuance for {image_key}")
        if expires_at - issued_at > MAX_WAIVER_LIFETIME:
            fail(f"waiver lifetime exceeds 30 days for {image_key}")
        if issued_at > now + MAX_WAIVER_CLOCK_SKEW:
            fail(f"waiver issuance is in the future for {image_key}")
        if expires_at <= now:
            fail(f"waiver is expired for {image_key}")
        compensating = exact_keys(
            waiver["compensating_attestation"],
            compensating_fields,
            f"waiver compensating attestation for {image_key}",
        )
        require_uri(
            compensating["uri"], f"waiver compensating attestation for {image_key}"
        )
        require_hex(
            compensating["sha256"],
            f"waiver compensating attestation for {image_key}",
        )
        if not all(
            isinstance(compensating[name], str) and compensating[name]
            for name in ("identity", "issuer")
        ):
            fail(f"waiver compensating signature is incomplete for {image_key}")
        if (
            not isinstance(compensating["rekor_log_index"], int)
            or compensating["rekor_log_index"] < 0
        ):
            fail(f"waiver compensating transparency-log binding is invalid for {image_key}")
        result[policy_key] = waiver
    return result


def validate_document(value: dict[str, Any], release: dict[str, str], release_sha: str) -> None:
    schema_version = value.get("schema_version")
    expected_root = {
        "schema_version",
        "issued_at",
        "platform",
        "release_pins_sha256",
        "registry_verification",
        "analyzer_overlay",
        "access_candidate",
    }
    if schema_version == 2:
        expected_root.add("waivers")
    exact_keys(value, expected_root, "evidence")
    if schema_version not in (1, 2) or value["platform"] != "linux/amd64":
        fail("unsupported supply-chain schema or platform")
    if value["release_pins_sha256"] != release_pins_sha256(release):
        fail("supply-chain evidence is not bound to the canonical release pins")
    if not isinstance(value["issued_at"], str) or not value["issued_at"].endswith("Z"):
        fail("issued_at must be an immutable UTC timestamp")
    waivers = (
        validate_waivers(value["waivers"], release, datetime.now(timezone.utc))
        if schema_version == 2
        else {}
    )
    consumed_waivers: set[tuple[str, str]] = set()

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
            require_uri(material["uri"], f"{key} {material_name}")
            require_hex(material["sha256"], f"{key} {material_name}")
        provenance_waiver = (key, "provenance")
        builder_waiver = (key, "provenance.builder_id")
        if provenance_waiver in waivers:
            if item["provenance"] is not None:
                fail(f"{key} provenance waiver does not match an absent provenance")
            consumed_waivers.add(provenance_waiver)
        else:
            provenance = exact_keys(
                item["provenance"],
                {"uri", "sha256", "builder_id"},
                f"{key} provenance",
            )
            require_uri(provenance["uri"], f"{key} provenance")
            require_hex(provenance["sha256"], f"{key} provenance")
            if builder_waiver in waivers:
                if provenance["builder_id"] not in (None, ""):
                    fail(f"{key} builder waiver does not match an absent builder identity")
                consumed_waivers.add(builder_waiver)
            elif not isinstance(provenance["builder_id"], str) or len(
                provenance["builder_id"]
            ) < 8:
                fail(f"{key} builder identity is absent")
        signature = exact_keys(
            item["signature"], {"identity", "issuer", "rekor_log_index"}, f"{key} signature"
        )
        if not all(isinstance(signature[name], str) and signature[name] for name in ("identity", "issuer")):
            fail(f"{key} signature identity is incomplete")
        if not isinstance(signature["rekor_log_index"], int) or signature["rekor_log_index"] < 0:
            fail(f"{key} transparency-log binding is invalid")

    if set(waivers) != consumed_waivers:
        fail("supply-chain evidence contains an unconsumed waiver")

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
