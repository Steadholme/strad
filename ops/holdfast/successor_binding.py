#!/usr/bin/env python3
"""Validate the exact predecessor and policy delta for a Holdfast successor."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn

from recovery_completion_attestation import (
    ATTESTATION_NAME as RECOVERY_ATTESTATION_NAME,
    KIND as RECOVERY_COMPLETION_KIND,
    PUBLIC_KEY_NAME as RECOVERY_PUBLIC_KEY_NAME,
    SIGNATURE_NAME as RECOVERY_SIGNATURE_NAME,
    artifact_result as recovery_artifact_result,
    open_private_directory,
    read_direct_child,
    read_safe_regular,
    verify_raw_bundle,
)
from render_input_binding import (
    ACCESS_BUILD_INPUT_SCHEMA_V1,
    ACCESS_BUILD_INPUT_SCHEMA_V2,
    FROZEN_STATIC_PATHS,
    access_build_input_sha_for_schema,
    access_tree_build_input_sha_v2,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9._/-]+$")
POLICY_CEREMONIES = {
    1: "holdfast-rikune-successor-v1",
    2: "holdfast-rikune-successor-v2",
    3: "holdfast-rikune-successor-v3",
    4: "holdfast-rikune-successor-v4",
}
POLICY_CEREMONY = POLICY_CEREMONIES[1]
BUILD_INPUT_V1 = ACCESS_BUILD_INPUT_SCHEMA_V1
BUILD_INPUT_V2 = ACCESS_BUILD_INPUT_SCHEMA_V2
MAX_SUCCESSOR_OVERLAY_PATHS = 64
RECOVERY_COMPLETION_FIELDS = {
    "kind",
    "attestation_sha256",
    "signature_sha256",
    "public_key_sha256",
}
LEGACY_PREDECESSOR_FIELDS = {
    "current_state_sha256",
    "control_sha256",
    "apply_receipt_sha256",
    "release_evidence_sha256",
    "runtime_manifest_sha256",
    "candidate_evidence_sha256",
    "candidate_targets_sha256",
    "access_image",
    "access_build_input_schema",
    "access_build_input_sha256",
    "permission_catalog_sha256",
    "package_catalog_sha256",
}
RECOVERED_PREDECESSOR_FIELDS = (
    LEGACY_PREDECESSOR_FIELDS - {"apply_receipt_sha256"}
) | {"completion"}
GEN4_APPLY_RECEIPT_FIELDS = {
    "schema_version",
    "completion_state",
    "applied_at",
    "closed_verified_at",
    "estate_root",
    "backup_dir",
    "release_env_sha256",
    "release_evidence_sha256",
    "render_inputs_sha256",
    "apply_armed_receipt_sha256",
    "control_sha256",
    "transaction_sha256",
    "applied_targets_sha256",
    "cargo_gate",
    "runtime_backup",
    "closed_bracket",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "ingress_opened",
    "services_activated",
    "runtime_verified",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_completion_kind",
    "predecessor_completion_attestation_sha256",
    "predecessor_completion_signature_sha256",
    "predecessor_completion_public_key_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
}
GEN4_CURRENT_FIELDS = {
    "schema_version",
    "state",
    "estate_root",
    "backup_dir",
    "apply_receipt_sha256",
    "apply_armed_receipt_sha256",
    "control_sha256",
    "release_evidence_sha256",
    "transaction_sha256",
    "applied_targets_sha256",
    "closed_verified_at",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "services_activated",
    "runtime_verified",
    "ingress_opened",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_completion_kind",
    "predecessor_completion_attestation_sha256",
    "predecessor_completion_signature_sha256",
    "predecessor_completion_public_key_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
}
GEN4_SHARED_COMPLETION_FIELDS = GEN4_CURRENT_FIELDS & GEN4_APPLY_RECEIPT_FIELDS
RECOVERY_COMPLETION_NAMES = (
    RECOVERY_ATTESTATION_NAME,
    RECOVERY_SIGNATURE_NAME,
    RECOVERY_PUBLIC_KEY_NAME,
)
IGNORED_DIRECTORIES = frozenset({".git", ".workflow", "target", "__pycache__"})
SUPPORTING_RELAY_PATHS = frozenset(
    {
        "relay/upstream/new-api/router/enterprise_permissions.json",
        "relay/upstream/new-api/router/newapi-authz-v1.json",
    }
)
SUCCESSOR_STATIC_ASSET_SOURCES = (
    (
        "access-governance/catalog/rikune-authz-v1.json",
        "assets/rikune-authz-v1.json",
    ),
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_regular(path: Path, *, root_owned: bool = True) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"required file is absent: {path}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
    ):
        fail(f"file must be a single-link regular file: {path}")
    if root_owned and metadata.st_uid != 0:
        fail(f"file must be root-owned: {path}")
    return path


def require_directory(path: Path, *, private: bool = False) -> Path:
    if not path.is_absolute() or path == Path("/"):
        fail(f"directory path is unsafe: {path}")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"required directory is absent: {path}")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or path.resolve() != path
        or metadata.st_uid != 0
    ):
        fail(f"directory must be canonical, root-owned and non-symlink: {path}")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        fail(f"directory must not be group/world accessible: {path}")
    return path


def load_json(path: Path) -> dict[str, Any]:
    raw = read_safe_regular(path, "JSON authority")
    return load_json_bytes(raw, path)


def load_json_bytes(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_object
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON authority {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON authority root must be an object: {path}")
    return value


def parse_receipt_bytes(raw: bytes, label: str) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    result: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        if "=" not in line:
            fail(f"{label} line {line_number} is malformed")
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]*", key)
            or not value
            or key in result
        ):
            fail(f"{label} line {line_number} is invalid or duplicate")
        result[key] = value
    if not result:
        fail(f"{label} is empty")
    return result


def validate_gen4_apply_completion(
    raw: bytes,
    predecessor: dict[str, Any],
    estate: Path,
    backup: Path,
    current: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Validate Gen4's APPLY receipt as Gen5 completion authority.

    The embedded Gen3 recovery-completion values are immutable history only;
    schema v4 binds and forwards the APPLY receipt digest, never that namespace.
    """

    if sha256_bytes(raw) != predecessor.get("apply_receipt_sha256"):
        fail("Gen4 APPLY completion digest differs")
    receipt = parse_receipt_bytes(raw, "Gen4 APPLY completion")
    if set(receipt) != GEN4_APPLY_RECEIPT_FIELDS:
        fail("Gen4 APPLY completion field set is not exact")
    expected_values = {
        "schema_version": "2",
        "completion_state": "applied_ingress_closed",
        "estate_root": str(estate),
        "backup_dir": str(backup),
        "cargo_gate": "passed",
        "runtime_backup": "passed",
        "closed_bracket": "passed",
        "route_database_state": "absent",
        "public_ipv4_ipv6_closed_status": "404",
        "ingress_opened": "false",
        "services_activated": "true",
        "runtime_verified": "true",
        "successor": "true",
        "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
        "predecessor_current_file": "PREDECESSOR-CURRENT.json",
        "predecessor_completion_kind": RECOVERY_COMPLETION_KIND,
        "predecessor_release_generation": "3",
        "release_generation": "4",
    }
    for field, expected in expected_values.items():
        if receipt[field] != expected:
            if field in {"predecessor_release_generation", "release_generation"}:
                fail("Gen4 APPLY completion generation linkage differs")
            fail(f"Gen4 APPLY completion differs: {field}")
    if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", receipt["applied_at"]):
        fail("Gen4 APPLY completion applied_at differs")
    if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", receipt["closed_verified_at"]):
        fail("Gen4 APPLY completion closed_verified_at differs")
    digest_fields = {
        field for field in GEN4_APPLY_RECEIPT_FIELDS if field.endswith("_sha256")
    }
    for field in digest_fields:
        require_hex(receipt[field], f"Gen4 APPLY completion {field}")
    artifact_paths = {
        "release_env_sha256": backup / "release.env",
        "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
        "render_inputs_sha256": backup / "RENDER-INPUTS.sha256",
        "apply_armed_receipt_sha256": backup / "APPLY-ARMED.receipt",
        "control_sha256": backup / "CONTROL.sha256",
        "transaction_sha256": backup / "estate/TRANSACTION.json",
        "applied_targets_sha256": backup / "estate/APPLIED-TARGETS.sha256",
        "successor_armed_receipt_sha256": backup / "SUCCESSOR-ARMED.receipt",
        "runtime_backup_receipt_sha256": backup / "runtime/BACKUP.receipt",
        "runtime_backup_manifest_sha256": backup / "runtime/SHA256SUMS",
    }
    for field, path in artifact_paths.items():
        artifact = require_regular(path)
        if sha256(artifact) != receipt[field]:
            fail(f"Gen4 APPLY completion artifact differs: {field}")
    if current is not None:
        validated_current = validate_gen4_current(
            current, estate=estate, backup=backup
        )
        require_gen4_current_apply_alignment(validated_current, receipt)
        lineage_artifacts = {
            "predecessor_current_sha256": backup / "PREDECESSOR-CURRENT.json",
            "predecessor_completion_attestation_sha256": (
                backup / RECOVERY_ATTESTATION_NAME
            ),
            "predecessor_completion_signature_sha256": (
                backup / RECOVERY_SIGNATURE_NAME
            ),
            "predecessor_completion_public_key_sha256": (
                backup / RECOVERY_PUBLIC_KEY_NAME
            ),
        }
        for field, path in lineage_artifacts.items():
            artifact = require_regular(path)
            if sha256(artifact) != receipt[field]:
                fail(f"Gen4 APPLY completion artifact differs: {field}")
        predecessor_current_path = backup / receipt["predecessor_current_file"]
        predecessor_current = load_json(predecessor_current_path)
        predecessor_backup = require_directory(
            Path(receipt["predecessor_backup_dir"]), private=True
        )
        predecessor_current_values: dict[str, object] = {
            "schema_version": 2,
            "state": "applied_ingress_closed",
            "estate_root": str(estate),
            "backup_dir": str(predecessor_backup),
            "successor": True,
            "predecessor_release_generation": 2,
            "release_generation": 3,
            "services_activated": True,
            "runtime_verified": True,
            "ingress_opened": False,
        }
        for field, expected in predecessor_current_values.items():
            if predecessor_current.get(field) != expected:
                fail(f"Gen4 PREDECESSOR-CURRENT differs: {field}")
        predecessor_artifacts = {
            "predecessor_control_sha256": predecessor_backup / "CONTROL.sha256",
            "predecessor_release_evidence_sha256": (
                predecessor_backup / "RELEASE-EVIDENCE.json"
            ),
            "predecessor_runtime_backup_receipt_sha256": (
                predecessor_backup / "runtime/BACKUP.receipt"
            ),
            "predecessor_runtime_backup_manifest_sha256": (
                predecessor_backup / "runtime/SHA256SUMS"
            ),
        }
        predecessor_bytes: dict[str, bytes] = {}
        for field, path in predecessor_artifacts.items():
            artifact = require_regular(path)
            raw_artifact = read_safe_regular(
                artifact, f"Gen4 predecessor artifact {field}"
            )
            predecessor_bytes[field] = raw_artifact
            if sha256_bytes(raw_artifact) != receipt[field]:
                fail(f"Gen4 APPLY predecessor artifact differs: {field}")
        for state_field, receipt_field in (
            ("control_sha256", "predecessor_control_sha256"),
            ("release_evidence_sha256", "predecessor_release_evidence_sha256"),
        ):
            if predecessor_current.get(state_field) != receipt[receipt_field]:
                fail(f"Gen4 PREDECESSOR-CURRENT artifact differs: {state_field}")
        verify_checksum_manifest(
            predecessor_backup,
            predecessor_backup / "CONTROL.sha256",
            predecessor_bytes["predecessor_control_sha256"],
        )
        verify_checksum_manifest(
            predecessor_backup / "runtime",
            predecessor_backup / "runtime/SHA256SUMS",
            predecessor_bytes["predecessor_runtime_backup_manifest_sha256"],
        )
    return receipt


def exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} field set is not exact")
    return value


def require_hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def validate_gen4_current(
    value: object,
    *,
    estate: Path | None = None,
    backup: Path | None = None,
) -> dict[str, Any]:
    """Validate the one exact CURRENT contract emitted by Gen4.

    This contract is intentionally independent from the Gen5 policy.  Gen5
    may bind these immutable bytes, but it must not reinterpret their shape.
    """

    current = exact_object(value, GEN4_CURRENT_FIELDS, "Gen4 CURRENT")
    expected_values: dict[str, object] = {
        "schema_version": 2,
        "state": "applied_ingress_closed",
        "route_database_state": "absent",
        "public_ipv4_ipv6_closed_status": 404,
        "services_activated": True,
        "runtime_verified": True,
        "ingress_opened": False,
        "successor": True,
        "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
        "predecessor_current_file": "PREDECESSOR-CURRENT.json",
        "predecessor_completion_kind": RECOVERY_COMPLETION_KIND,
        "predecessor_release_generation": 3,
        "release_generation": 4,
    }
    if estate is not None:
        expected_values["estate_root"] = str(estate)
    if backup is not None:
        expected_values["backup_dir"] = str(backup)
    for field, expected in expected_values.items():
        if current[field] != expected:
            if field in {"predecessor_release_generation", "release_generation"}:
                fail("Gen4 CURRENT generation linkage differs")
            fail(f"Gen4 CURRENT differs: {field}")
    if not re.fullmatch(
        r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        str(current["closed_verified_at"]),
    ):
        fail("Gen4 CURRENT closed_verified_at differs")
    for field in GEN4_CURRENT_FIELDS:
        if field.endswith("_sha256"):
            require_hex(current[field], f"Gen4 CURRENT {field}")
    for field in ("estate_root", "backup_dir", "predecessor_backup_dir"):
        path = current[field]
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or Path(path) == Path("/")
        ):
            fail(f"Gen4 CURRENT {field} is unsafe")
    return current


def require_gen4_current_apply_alignment(
    current: dict[str, Any], receipt: dict[str, str]
) -> None:
    for field in GEN4_SHARED_COMPLETION_FIELDS:
        observed: object = receipt[field]
        expected: object = current[field]
        if isinstance(expected, bool):
            observed = observed == "true" if observed in {"true", "false"} else observed
        elif isinstance(expected, int):
            try:
                observed = int(observed)
            except ValueError:
                pass
        if observed != expected:
            fail(f"Gen4 CURRENT/APPLY completion differs: {field}")


def validate_completion_binding(value: object) -> dict[str, Any]:
    completion = exact_object(
        value, RECOVERY_COMPLETION_FIELDS, "recovery completion binding"
    )
    if completion["kind"] != RECOVERY_COMPLETION_KIND:
        fail("recovery completion kind differs")
    for field in (
        "attestation_sha256",
        "signature_sha256",
        "public_key_sha256",
    ):
        require_hex(completion[field], f"recovery completion {field}")
    return completion


def read_recovery_completion_bundle(
    root: Path,
    completion: dict[str, Any],
    *,
    exact_namespace: bool = True,
) -> dict[str, Any]:
    """Read each signed completion artifact once and verify those exact bytes."""

    validated = validate_completion_binding(completion)
    directory = open_private_directory(root)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
            fail("recovery completion root must have mode 0700")
        names = set(os.listdir(directory))
        expected_names = set(RECOVERY_COMPLETION_NAMES)
        if exact_namespace and names != expected_names:
            fail("recovery completion root file set is not exact")
        if not expected_names.issubset(names):
            fail("recovery completion bundle is incomplete")
        attestation = read_direct_child(
            directory, RECOVERY_ATTESTATION_NAME, "recovery completion attestation"
        )
        signature = read_direct_child(
            directory,
            RECOVERY_SIGNATURE_NAME,
            "recovery completion signature",
            maximum_size=65_536,
        )
        public_key = read_direct_child(
            directory,
            RECOVERY_PUBLIC_KEY_NAME,
            "recovery completion public key",
            maximum_size=65_536,
        )
    finally:
        os.close(directory)
    observed = recovery_artifact_result(attestation, signature, public_key)
    expected_hashes = {
        "attestation_sha256": validated["attestation_sha256"],
        "signature_sha256": validated["signature_sha256"],
        "public_key_sha256": validated["public_key_sha256"],
    }
    for field, expected in expected_hashes.items():
        if observed[field] != expected:
            fail(f"recovery completion artifact differs: {field}")
    document = verify_raw_bundle(
        attestation,
        signature,
        public_key,
        validated["public_key_sha256"],
    )
    return {
        "document": document,
        "artifacts": observed,
        "bytes": {
            RECOVERY_ATTESTATION_NAME: attestation,
            RECOVERY_SIGNATURE_NAME: signature,
            RECOVERY_PUBLIC_KEY_NAME: public_key,
        },
    }


def require_same_recovery_completion_snapshot(
    before: dict[str, Any], after: dict[str, Any]
) -> None:
    if (
        before.get("artifacts") != after.get("artifacts")
        or before.get("bytes") != after.get("bytes")
        or before.get("document") != after.get("document")
    ):
        fail("recovery completion source changed during render")


def write_recovery_completion_bundle(
    stage_root: Path,
    completion: dict[str, Any],
    bundle: dict[str, Any],
) -> None:
    """Copy the already-verified bytes into one private successor stage."""

    stage = require_directory(stage_root, private=True)
    raw = bundle.get("bytes")
    if not isinstance(raw, dict) or set(raw) != set(RECOVERY_COMPLETION_NAMES):
        fail("verified recovery completion bytes are unavailable")
    directory = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for name in RECOVERY_COMPLETION_NAMES:
            content = raw[name]
            if not isinstance(content, bytes) or not content:
                fail("verified recovery completion bytes are invalid")
            descriptor = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            try:
                os.fchmod(descriptor, 0o600)
                offset = 0
                while offset < len(content):
                    offset += os.write(descriptor, content[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(directory)
    except FileExistsError:
        fail("recovery completion stage output already exists")
    finally:
        os.close(directory)
    staged = read_recovery_completion_bundle(
        stage, completion, exact_namespace=False
    )
    require_same_recovery_completion_snapshot(bundle, staged)


def safe_relative(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not SAFE_RELATIVE.fullmatch(value)
        or value.startswith("/")
        or ".." in Path(value).parts
        or Path(value).as_posix() != value
    ):
        fail(f"{label} is not a safe relative path")
    return value


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    raw = read_safe_regular(path, "checksum manifest")
    return parse_checksum_manifest_bytes(raw, path)


def parse_checksum_manifest_bytes(raw: bytes, path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"checksum manifest is not UTF-8: {path}: {error}")
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if (
            not match
            or match.group(2).startswith("/")
            or ".." in Path(match.group(2)).parts
            or Path(match.group(2)).as_posix() != match.group(2)
            or match.group(2) in result
        ):
            fail(f"invalid checksum manifest line {line_number}: {path}")
        result[match.group(2)] = match.group(1)
    if not result:
        fail(f"checksum manifest is empty: {path}")
    return result


def parse_path_manifest(path: Path) -> set[str]:
    require_regular(path)
    result: set[str] = set()
    for line_number, relative in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not relative:
            continue
        if (
            not SAFE_RELATIVE.fullmatch(relative)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or Path(relative).as_posix() != relative
            or relative in result
        ):
            fail(f"invalid or duplicate absent path line {line_number}: {path}")
        result.add(relative)
    return result


def validate_static_asset_transition(
    preimages: dict[str, str],
    static_targets: dict[str, str],
    authority_root: Path,
    policy_version: int = 1,
) -> dict[str, str]:
    expected_paths = set(FROZEN_STATIC_PATHS)
    if not expected_paths.issubset(preimages) or set(static_targets) != expected_paths:
        fail("successor static transition path set is not exact")
    sources = dict(SUCCESSOR_STATIC_ASSET_SOURCES)
    if len(sources) != len(SUCCESSOR_STATIC_ASSET_SOURCES):
        fail("successor static asset source path set contains duplicates")
    changed_paths = {
        relative
        for relative in FROZEN_STATIC_PATHS
        if preimages[relative] != static_targets[relative]
    }
    if policy_version == 1:
        valid_transition = changed_paths == set(sources)
    elif policy_version in (2, 3, 4):
        valid_transition = changed_paths.issubset(sources)
    else:
        valid_transition = False
    if not valid_transition:
        fail("successor static asset transition path set is not exact")
    root = require_directory(authority_root)
    changed_sources = {
        relative: source_relative
        for relative, source_relative in SUCCESSOR_STATIC_ASSET_SOURCES
        if relative in changed_paths
    }
    for relative, source_relative in changed_sources.items():
        safe_relative(relative, "successor static asset target")
        safe_relative(source_relative, "successor static asset source")
        source = require_regular(root / source_relative)
        if source.resolve() != source or root not in source.resolve().parents:
            fail(f"successor static asset source escapes authority: {relative}")
        if sha256(source) != static_targets[relative]:
            fail(f"successor static asset source differs: {relative}")
    return changed_sources


def verify_checksum_manifest(
    root: Path, manifest: Path, manifest_raw: bytes | None = None
) -> None:
    base = require_directory(root)
    expected_files = (
        parse_checksum_manifest(manifest)
        if manifest_raw is None
        else parse_checksum_manifest_bytes(manifest_raw, manifest)
    )
    for relative, expected in expected_files.items():
        target = require_regular(base / relative)
        if target.resolve() != target or base not in target.resolve().parents:
            fail(f"checksum path escapes authority root: {relative}")
        if sha256(target) != expected:
            fail(f"checksum authority differs: {relative}")


def source_files(base: Path) -> dict[str, Path]:
    root = require_directory(base)
    result: dict[str, Path] = {}
    for current_root, directories, names in os.walk(root, followlinks=False):
        current = Path(current_root)
        for name in [*directories, *names]:
            if (current / name).is_symlink():
                fail(f"Access source contains a symlink: {current / name}")
        directories[:] = sorted(
            name for name in directories if name not in IGNORED_DIRECTORIES
        )
        for name in sorted(names):
            if name.endswith(".pyc") or fnmatch.fnmatch(name, "*.log"):
                continue
            path = require_regular(current / name, root_owned=False)
            relative = path.relative_to(root).as_posix()
            result[relative] = path
    return result


def validate_policy(path: Path) -> dict[str, Any]:
    policy = exact_object(
        load_json(path),
        {"schema_version", "ceremony", "predecessor", "successor", "overlay"},
        "successor policy",
    )
    policy_version = policy["schema_version"]
    if (
        type(policy_version) is not int
        or policy_version not in POLICY_CEREMONIES
        or policy["ceremony"] != POLICY_CEREMONIES[policy_version]
    ):
        fail("successor policy version or ceremony differs")
    predecessor_fields = {
        3: RECOVERED_PREDECESSOR_FIELDS,
    }.get(policy_version, LEGACY_PREDECESSOR_FIELDS)
    predecessor = exact_object(
        policy["predecessor"], predecessor_fields, "predecessor policy"
    )
    predecessor_hash_fields = [
        "current_state_sha256",
        "control_sha256",
        "release_evidence_sha256",
        "runtime_manifest_sha256",
        "candidate_evidence_sha256",
        "candidate_targets_sha256",
        "access_build_input_sha256",
        "permission_catalog_sha256",
        "package_catalog_sha256",
    ]
    if policy_version != 3:
        predecessor_hash_fields.append("apply_receipt_sha256")
    else:
        validate_completion_binding(predecessor["completion"])
    for key in predecessor_hash_fields:
        require_hex(predecessor[key], f"predecessor {key}")
    if predecessor["access_build_input_schema"] not in {
        BUILD_INPUT_V1,
        BUILD_INPUT_V2,
    }:
        fail("predecessor build-input schema differs")
    if (
        policy_version == 1
        and predecessor["access_build_input_schema"] != BUILD_INPUT_V1
    ):
        fail("legacy successor policy cannot bind a v2 predecessor")
    if (
        policy_version in (3, 4)
        and predecessor["access_build_input_schema"] != BUILD_INPUT_V2
    ):
        fail("modern successor policy requires a v2 predecessor")
    if not isinstance(predecessor["access_image"], str) or not IMAGE.fullmatch(
        predecessor["access_image"]
    ):
        fail("predecessor Access image is not an immutable digest")
    successor = exact_object(
        policy["successor"],
        {
            "generator",
            "access_build_input_schema",
            "source_access_build_input_sha256",
            "access_build_input_sha256",
            "preimages_manifest",
            "absent_manifest",
            "static_targets_manifest",
            "supporting_targets_manifest",
            "frozen_targets_manifest",
        },
        "successor policy",
    )
    if (
        successor["generator"] != "holdfast-rikune-estate/2.0.0"
        or successor["access_build_input_schema"] != BUILD_INPUT_V2
    ):
        fail("successor generator or build-input schema differs")
    require_hex(
        successor["source_access_build_input_sha256"],
        "successor source build input",
    )
    require_hex(successor["access_build_input_sha256"], "successor build input")
    for key in (
        "preimages_manifest",
        "absent_manifest",
        "static_targets_manifest",
        "supporting_targets_manifest",
        "frozen_targets_manifest",
    ):
        safe_relative(successor[key], f"successor {key}")
    expected_manifests = {
        "preimages_manifest": "successor-preimages.sha256",
        "absent_manifest": "successor-absent.paths",
        "static_targets_manifest": "successor-static-targets.sha256",
        "supporting_targets_manifest": "successor-supporting-targets.sha256",
        "frozen_targets_manifest": "successor-frozen-targets.json",
    }
    for key, expected in expected_manifests.items():
        if successor[key] != expected:
            fail(f"successor {key} differs from the canonical authority")
    overlay = policy["overlay"]
    if not isinstance(overlay, list) or (
        policy_version == 1 and len(overlay) != 7
    ) or (
        policy_version in (2, 3, 4)
        and (not overlay or len(overlay) > MAX_SUCCESSOR_OVERLAY_PATHS)
    ):
        fail("successor overlay size differs from its policy version")
    seen: set[str] = set()
    paths: list[str] = []
    for index, item in enumerate(overlay):
        entry = exact_object(
            item,
            {"path", "before_sha256", "after_sha256"},
            f"overlay {index}",
        )
        relative = safe_relative(entry["path"], f"overlay {index} path")
        if (
            not relative.startswith("access-governance/")
            or len(Path(relative).parts) < 2
            or relative in seen
        ):
            fail("successor overlay path is duplicate or outside Access")
        seen.add(relative)
        paths.append(relative)
        if entry["before_sha256"] is not None:
            require_hex(entry["before_sha256"], f"overlay {relative} before")
        require_hex(entry["after_sha256"], f"overlay {relative} after")
    if policy_version in (2, 3, 4) and paths != sorted(paths):
        fail("successor overlay paths must be sorted")
    return policy


def exact_tree_files(root: Path, relative_root: str) -> dict[str, Path]:
    authority_root = require_directory(root)
    tree = require_directory(authority_root / relative_root)
    if authority_root not in tree.parents:
        fail(f"supporting tree escapes its authority root: {relative_root}")
    result: dict[str, Path] = {}
    for current_root, directories, names in os.walk(tree, followlinks=False):
        current = Path(current_root)
        for name in [*directories, *names]:
            if (current / name).is_symlink():
                fail(f"supporting tree contains a symlink: {current / name}")
        directories[:] = sorted(directories)
        for name in sorted(names):
            path = require_regular(current / name)
            relative = path.relative_to(authority_root).as_posix()
            result[relative] = path
    if not result:
        fail(f"supporting tree is empty: {relative_root}")
    return result


def validate_supporting_snapshot(
    root: Path, expected: dict[str, str]
) -> None:
    verdict = exact_tree_files(root, "verdict")
    relay = exact_tree_files(root, "relay/upstream/new-api/router")
    if set(relay) != SUPPORTING_RELAY_PATHS:
        fail("supporting relay source field set is not exact")
    observed = verdict | relay
    if set(expected) != set(observed):
        fail("supporting source manifest field set is not exact")
    for relative, path in observed.items():
        if sha256(path) != expected[relative]:
            fail(f"supporting source differs: {relative}")


def validate_source_delta(
    policy: dict[str, Any], predecessor_access: Path, live_access: Path
) -> None:
    before = source_files(predecessor_access)
    after = source_files(live_access)
    overlay = {
        item["path"].removeprefix("access-governance/"): item
        for item in policy["overlay"]
    }
    observed_delta = {
        relative
        for relative in set(before) | set(after)
        if relative not in before
        or relative not in after
        or sha256(before[relative]) != sha256(after[relative])
    }
    if observed_delta != set(overlay):
        unexpected = sorted(observed_delta ^ set(overlay))
        fail(f"live Access delta differs from the exact policy overlay: {unexpected}")
    for relative, item in overlay.items():
        before_path = before.get(relative)
        expected_before = item["before_sha256"]
        if expected_before is None:
            if before_path is not None:
                fail(f"overlay path was expected absent in predecessor: {relative}")
        elif before_path is None or sha256(before_path) != expected_before:
            fail(f"overlay predecessor hash differs: {relative}")
        if relative not in after or sha256(after[relative]) != item["after_sha256"]:
            fail(f"overlay successor hash differs: {relative}")


def validate_predecessor_access_identity(
    candidate_root: Path,
    stage_root: Path,
    predecessor: dict[str, Any],
    *,
    bind_evidence_hashes: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = require_directory(candidate_root)
    stage = require_directory(stage_root, private=True)
    schema = predecessor.get("access_build_input_schema")
    expected = require_hex(
        predecessor.get("access_build_input_sha256"),
        "predecessor build input",
    )
    observed = access_build_input_sha_for_schema(candidate, schema)
    if observed != expected:
        fail("sealed predecessor Access build input differs")

    expected_evidence_schema = 1 if schema == BUILD_INPUT_V1 else 2
    evidence_values: list[dict[str, Any]] = []
    for label, root in (("candidate", candidate), ("stage", stage)):
        evidence_path = root / "RELEASE-EVIDENCE.json"
        evidence_raw = read_safe_regular(
            evidence_path, f"predecessor {label} release evidence"
        )
        if bind_evidence_hashes:
            expected_evidence_sha = predecessor[
                "candidate_evidence_sha256"
                if label == "candidate"
                else "release_evidence_sha256"
            ]
            if sha256_bytes(evidence_raw) != expected_evidence_sha:
                fail(f"sealed predecessor {label} evidence differs")
        evidence = load_json_bytes(evidence_raw, evidence_path)
        if (
            type(evidence.get("schema_version")) is not int
            or evidence.get("schema_version") != expected_evidence_schema
            or evidence.get("access_governance_build_input_sha256") != expected
        ):
            fail(f"predecessor {label} build-input evidence differs")
        evidence_schema = evidence.get("access_governance_build_input_schema")
        if (
            schema == BUILD_INPUT_V1
            and evidence_schema not in (None, BUILD_INPUT_V1)
        ) or (schema == BUILD_INPUT_V2 and evidence_schema != BUILD_INPUT_V2):
            fail(f"predecessor {label} build-input schema evidence differs")
        evidence_values.append(evidence)
    return evidence_values[0], evidence_values[1]


def validate_predecessor_generation(
    state: dict[str, Any], build_input_schema: object
) -> int:
    if build_input_schema == BUILD_INPUT_V1:
        release_generation = state.get("release_generation", 1)
        if (
            type(release_generation) is not int
            or release_generation != 1
            or state.get("successor") not in (None, False)
        ):
            fail("legacy predecessor generation authority differs")
        return release_generation
    if build_input_schema != BUILD_INPUT_V2:
        fail("predecessor build-input schema differs")
    release_generation = state.get("release_generation")
    previous_generation = state.get("predecessor_release_generation")
    if (
        state.get("successor") is not True
        or type(release_generation) is not int
        or type(previous_generation) is not int
        or release_generation < 2
        or previous_generation < 1
        or release_generation != previous_generation + 1
    ):
        fail("successor predecessor generation authority differs")
    return release_generation


def validate_recovered_predecessor(
    *,
    completion_root: Path,
    predecessor: dict[str, Any],
    state_path: Path,
    state: dict[str, Any],
    state_raw: bytes | None = None,
    estate: Path,
    backup: Path,
    authority_bytes: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    completion = predecessor.get("completion")
    if not isinstance(completion, dict):
        fail("recovered predecessor lacks completion authority")
    bundle = read_recovery_completion_bundle(
        completion_root, completion, exact_namespace=True
    )
    document = bundle["document"]
    current_raw = (
        read_safe_regular(state_path, "CURRENT authority")
        if state_raw is None
        else state_raw
    )
    parsed_state = load_json_bytes(current_raw, state_path)
    if parsed_state != state:
        fail("recovered CURRENT parsed state differs from its byte snapshot")
    state_sha256 = sha256_bytes(current_raw)
    expected_document_bindings = {
        "current_sha256": predecessor["current_state_sha256"],
        "control_sha256": predecessor["control_sha256"],
        "release_evidence_sha256": predecessor["release_evidence_sha256"],
        "runtime_manifest_sha256": predecessor["runtime_manifest_sha256"],
        "estate_root": str(estate),
        "backup_dir": str(backup),
        "predecessor_release_generation": 2,
        "release_generation": 3,
    }
    for field, expected in expected_document_bindings.items():
        if document.get(field) != expected:
            fail(f"recovery completion predecessor binding differs: {field}")
    if state_sha256 != document["current_sha256"]:
        fail("recovery completion CURRENT bytes differ")
    if (
        state.get("successor") is not True
        or state.get("predecessor_release_generation") != 2
        or state.get("release_generation") != 3
    ):
        fail("recovered CURRENT generation linkage must be exactly 2 -> 3")
    if state.get("control_sha256") != predecessor["control_sha256"]:
        fail("recovered CURRENT control binding differs")
    if (
        state.get("release_evidence_sha256")
        != predecessor["release_evidence_sha256"]
    ):
        fail("recovered CURRENT release evidence binding differs")
    apply_receipt = backup / "APPLY.receipt"
    if apply_receipt.exists() or apply_receipt.is_symlink():
        fail("recovered predecessor backup must not contain APPLY.receipt")

    artifact_bindings = {
        "control_sha256": backup / "CONTROL.sha256",
        "release_env_sha256": backup / "release.env",
        "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
        "transaction_sha256": backup / "estate/TRANSACTION.json",
        "applied_targets_sha256": backup / "estate/APPLIED-TARGETS.sha256",
        "runtime_receipt_sha256": backup / "runtime/BACKUP.receipt",
        "runtime_manifest_sha256": backup / "runtime/SHA256SUMS",
    }
    for field, path in artifact_bindings.items():
        require_regular(path)
        raw = (
            authority_bytes.get(field)
            if authority_bytes is not None
            else None
        )
        if raw is None:
            raw = read_safe_regular(path, f"recovery completion artifact {field}")
        if sha256_bytes(raw) != document[field]:
            fail(f"recovery completion backup artifact differs: {field}")
    return bundle


def validate_overlay_static_separation(
    policy: dict[str, Any],
    preimages: dict[str, str],
    static_targets: dict[str, str],
) -> None:
    changed_static_paths = {
        relative
        for relative in FROZEN_STATIC_PATHS
        if preimages[relative] != static_targets[relative]
    }
    overlay_paths = {item["path"] for item in policy["overlay"]}
    overlap = sorted(changed_static_paths & overlay_paths)
    if overlap:
        fail(f"successor overlay overlaps a changed static target: {overlap}")


def validate_predecessor(
    *,
    policy_path: Path,
    current_state_path: Path,
    estate_root: Path,
    predecessor_candidate: Path,
    predecessor_stage: Path,
    successor_preimages: Path,
    recovery_completion_root: Path | None = None,
) -> dict[str, Any]:
    policy = validate_policy(policy_path)
    policy_version = policy["schema_version"]
    predecessor = policy["predecessor"]
    successor = policy["successor"]
    authority_root = require_directory(policy_path.parent)
    if policy_path != authority_root / "successor-policy.json":
        fail("successor policy is not the canonical authority file")
    canonical_preimages = authority_root / successor["preimages_manifest"]
    if successor_preimages != canonical_preimages:
        fail("successor preimage input is not the policy authority")
    preimages = parse_checksum_manifest(canonical_preimages)
    overlay_paths = {item["path"] for item in policy["overlay"]}
    expected_preimages = set(FROZEN_STATIC_PATHS) | overlay_paths | {"deploy/.env"}
    if set(preimages) != expected_preimages:
        fail("successor preimage path set is not exact")
    absent_path = authority_root / successor["absent_manifest"]
    if parse_path_manifest(absent_path):
        fail("successor absent path set must be exactly empty")
    static_targets = parse_checksum_manifest(
        authority_root / successor["static_targets_manifest"]
    )
    if set(static_targets) != set(FROZEN_STATIC_PATHS):
        fail("successor static target path set is not exact")
    validate_static_asset_transition(
        preimages, static_targets, authority_root, policy["schema_version"]
    )
    validate_overlay_static_separation(policy, preimages, static_targets)
    supporting_targets = parse_checksum_manifest(
        authority_root / successor["supporting_targets_manifest"]
    )
    frozen = load_json(authority_root / successor["frozen_targets_manifest"])
    if (
        frozen.get("schema_version") != 2
        or frozen.get("generator") != successor["generator"]
        or frozen.get("access_governance_build_input_schema") != BUILD_INPUT_V2
        or frozen.get("access_governance_build_input_sha256")
        != successor["access_build_input_sha256"]
        or frozen.get("permission_catalog_sha256")
        != predecessor["permission_catalog_sha256"]
        or frozen.get("package_catalog_sha256")
        != predecessor["package_catalog_sha256"]
    ):
        fail("successor policy and frozen semantic authority differ")
    state_path = require_regular(current_state_path)
    state_raw = read_safe_regular(state_path, "CURRENT authority")
    if sha256_bytes(state_raw) != predecessor["current_state_sha256"]:
        fail("CURRENT authority differs from the successor policy")
    state = load_json_bytes(state_raw, state_path)
    if policy_version == 4:
        state = validate_gen4_current(state)
    if (
        state.get("schema_version") != 2
        or state.get("state") != "applied_ingress_closed"
        or state.get("ingress_opened") is not False
        or state.get("services_activated") is not True
        or state.get("runtime_verified") is not True
    ):
        fail("CURRENT is not a verified applied_ingress_closed predecessor")
    if policy_version == 3:
        if recovery_completion_root is None:
            fail("schema 3 successor policy requires --recovery-completion-root")
        if any(
            field in state
            for field in (
                "apply_receipt_sha256",
                "route_database_state",
                "public_ipv4_ipv6_closed_status",
            )
        ):
            fail("recovered CURRENT contains legacy completion authority")
        if (
            state.get("successor") is not True
            or state.get("predecessor_release_generation") != 2
            or state.get("release_generation") != 3
        ):
            fail("recovered CURRENT generation linkage must be exactly 2 -> 3")
    else:
        if recovery_completion_root is not None:
            fail("recovery completion root is forbidden for legacy successor policy")
        if (
            state.get("route_database_state") != "absent"
            or state.get("public_ipv4_ipv6_closed_status") != 404
        ):
            fail("CURRENT is not a verified applied_ingress_closed predecessor")
        validate_predecessor_generation(
            state, predecessor["access_build_input_schema"]
        )
        if policy_version == 4 and (
            state.get("successor") is not True
            or state.get("predecessor_release_generation") != 3
            or state.get("release_generation") != 4
        ):
            fail("schema 4 predecessor generation linkage must be exactly 3 -> 4")
    estate = require_directory(estate_root)
    if Path(str(state.get("estate_root"))).resolve() != estate:
        fail("CURRENT estate root differs")
    backup = require_directory(Path(str(state.get("backup_dir"))), private=True)
    if backup.parent != Path("/secure/backups") or not backup.name.startswith(
        "holdfast-rikune-"
    ):
        fail("CURRENT predecessor backup location is outside the release authority")
    authority_files = (
        {
            "control_sha256": backup / "CONTROL.sha256",
            "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
            "runtime_manifest_sha256": backup / "runtime/SHA256SUMS",
        }
        if policy_version == 3
        else {
            "control_sha256": backup / "CONTROL.sha256",
            "apply_receipt_sha256": backup / "APPLY.receipt",
            "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
            "runtime_manifest_sha256": backup / "runtime/SHA256SUMS",
        }
    )
    authority_bytes: dict[str, bytes] = {}
    for key, path in authority_files.items():
        require_regular(path)
        raw = read_safe_regular(path, f"predecessor authority {key}")
        authority_bytes[key] = raw
        if sha256_bytes(raw) != predecessor[key]:
            fail(f"predecessor authority differs: {key}")
    if state.get("control_sha256") != predecessor["control_sha256"]:
        fail("CURRENT control binding differs")
    if policy_version != 3 and (
        state.get("apply_receipt_sha256") != predecessor["apply_receipt_sha256"]
    ):
        fail("CURRENT apply receipt binding differs")
    if state.get("release_evidence_sha256") != predecessor["release_evidence_sha256"]:
        fail("CURRENT release evidence binding differs")
    verify_checksum_manifest(
        backup,
        backup / "CONTROL.sha256",
        authority_bytes["control_sha256"],
    )
    verify_checksum_manifest(
        backup / "runtime",
        backup / "runtime/SHA256SUMS",
        authority_bytes["runtime_manifest_sha256"],
    )
    if policy_version == 4:
        apply_completion = validate_gen4_apply_completion(
            authority_bytes["apply_receipt_sha256"],
            predecessor,
            estate,
            backup,
            state,
        )
        for field in (
            "predecessor_completion_kind",
            "predecessor_completion_attestation_sha256",
            "predecessor_completion_signature_sha256",
            "predecessor_completion_public_key_sha256",
        ):
            if state.get(field) != apply_completion[field]:
                fail(f"Gen4 CURRENT historical completion differs: {field}")
    recovery_completion: dict[str, Any] | None = None
    if policy_version == 3:
        assert recovery_completion_root is not None
        recovery_completion = validate_recovered_predecessor(
            completion_root=recovery_completion_root,
            predecessor=predecessor,
            state_path=state_path,
            state=state,
            state_raw=state_raw,
            estate=estate,
            backup=backup,
            authority_bytes=authority_bytes,
        )

    candidate = require_directory(predecessor_candidate)
    stage = require_directory(predecessor_stage, private=True)
    candidate_targets_path = require_regular(candidate / "TARGETS.sha256")
    candidate_targets_raw = read_safe_regular(
        candidate_targets_path, "sealed predecessor candidate targets"
    )
    if sha256_bytes(candidate_targets_raw) != predecessor["candidate_targets_sha256"]:
        fail("sealed predecessor candidate targets differ")
    verify_checksum_manifest(
        candidate, candidate_targets_path, candidate_targets_raw
    )
    _, release_evidence = validate_predecessor_access_identity(
        candidate, stage, predecessor, bind_evidence_hashes=True
    )
    validate_supporting_snapshot(candidate, supporting_targets)
    release = release_evidence.get("release")
    if not isinstance(release, dict):
        fail("predecessor release evidence lacks release pins")
    expected_release = {
        "ACCESS_GOVERNANCE_IMAGE": predecessor["access_image"],
        "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": predecessor[
            "access_build_input_sha256"
        ],
        "PERMISSION_CATALOG_SHA256": predecessor["permission_catalog_sha256"],
        "PACKAGE_CATALOG_SHA256": predecessor["package_catalog_sha256"],
    }
    for key, expected in expected_release.items():
        if release.get(key) != expected:
            fail(f"predecessor release pin differs: {key}")

    validate_source_delta(
        policy, candidate / "access-governance", estate / "access-governance"
    )
    for relative, expected in preimages.items():
        target = require_regular(estate / relative)
        if target.resolve() != target or estate not in target.resolve().parents:
            fail(f"successor preimage path escapes the estate: {relative}")
        if sha256(target) != expected:
            fail(f"successor live preimage differs: {relative}")
    observed_build_input = access_tree_build_input_sha_v2(
        estate / "access-governance"
    )
    if observed_build_input != successor["source_access_build_input_sha256"]:
        fail("live exact successor Access source build input differs")
    result = {
        "policy": policy,
        "state": state,
        "backup": backup,
        "predecessor_candidate": candidate,
        "predecessor_stage": stage,
        "successor_preimages": preimages,
        "successor_static_targets": static_targets,
        "successor_supporting_targets": supporting_targets,
    }
    if recovery_completion is not None:
        result["recovery_completion"] = recovery_completion
    return result


def write_delta_manifest(stage_root: Path, policy: dict[str, Any]) -> Path:
    stage = require_directory(stage_root, private=True)
    output = stage_root / "SUCCESSOR-DELTA.sha256"
    lines: list[str] = []
    for item in policy["overlay"]:
        before = item["before_sha256"] or "0" * 64
        lines.append(f"{before}  {item['after_sha256']}  {item['path']}")
    content = ("\n".join(lines) + "\n").encode("utf-8")
    directory_fd = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    file_fd: int | None = None
    try:
        file_fd = os.open(
            output.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(file_fd, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchmod(file_fd, 0o600)
        os.fsync(directory_fd)
    except FileExistsError:
        fail("successor delta output already exists")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    validation_mode = parser.add_mutually_exclusive_group()
    validation_mode.add_argument("--validate-gen4-current", action="store_true")
    validation_mode.add_argument("--validate-gen4-lineage", action="store_true")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--current-state", type=Path)
    parser.add_argument("--estate-root", type=Path)
    parser.add_argument("--predecessor-candidate", type=Path)
    parser.add_argument("--predecessor-stage", type=Path)
    parser.add_argument("--successor-preimages", type=Path)
    parser.add_argument("--recovery-completion-root", type=Path)
    args = parser.parse_args()
    try:
        if args.validate_gen4_current or args.validate_gen4_lineage:
            if (
                args.current_state is None
                or args.estate_root is None
                or any(
                    value is not None
                    for value in (
                        args.policy,
                        args.predecessor_candidate,
                        args.predecessor_stage,
                        args.successor_preimages,
                        args.recovery_completion_root,
                    )
                )
            ):
                parser.error(
                    "Gen4 validation requires only --current-state and "
                    "--estate-root"
                )
            current_path = args.current_state.absolute()
            current = load_json(current_path)
            validated_current = validate_gen4_current(
                current,
                estate=args.estate_root.absolute(),
                backup=Path(str(current.get("backup_dir"))),
            )
            if args.validate_gen4_lineage:
                backup = require_directory(
                    Path(str(validated_current["backup_dir"])), private=True
                )
                apply_path = require_regular(backup / "APPLY.receipt")
                validate_gen4_apply_completion(
                    read_safe_regular(apply_path, "Gen4 APPLY completion"),
                    {
                        "apply_receipt_sha256": validated_current[
                            "apply_receipt_sha256"
                        ]
                    },
                    args.estate_root.absolute(),
                    backup,
                    validated_current,
                )
                print("Holdfast Gen4 CURRENT/APPLY lineage is valid")
            else:
                print("Holdfast Gen4 CURRENT exact contract is valid")
            return 0
        required = {
            "--policy": args.policy,
            "--current-state": args.current_state,
            "--estate-root": args.estate_root,
            "--predecessor-candidate": args.predecessor_candidate,
            "--predecessor-stage": args.predecessor_stage,
            "--successor-preimages": args.successor_preimages,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error(f"required arguments are missing: {', '.join(missing)}")
        assert args.policy is not None
        assert args.current_state is not None
        assert args.estate_root is not None
        assert args.predecessor_candidate is not None
        assert args.predecessor_stage is not None
        assert args.successor_preimages is not None
        validate_predecessor(
            policy_path=args.policy.absolute(),
            current_state_path=args.current_state.absolute(),
            estate_root=args.estate_root.absolute(),
            predecessor_candidate=args.predecessor_candidate.absolute(),
            predecessor_stage=args.predecessor_stage.absolute(),
            successor_preimages=args.successor_preimages.absolute(),
            recovery_completion_root=(
                args.recovery_completion_root.absolute()
                if args.recovery_completion_root is not None
                else None
            ),
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"holdfast successor binding: {error}", file=sys.stderr)
        return 1
    print("Holdfast successor predecessor and exact delta are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
