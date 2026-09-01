#!/usr/bin/env python3
"""Assemble Gen6 schema-v5 supply-chain evidence from offline authorities."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, NoReturn

import render_input_binding
import successor_binding
import supply_chain_evidence as validator
import validate_release_evidence as release_validator


sys.dont_write_bytecode = True

OPS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = OPS_ROOT.parents[1]
PRODUCTION_VALIDATOR = OPS_ROOT / "supply_chain_evidence.py"
DEFAULT_DOCKERFILE = REPOSITORY_ROOT / "Dockerfile.analyzer"
DEFAULT_BRIDGE_LOCK = REPOSITORY_ROOT / "bridge/package-lock.json"
DOCKER = Path("/usr/bin/docker")
COSIGN_VERIFIER_IMAGE = validator.COSIGN_VERIFIER_IMAGE
COSIGN_IDENTITY = validator.STRAD_COSIGN_IDENTITY
COSIGN_ISSUER = validator.STRAD_COSIGN_ISSUER
SOURCE_REPOSITORY = "https://github.com/Steadholme/strad"
GEN6_ACCESS_BUILD_INPUT_SHA256 = (
    "518d15ae06c9df1ea5d7025fc85be09e2e25a3c7397dd6e07dbf2e536d63b948"
)
STATIC_LOCK_SHA256 = validator.STATIC_LOCK_SHA256
ACCESS_COSIGN_PUBLIC_KEY_SHA256 = validator.ACCESS_COSIGN_PUBLIC_KEY_SHA256
SIGSTORE_TRUSTED_ROOT_SHA256 = validator.SIGSTORE_TRUSTED_ROOT_SHA256
IMAGE_SIGNATURE_PREDICATE = "https://sigstore.dev/cosign/sign/v1"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_PREDICATE = "https://spdx.dev/Document"
FRESH_IMAGE_KEYS = frozenset(validator.FRESH_IMAGE_KEYS)
UNSIGNED_SIGNATURE_PLACEHOLDER = hashlib.sha256(
    b"holdfast-schema-v5-unsigned-signature-placeholder"
).hexdigest()
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ENV_BYTES = 128 * 1024
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
RECEIPT_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
IMAGE = validator.IMAGE
OFFLINE_ENV = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "ALL_PROXY": "http://127.0.0.1:9",
    "NO_PROXY": "",
    "PYTHONDONTWRITEBYTECODE": "1",
}
ACCESS_RECEIPT_FIELDS = {
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
}
IMAGE_RECORD_FIELDS = {
    "image",
    "manifest_digest",
    "registry",
    "subject_digest",
    "sbom",
    "provenance",
    "attestation",
    "signature",
}


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_absolute(path: Path, label: str) -> Path:
    raw = str(path)
    if (
        not path.is_absolute()
        or path == Path("/")
        or raw.startswith("//")
        or raw != os.path.normpath(raw)
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        fail(f"{label} must be a canonical absolute path")
    return path


def open_canonical(path: Path, flags: int, label: str) -> int:
    source = canonical_absolute(path, label)
    directory = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        for component in source.parts[1:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            metadata = os.fstat(next_directory)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                os.close(next_directory)
                fail(f"{label} has an unsafe ancestor directory")
            os.close(directory)
            directory = next_directory
        return os.open(
            source.name,
            flags | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def stable_stat(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_safe_bytes(
    path: Path,
    label: str,
    *,
    allowed_modes: set[int] = {0o600, 0o644},
    maximum_size: int = MAX_JSON_BYTES,
    allow_empty: bool = False,
) -> bytes:
    descriptor = open_canonical(path, os.O_RDONLY | os.O_NONBLOCK, label)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in allowed_modes
            or before.st_size > maximum_size
            or (before.st_size == 0 and not allow_empty)
        ):
            fail(f"{label} must be a safe root-owned single-link regular file")
        raw = bytearray()
        while len(raw) <= maximum_size:
            block = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
        if len(raw) > maximum_size:
            fail(f"{label} exceeds the maximum safe size")
        if stable_stat(before) != stable_stat(after) or len(raw) != before.st_size:
            fail(f"{label} changed while it was read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def require_private_directory(path: Path, label: str) -> Path:
    source = canonical_absolute(path, label)
    descriptor = open_canonical(source, os.O_RDONLY | os.O_DIRECTORY, label)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            fail(f"{label} must be a root-owned mode-0700 directory")
    finally:
        os.close(descriptor)
    return source


def require_root_directory(path: Path, label: str) -> Path:
    source = canonical_absolute(path, label)
    descriptor = open_canonical(source, os.O_RDONLY | os.O_DIRECTORY, label)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            fail(f"{label} must be a safe root-owned directory")
    finally:
        os.close(descriptor)
    return source


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def load_json(path: Path, label: str, *, maximum_size: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = read_safe_bytes(path, label, maximum_size=maximum_size)
    return load_json_bytes(raw, label), raw


def exact_object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} field set is not exact")
    return value


def require_hex40(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        fail(f"{label} must be a lowercase 40-character revision")
    return value


def require_hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")
    return value


def require_image(value: object, label: str) -> str:
    if not isinstance(value, str) or not IMAGE.fullmatch(value):
        fail(f"{label} must be an immutable image digest")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        fail(f"{label} must be an RFC3339 UTC timestamp")
    if parsed > datetime.now(timezone.utc) + MAX_CLOCK_SKEW:
        fail(f"{label} is future-dated")
    return parsed


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_release_env_bytes(raw: bytes, expected_keys: set[str], label: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    if not text.endswith("\n"):
        fail(f"{label} must end with one complete line")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            fail(f"{label} contains a malformed line at {line_number}")
        key, value = line.split("=", 1)
        if not ENV_KEY.fullmatch(key) or key in result or not value:
            fail(f"{label} contains an invalid field at {line_number}")
        result[key] = value
    if set(result) != expected_keys:
        fail(f"{label} field set is not exact")
    return result


def load_release_env(path: Path, expected_keys: set[str], label: str) -> tuple[dict[str, str], bytes]:
    raw = read_safe_bytes(path, label, allowed_modes={0o600}, maximum_size=MAX_ENV_BYTES)
    return parse_release_env_bytes(raw, expected_keys, label), raw


def canonical_env_bytes(values: dict[str, str], expected_keys: set[str]) -> bytes:
    if set(values) != expected_keys:
        fail("assembled release env field set is not exact")
    return "".join(f"{key}={values[key]}\n" for key in sorted(values)).encode()


def unsigned_env_bytes(values: dict[str, str], expected_keys: set[str]) -> bytes:
    return (
        b"# UNSIGNED: finalize-env must replace the detached-signature placeholder.\n"
        + canonical_env_bytes(values, expected_keys)
    )


def validate_policy_v5_snapshot(raw: bytes, snapshot_path: Path) -> dict[str, Any]:
    raw_value = load_json_bytes(raw, "successor policy")
    policy = validator.validate_successor_policy(snapshot_path)
    if policy != raw_value:
        fail("production successor-policy projection differs from exact JSON")
    if (
        policy.get("schema_version") != 5
        or policy.get("ceremony") != "holdfast-rikune-successor-v5"
    ):
        fail("Gen6 supply-chain assembly requires successor policy v5")
    predecessor = policy.get("predecessor")
    if (
        not isinstance(predecessor, dict)
        or "completion" in predecessor
        or "apply_receipt_sha256" in predecessor
        or not HEX64.fullmatch(str(predecessor.get("current_state_sha256", "")))
    ):
        fail("successor policy v5 predecessor completion binding is not exact")
    validator.validate_recovery_completion_binding_v5(
        predecessor.get("recovery_completion")
    )
    successor = policy.get("successor")
    if not isinstance(successor, dict) or any(
        successor.get(field) != GEN6_ACCESS_BUILD_INPUT_SHA256
        for field in (
            "source_access_build_input_sha256",
            "access_build_input_sha256",
        )
    ):
        fail("successor policy does not freeze the Gen6 Access build input")
    return policy


def validate_policy_v5_bytes(
    raw: bytes, *, snapshot_parent: Path = Path("/root")
) -> dict[str, Any]:
    with private_snapshot(
        {"successor-policy.json": raw}, parent=snapshot_parent
    ) as snapshot:
        return validate_policy_v5_snapshot(raw, snapshot / "successor-policy.json")


def validate_policy_v5(path: Path) -> dict[str, Any]:
    raw = read_safe_bytes(path, "successor policy")
    return validate_policy_v5_bytes(raw)


def validate_checkout_revision(expected_revision: str) -> None:
    revision = require_hex40(expected_revision, "release-tool revision")
    git = Path("/usr/bin/git")
    read_safe_bytes(
        git,
        "Git executable",
        allowed_modes={0o755},
        maximum_size=16 * 1024 * 1024,
    )
    head = subprocess.run(
        [str(git), "-C", str(REPOSITORY_ROOT), "rev-parse", "--verify", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        env=OFFLINE_ENV,
    )
    if head.returncode != 0 or head.stdout.decode("ascii", errors="replace").strip() != revision:
        fail("release-tool revision differs from the current Strad HEAD")
    status = subprocess.run(
        [
            str(git),
            "-C",
            str(REPOSITORY_ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "ops/holdfast",
            "Dockerfile",
            "Dockerfile.analyzer",
            "bridge/package-lock.json",
            ".github/workflows/release.yml",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        env=OFFLINE_ENV,
    )
    if status.returncode != 0 or status.stdout:
        fail("release-tool checkout contains tracked or untracked drift")


def validate_access_builder_key_binding(builder_id: object, public_key: bytes) -> str:
    public_key_sha256 = sha256_bytes(public_key)
    if public_key_sha256 != ACCESS_COSIGN_PUBLIC_KEY_SHA256:
        fail("Access Cosign public key differs from the canonical authority")
    validator.validate_access_builder_identity(builder_id, public_key_sha256)
    return public_key_sha256


def parse_access_receipt(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        fail(f"Access build receipt is not UTF-8: {error}")
    if not text.endswith("\n"):
        fail("Access build receipt lacks a final newline")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or "=" not in line:
            fail(f"Access build receipt is malformed at line {line_number}")
        key, value = line.split("=", 1)
        if not RECEIPT_KEY.fullmatch(key) or key in result or not value:
            fail(f"Access build receipt has an invalid field at line {line_number}")
        result[key] = value
    if set(result) != ACCESS_RECEIPT_FIELDS:
        fail("Access build receipt field set is not exact")
    return result


def safe_relative(value: str, label: str) -> Path:
    path = Path(value)
    if (
        not re.fullmatch(r"[A-Za-z0-9._/-]+", value)
        or path.is_absolute()
        or value in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        fail(f"{label} is not a safe relative path")
    return path


def verify_checksum_manifest(root: Path, raw: bytes, label: str) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    if not text.endswith("\n"):
        fail(f"{label} lacks a final newline")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if match is None:
            fail(f"{label} is malformed at line {line_number}")
        expected, relative_value = match.groups()
        relative = safe_relative(relative_value, label)
        if relative_value in result:
            fail(f"{label} contains a duplicate path")
        target_raw = read_safe_bytes(
            root / relative,
            f"{label} target {relative_value}",
            allowed_modes={0o600, 0o644, 0o755},
            maximum_size=32 * 1024 * 1024,
            allow_empty=True,
        )
        if sha256_bytes(target_raw) != expected:
            fail(f"{label} target checksum differs: {relative_value}")
        result[relative_value] = expected
    if not result:
        fail(f"{label} must not be empty")
    return result


def validate_access_candidate(
    release_root: Path,
    candidate_root: Path,
    policy: dict[str, Any],
    policy_path: Path,
    policy_sha256: str,
    release_tool_revision: str,
) -> tuple[dict[str, str], str, dict[str, Any]]:
    if candidate_root != release_root / "rikune-candidate-source":
        fail("candidate root must be the exact rikune-candidate-source child")
    receipt_raw = read_safe_bytes(
        release_root / "ACCESS-BUILD.receipt",
        "Access build receipt",
        allowed_modes={0o600},
        maximum_size=MAX_RECEIPT_BYTES,
    )
    receipt = parse_access_receipt(receipt_raw)
    if (
        receipt["schema"] != "holdfast-access-candidate-build/1"
        or receipt["platform"] != "linux/amd64"
        or receipt["build_input_schema"] != "access-build-input/2"
        or receipt["build_input_sha256"] != GEN6_ACCESS_BUILD_INPUT_SHA256
        or receipt["build_input_sha256"]
        != policy["successor"]["access_build_input_sha256"]
        or receipt["holdfast_release_tool_revision"] != release_tool_revision
        or receipt["provenance"] != "mode.max"
        or receipt["sbom"] != "enabled"
    ):
        fail("Access build receipt schema or Gen6 authority differs")
    require_image(receipt["image"], "Access candidate image")
    for field in (
        "build_input_sha256",
        "candidate_evidence_sha256",
        "candidate_targets_sha256",
        "render_inputs_sha256",
        "metadata_sha256",
    ):
        require_hex64(receipt[field], f"Access build receipt {field}")
    if (
        render_input_binding.access_tree_build_input_sha_v2(
            candidate_root / "access-governance"
        )
        != GEN6_ACCESS_BUILD_INPUT_SHA256
    ):
        fail("candidate Access tree differs from the frozen Gen6 build input")

    candidate_evidence, candidate_evidence_raw = load_json(
        candidate_root / "RELEASE-EVIDENCE.json", "candidate release evidence"
    )
    if sha256_bytes(candidate_evidence_raw) != receipt["candidate_evidence_sha256"]:
        fail("candidate release evidence differs from the Access receipt")
    release_validator.validate_successor_evidence(
        candidate_evidence,
        True,
        candidate_evidence.get("release"),
        policy_path.absolute(),
    )
    if candidate_evidence.get("holdfast_release_tool_revision") != release_tool_revision:
        fail("candidate release evidence tool revision differs")

    targets_raw = read_safe_bytes(
        candidate_root / "TARGETS.sha256",
        "candidate targets manifest",
        maximum_size=MAX_MANIFEST_BYTES,
    )
    if sha256_bytes(targets_raw) != receipt["candidate_targets_sha256"]:
        fail("candidate targets manifest differs from the Access receipt")
    targets = verify_checksum_manifest(candidate_root, targets_raw, "candidate targets")
    for evidence_field, target_path in (
        (
            "permission_catalog_sha256",
            "access-governance/catalog/permissions.snapshot.json",
        ),
        (
            "package_catalog_sha256",
            "access-governance/catalog/packages.snapshot.json",
        ),
    ):
        if candidate_evidence[evidence_field] != targets.get(target_path):
            fail(f"candidate catalog target differs: {evidence_field}")

    render_inputs_raw = read_safe_bytes(
        candidate_root / "RENDER-INPUTS.sha256",
        "candidate render-input manifest",
        maximum_size=MAX_MANIFEST_BYTES,
    )
    if sha256_bytes(render_inputs_raw) != receipt["render_inputs_sha256"]:
        fail("candidate render-input manifest differs from the Access receipt")
    render_inputs = verify_checksum_manifest(
        OPS_ROOT, render_inputs_raw, "candidate render inputs"
    )
    if render_inputs.get("successor-policy.json") != policy_sha256:
        fail("candidate render inputs differ from the exact policy-v5 bytes")

    metadata, metadata_raw = load_json(
        release_root / "access-build.metadata.json", "Access build metadata"
    )
    if sha256_bytes(metadata_raw) != receipt["metadata_sha256"]:
        fail("Access build metadata differs from the Access receipt")
    metadata = exact_object(
        metadata,
        {
            "buildx.build.provenance",
            "buildx.build.ref",
            "containerimage.descriptor",
            "containerimage.digest",
            "image.name",
        },
        "Access build metadata",
    )
    expected_digest = receipt["image"].rsplit("@", 1)[1]
    descriptor = exact_object(
        metadata["containerimage.descriptor"],
        {"mediaType", "digest", "size"},
        "Access build metadata descriptor",
    )
    if (
        descriptor["mediaType"] != "application/vnd.oci.image.index.v1+json"
        or descriptor["digest"] != expected_digest
        or metadata["containerimage.digest"] != expected_digest
        or metadata["image.name"]
        != f"{receipt['image'].rsplit('@', 1)[0]}:{release_root.name}"
    ):
        fail("Access build metadata image binding differs")
    metadata_builder = require_nested_value(
        metadata,
        ("buildx.build.provenance", "builder", "id"),
        "Access build metadata",
    )
    if metadata_builder != receipt["provenance_builder_id"]:
        fail("Access build metadata builder identity differs")

    predicate, predicate_raw = load_json(
        release_root / "ACCESS-CANDIDATE.builder-provenance.predicate.json",
        "Access provenance predicate",
    )
    predicate = exact_object(
        predicate,
        {"buildDefinition", "runDetails"},
        "Access provenance predicate",
    )
    if (
        require_nested_value(
            predicate,
            ("runDetails", "builder", "id"),
            "Access provenance predicate",
        )
        != receipt["provenance_builder_id"]
    ):
        fail("Access provenance predicate builder identity differs")
    provenance_wrapper, _ = load_json(
        release_root / "ACCESS-CANDIDATE.provenance.json",
        "Access provenance wrapper",
    )
    if exact_object(
        provenance_wrapper, {"SLSA"}, "Access provenance wrapper"
    )["SLSA"] != predicate:
        fail("Access provenance wrapper differs from the exact predicate")
    sbom_wrapper, _ = load_json(
        release_root / "ACCESS-CANDIDATE.sbom.json",
        "Access SBOM wrapper",
        maximum_size=MAX_JSON_BYTES,
    )
    sbom = exact_object(sbom_wrapper, {"SPDX"}, "Access SBOM wrapper")["SPDX"]
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("dataLicense") != "CC0-1.0"
        or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        fail("Access SBOM wrapper schema differs")
    return (
        receipt,
        sha256_bytes(receipt_raw),
        {
            "metadata_descriptor": descriptor,
            "provenance_predicate": predicate,
            "provenance_sha256": sha256_bytes(predicate_raw),
            "sbom_predicate": sbom,
        },
    )


def descriptor_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        fail(f"{label} digest is invalid")
    return require_hex64(value.removeprefix("sha256:"), label)


def verify_layout_blob(
    layout: Path,
    descriptor: dict[str, Any],
    label: str,
    *,
    maximum_size: int,
) -> None:
    digest = descriptor_digest(descriptor.get("digest"), label)
    size = descriptor.get("size")
    if type(size) is not int or size < 1 or size > maximum_size:
        fail(f"{label} size is invalid")
    path = layout / "blobs" / "sha256" / digest
    descriptor_fd = open_canonical(path, os.O_RDONLY | os.O_NONBLOCK, label)
    try:
        before = os.fstat(descriptor_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o600, 0o644}
            or before.st_size != size
        ):
            fail(f"{label} must be an exact safe OCI blob")
        observed = hashlib.sha256()
        observed_size = 0
        while True:
            block = os.read(descriptor_fd, 1024 * 1024)
            if not block:
                break
            observed.update(block)
            observed_size += len(block)
            if observed_size > maximum_size:
                fail(f"{label} exceeds the maximum safe size")
        after = os.fstat(descriptor_fd)
        if (
            stable_stat(before) != stable_stat(after)
            or observed_size != size
            or observed.hexdigest() != digest
        ):
            fail(f"{label} content differs from its OCI descriptor")
    finally:
        os.close(descriptor_fd)


def read_layout_blob(
    layout: Path,
    descriptor: dict[str, Any],
    label: str,
    *,
    maximum_size: int = MAX_JSON_BYTES,
) -> bytes:
    digest = descriptor_digest(descriptor.get("digest"), label)
    verify_layout_blob(layout, descriptor, label, maximum_size=maximum_size)
    raw = read_safe_bytes(
        layout / "blobs" / "sha256" / digest,
        label,
        allowed_modes={0o600, 0o644},
        maximum_size=maximum_size,
    )
    if sha256_bytes(raw) != digest:
        fail(f"{label} content differs from its OCI descriptor")
    return raw


def validate_layout_directories(path: Path, label: str) -> Path:
    layout = require_private_directory(path, label)
    require_private_directory(layout / "blobs", f"{label} blobs")
    require_private_directory(layout / "blobs" / "sha256", f"{label} sha256 blobs")
    oci_layout, _ = load_json(layout / "oci-layout", f"{label} oci-layout")
    if oci_layout != {"imageLayoutVersion": "1.0.0"}:
        fail(f"{label} OCI layout version differs")
    return layout


def validate_statement_subject(
    statement: dict[str, Any],
    primary_digest: str,
    predicate_type: str,
    label: str,
) -> dict[str, Any]:
    statement = exact_object(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        label,
    )
    subjects = statement["subject"]
    if (
        statement["_type"] != "https://in-toto.io/Statement/v1"
        or statement["predicateType"] != predicate_type
        or not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], dict)
        or subjects[0].get("digest") != {"sha256": primary_digest}
    ):
        fail(f"{label} subject or predicate differs")
    return statement


def parse_bundle(
    raw: bytes,
    root_digest: str,
    predicate_type: str,
    issued_at: datetime,
    label: str,
) -> tuple[int, bytes]:
    bundle = exact_object(
        load_json_bytes(raw, label),
        {"mediaType", "dsseEnvelope", "verificationMaterial"},
        label,
    )
    if bundle["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
        fail(f"{label} media type differs")
    envelope = exact_object(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        f"{label} envelope",
    )
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        fail(f"{label} payload type differs")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        fail(f"{label} signature set differs")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (TypeError, ValueError):
        fail(f"{label} payload is not canonical base64")
    statement = validate_statement_subject(
        load_json_bytes(payload, f"{label} payload"),
        root_digest,
        predicate_type,
        f"{label} statement",
    )
    if predicate_type == IMAGE_SIGNATURE_PREDICATE and statement["predicate"] != {}:
        fail(f"{label} signature predicate differs")
    material = bundle["verificationMaterial"]
    if not isinstance(material, dict) or set(material) not in (
        {"certificate", "timestampVerificationData", "tlogEntries"},
        {"publicKey", "timestampVerificationData", "tlogEntries"},
    ):
        fail(f"{label} verification material differs")
    entries = material["tlogEntries"]
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        fail(f"{label} transparency-log entry set differs")
    entry = entries[0]
    log_index = entry.get("logIndex")
    integrated_time = entry.get("integratedTime")
    if (
        not isinstance(log_index, str)
        or not log_index.isdigit()
        or not isinstance(integrated_time, str)
        or not integrated_time.isdigit()
        or datetime.fromtimestamp(int(integrated_time), timezone.utc)
        > issued_at + MAX_CLOCK_SKEW
    ):
        fail(f"{label} transparency-log time or index differs")
    return int(log_index), payload


def locate_sigstore_bundles(
    layout: Path,
    root_digest: str,
    required_predicates: set[str],
    issued_at: datetime,
    label: str,
) -> dict[str, tuple[bytes, int]]:
    found: dict[str, tuple[bytes, int]] = {}
    blob_root = layout / "blobs" / "sha256"
    for entry in sorted(os.scandir(blob_root), key=lambda item: item.name):
        if not HEX64.fullmatch(entry.name):
            fail(f"{label} contains an invalid OCI blob name")
        metadata = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128 * 1024:
            continue
        raw = read_safe_bytes(
            blob_root / entry.name,
            f"{label} OCI metadata blob",
            maximum_size=128 * 1024,
        )
        if sha256_bytes(raw) != entry.name:
            fail(f"{label} OCI metadata blob name differs from its content")
        try:
            value = load_json_bytes(raw, f"{label} OCI metadata blob")
        except ValueError:
            continue
        if value.get("artifactType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
            continue
        subject = value.get("subject")
        if not isinstance(subject, dict) or subject.get("digest") != f"sha256:{root_digest}":
            continue
        annotations = value.get("annotations")
        if not isinstance(annotations, dict):
            fail(f"{label} Sigstore artifact annotations differ")
        predicate_type = annotations.get("dev.sigstore.bundle.predicateType")
        if predicate_type not in required_predicates:
            continue
        manifest = exact_object(
            value,
            {
                "schemaVersion",
                "mediaType",
                "artifactType",
                "config",
                "layers",
                "subject",
                "annotations",
            },
            f"{label} Sigstore artifact manifest",
        )
        if (
            manifest["schemaVersion"] != 2
            or manifest["mediaType"]
            != "application/vnd.oci.image.manifest.v1+json"
            or manifest["artifactType"]
            != "application/vnd.dev.sigstore.bundle.v0.3+json"
            or set(annotations)
            != {
                "dev.sigstore.bundle.content",
                "dev.sigstore.bundle.predicateType",
                "org.opencontainers.image.created",
            }
            or annotations["dev.sigstore.bundle.content"] != "dsse-envelope"
        ):
            fail(f"{label} Sigstore artifact schema differs")
        subject = exact_object(
            manifest["subject"],
            {"mediaType", "digest", "size"},
            f"{label} Sigstore artifact subject",
        )
        root_blob = layout / "blobs" / "sha256" / root_digest
        if (
            subject["mediaType"] != "application/vnd.oci.image.index.v1+json"
            or subject["digest"] != f"sha256:{root_digest}"
            or subject["size"] != root_blob.stat().st_size
        ):
            fail(f"{label} Sigstore artifact subject differs")
        config = manifest["config"]
        if not isinstance(config, dict) or set(config) not in (
            {"mediaType", "digest", "size"},
            {"mediaType", "digest", "size", "artifactType"},
        ):
            fail(f"{label} Sigstore artifact config differs")
        if config["mediaType"] != "application/vnd.oci.empty.v1+json":
            fail(f"{label} Sigstore artifact config media type differs")
        if (
            "artifactType" in config
            and config["artifactType"]
            != "application/vnd.dev.sigstore.bundle.v0.3+json"
        ):
            fail(f"{label} Sigstore artifact config artifact type differs")
        config_raw = read_layout_blob(
            layout,
            config,
            f"{label} Sigstore artifact config",
            maximum_size=65_536,
        )
        if config_raw != b"{}":
            fail(f"{label} Sigstore artifact config is not empty")
        layers = manifest["layers"]
        if not isinstance(layers, list) or len(layers) != 1 or not isinstance(layers[0], dict):
            fail(f"{label} Sigstore artifact layer set differs")
        layer = exact_object(
            layers[0],
            {"mediaType", "digest", "size"},
            f"{label} Sigstore artifact layer",
        )
        if layer["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
            fail(f"{label} Sigstore artifact layer media type differs")
        bundle_raw = read_layout_blob(
            layout,
            layer,
            f"{label} {predicate_type} bundle",
            maximum_size=128 * 1024,
        )
        log_index, _ = parse_bundle(
            bundle_raw,
            root_digest,
            predicate_type,
            issued_at,
            f"{label} {predicate_type} bundle",
        )
        if predicate_type in found:
            fail(f"{label} contains duplicate {predicate_type} bundles")
        found[predicate_type] = (bundle_raw, log_index)
    if set(found) != required_predicates:
        fail(f"{label} Sigstore bundle set is not exact")
    return found


def write_private_file(root: Path, name: str, raw: bytes) -> None:
    descriptor = os.open(
        root / name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def private_snapshot(
    files: dict[str, bytes], *, parent: Path = Path("/root")
) -> Iterator[Path]:
    snapshot_parent = require_private_directory(parent, "snapshot parent")
    with tempfile.TemporaryDirectory(
        prefix="holdfast-supply-v5-snapshot-", dir=snapshot_parent
    ) as name:
        root = Path(name)
        root.chmod(0o700)
        if not files:
            fail("private snapshot must contain at least one authority")
        for filename, raw in files.items():
            if not re.fullmatch(r"[A-Za-z0-9._-]+", filename) or not raw:
                fail("private snapshot authority name or content is invalid")
            write_private_file(root, filename, raw)
            os.chmod(root / filename, 0o400, follow_symlinks=False)
        directory = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        yield root


def run_cosign(
    arguments: list[str],
    files: dict[str, bytes],
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    read_safe_bytes(
        DOCKER,
        "Docker executable",
        allowed_modes={0o755},
        maximum_size=128 * 1024 * 1024,
    )
    with tempfile.TemporaryDirectory(prefix="holdfast-cosign-v5-", dir="/root") as name:
        root = Path(name)
        for filename, raw in files.items():
            write_private_file(root, filename, raw)
        command = [
            str(DOCKER),
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--user",
            "0:0",
            "--volume",
            f"{root}:/holdfast-input:ro",
            COSIGN_VERIFIER_IMAGE,
            *arguments,
        ]
        completed = runner(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=OFFLINE_ENV,
        )
        if completed.returncode != 0:
            fail("pinned offline Cosign verification failed")


def verify_attestation_bundle(
    raw: bytes,
    trusted_root: bytes,
    root_digest: str,
    predicate_type: str,
    *,
    source_revision: str | None,
    public_key: bytes | None,
    require_signed_timestamp: bool,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    arguments = [
        "verify-blob-attestation",
        "--bundle",
        "/holdfast-input/bundle.json",
        "--trusted-root",
        "/holdfast-input/trusted-root.json",
        "--digest",
        root_digest,
        "--digestAlg",
        "sha256",
        "--type",
        predicate_type,
    ]
    files = {"bundle.json": raw, "trusted-root.json": trusted_root}
    if public_key is None:
        if source_revision is None:
            fail("keyless verification requires the Strad source revision")
        arguments.extend(
            [
                "--certificate-identity",
                COSIGN_IDENTITY,
                "--certificate-oidc-issuer",
                COSIGN_ISSUER,
                "--certificate-github-workflow-sha",
                source_revision,
            ]
        )
    else:
        files["cosign.pub"] = public_key
        arguments.extend(["--key", "/holdfast-input/cosign.pub"])
    if require_signed_timestamp:
        arguments.append("--use-signed-timestamps")
    run_cosign(arguments, files, runner=runner)


def require_nested_value(value: object, path: tuple[str, ...], label: str) -> object:
    current = value
    for field in path:
        if not isinstance(current, dict) or field not in current:
            fail(f"{label} lacks {'.'.join(path)}")
        current = current[field]
    return current


def validate_buildkit_provenance(
    raw: bytes,
    primary_digest: str,
    image_key: str,
    release: dict[str, str],
    source_revision: str | None,
) -> str:
    statement = validate_statement_subject(
        load_json_bytes(raw, f"{image_key} BuildKit provenance"),
        primary_digest,
        PROVENANCE_PREDICATE,
        f"{image_key} BuildKit provenance",
    )
    predicate = exact_object(
        statement["predicate"],
        {"buildDefinition", "runDetails"},
        f"{image_key} provenance predicate",
    )
    builder_id = require_nested_value(
        predicate,
        ("runDetails", "builder", "id"),
        f"{image_key} provenance",
    )
    if not isinstance(builder_id, str) or len(builder_id) < 8:
        fail(f"{image_key} provenance builder identity is absent")
    if source_revision is None:
        return builder_id

    external = require_nested_value(
        predicate,
        ("buildDefinition", "externalParameters"),
        f"{image_key} provenance",
    )
    request_args = require_nested_value(
        external,
        ("request", "args"),
        f"{image_key} provenance",
    )
    root_args = require_nested_value(
        external,
        ("request", "root", "request", "args"),
        f"{image_key} provenance",
    )
    expected_common = {
        "build-arg:STRAD_REVISION": source_revision,
        "label:org.opencontainers.image.revision": source_revision,
        "label:org.opencontainers.image.source": SOURCE_REPOSITORY,
    }
    expected_specific = (
        {
            "build-arg:STRAD_RUST_BUILDER_IMAGE": release[
                "STRAD_RUST_BUILDER_IMAGE"
            ],
            "build-arg:STRAD_RUNTIME_IMAGE": release["STRAD_RUNTIME_IMAGE"],
        }
        if image_key == "STRAD_IMAGE"
        else {
            "build-arg:STRAD_NODE_BUILDER_IMAGE": release[
                "STRAD_NODE_BUILDER_IMAGE"
            ],
            "build-arg:RIKUNE_ANALYZER_IMAGE": release[
                "RIKUNE_ANALYZER_IMAGE"
            ],
        }
    )
    for field, expected in (expected_common | expected_specific).items():
        if (
            not isinstance(request_args, dict)
            or request_args.get(field) != expected
            or not isinstance(root_args, dict)
            or root_args.get(field) != expected
        ):
            fail(f"{image_key} provenance build input differs: {field}")
    for field, expected in (
        ("vcs:revision", source_revision),
        ("vcs:source", SOURCE_REPOSITORY),
    ):
        if not isinstance(root_args, dict) or root_args.get(field) != expected:
            fail(f"{image_key} provenance source differs: {field}")
    return builder_id


def validate_sbom(raw: bytes, primary_digest: str, image_key: str) -> None:
    statement = validate_statement_subject(
        load_json_bytes(raw, f"{image_key} SBOM"),
        primary_digest,
        SBOM_PREDICATE,
        f"{image_key} SBOM",
    )
    predicate = statement["predicate"]
    if (
        not isinstance(predicate, dict)
        or predicate.get("spdxVersion") != "SPDX-2.3"
        or predicate.get("dataLicense") != "CC0-1.0"
        or predicate.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        fail(f"{image_key} SBOM schema differs")


def validate_oci_layout(
    layout_path: Path,
    image_key: str,
    expected_image: str,
    release: dict[str, str],
    issued_at: datetime,
    trusted_root: bytes,
    *,
    source_revision: str | None,
    public_key: bytes | None,
    access_artifacts: dict[str, Any] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    layout = validate_layout_directories(layout_path, f"{image_key} OCI layout")
    image = require_image(expected_image, image_key)
    root_digest = image.rsplit("@sha256:", 1)[1]
    index, _ = load_json(layout / "index.json", f"{image_key} OCI index")
    index = exact_object(
        index,
        {"schemaVersion", "mediaType", "manifests"},
        f"{image_key} OCI index",
    )
    manifests = index["manifests"]
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != "application/vnd.oci.image.index.v1+json"
        or not isinstance(manifests, list)
        or len(manifests) != 1
        or not isinstance(manifests[0], dict)
    ):
        fail(f"{image_key} OCI root index differs")
    root_descriptor = exact_object(
        manifests[0],
        {"mediaType", "size", "digest", "annotations"},
        f"{image_key} OCI root descriptor",
    )
    if (
        root_descriptor["mediaType"]
        != "application/vnd.oci.image.index.v1+json"
        or root_descriptor["digest"] != f"sha256:{root_digest}"
        or root_descriptor["annotations"]
        != {"kind": "dev.cosignproject.cosign/imageIndex"}
    ):
        fail(f"{image_key} OCI root descriptor differs")
    if access_artifacts is not None:
        expected_descriptor = access_artifacts.get("metadata_descriptor")
        if not isinstance(expected_descriptor, dict) or any(
            root_descriptor.get(field) != expected_descriptor.get(field)
            for field in ("mediaType", "digest", "size")
        ):
            fail("Access OCI root differs from the receipt-bound build metadata")
    root_raw = read_layout_blob(
        layout,
        root_descriptor,
        f"{image_key} immutable root manifest",
    )
    root = exact_object(
        load_json_bytes(root_raw, f"{image_key} immutable root manifest"),
        {"schemaVersion", "mediaType", "manifests"},
        f"{image_key} immutable root manifest",
    )
    children = root["manifests"]
    if (
        root["schemaVersion"] != 2
        or root["mediaType"] != "application/vnd.oci.image.index.v1+json"
        or not isinstance(children, list)
        or len(children) != 2
    ):
        fail(f"{image_key} platform/attestation manifest set differs")
    primary_values = [
        value
        for value in children
        if isinstance(value, dict)
        and value.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    attestation_values = [
        value
        for value in children
        if isinstance(value, dict)
        and value.get("platform") == {"architecture": "unknown", "os": "unknown"}
    ]
    if len(primary_values) != 1 or len(attestation_values) != 1:
        fail(f"{image_key} must contain one linux/amd64 image and one attestation")
    primary = exact_object(
        primary_values[0],
        {"mediaType", "digest", "size", "platform"},
        f"{image_key} primary descriptor",
    )
    attestation = exact_object(
        attestation_values[0],
        {"mediaType", "digest", "size", "annotations", "platform"},
        f"{image_key} attestation descriptor",
    )
    if (
        primary["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
        or attestation["mediaType"]
        != "application/vnd.oci.image.manifest.v1+json"
    ):
        fail(f"{image_key} child manifest media type differs")
    primary_digest = descriptor_digest(primary["digest"], f"{image_key} primary")
    if attestation["annotations"] != {
        "vnd.docker.reference.digest": primary["digest"],
        "vnd.docker.reference.type": "attestation-manifest",
    }:
        fail(f"{image_key} attestation subject annotation differs")
    primary_manifest = exact_object(
        load_json_bytes(
            read_layout_blob(layout, primary, f"{image_key} primary manifest"),
            f"{image_key} primary manifest",
        ),
        {"schemaVersion", "mediaType", "config", "layers"},
        f"{image_key} primary manifest",
    )
    if (
        primary_manifest["schemaVersion"] != 2
        or primary_manifest["mediaType"]
        != "application/vnd.oci.image.manifest.v1+json"
    ):
        fail(f"{image_key} primary manifest schema differs")
    config_descriptor = exact_object(
        primary_manifest["config"],
        {"mediaType", "digest", "size"},
        f"{image_key} config descriptor",
    )
    if config_descriptor["mediaType"] != "application/vnd.oci.image.config.v1+json":
        fail(f"{image_key} config media type differs")
    config = load_json_bytes(
        read_layout_blob(layout, config_descriptor, f"{image_key} image config"),
        f"{image_key} image config",
    )
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        fail(f"{image_key} image config platform differs")
    if source_revision is not None:
        labels = require_nested_value(config, ("config", "Labels"), f"{image_key} config")
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.revision") != source_revision
            or labels.get("org.opencontainers.image.source") != SOURCE_REPOSITORY
        ):
            fail(f"{image_key} image config source revision differs")
    runtime_layers = primary_manifest["layers"]
    if not isinstance(runtime_layers, list) or not runtime_layers:
        fail(f"{image_key} runtime layer set is absent")
    for position, runtime_layer in enumerate(runtime_layers):
        runtime_layer = exact_object(
            runtime_layer,
            {"mediaType", "digest", "size"},
            f"{image_key} runtime layer {position}",
        )
        if not isinstance(runtime_layer["mediaType"], str) or not runtime_layer[
            "mediaType"
        ].startswith("application/vnd.oci.image.layer."):
            fail(f"{image_key} runtime layer {position} media type differs")
        verify_layout_blob(
            layout,
            runtime_layer,
            f"{image_key} runtime layer {position}",
            maximum_size=8 * 1024 * 1024 * 1024,
        )

    attestation_manifest = load_json_bytes(
        read_layout_blob(
            layout, attestation, f"{image_key} BuildKit attestation manifest"
        ),
        f"{image_key} BuildKit attestation manifest",
    )
    if source_revision is None:
        attestation_manifest = exact_object(
            attestation_manifest,
            {"schemaVersion", "mediaType", "config", "layers"},
            f"{image_key} BuildKit attestation manifest",
        )
    else:
        attestation_manifest = exact_object(
            attestation_manifest,
            {
                "schemaVersion",
                "mediaType",
                "artifactType",
                "config",
                "layers",
                "subject",
            },
            f"{image_key} BuildKit attestation manifest",
        )
        if (
            attestation_manifest["artifactType"]
            != "application/vnd.docker.attestation.manifest.v1+json"
            or attestation_manifest["subject"] != {
                "mediaType": primary["mediaType"],
                "digest": primary["digest"],
                "size": primary["size"],
            }
        ):
            fail(f"{image_key} BuildKit attestation subject differs")
    if (
        attestation_manifest["schemaVersion"] != 2
        or attestation_manifest["mediaType"]
        != "application/vnd.oci.image.manifest.v1+json"
    ):
        fail(f"{image_key} BuildKit attestation manifest schema differs")
    attestation_config = attestation_manifest["config"]
    if not isinstance(attestation_config, dict) or set(attestation_config) not in (
        {"mediaType", "digest", "size"},
        {"mediaType", "digest", "size", "data"},
    ):
        fail(f"{image_key} BuildKit attestation config descriptor differs")
    expected_attestation_config_media_type = (
        "application/vnd.oci.image.config.v1+json"
        if source_revision is None
        else "application/vnd.oci.empty.v1+json"
    )
    if attestation_config["mediaType"] != expected_attestation_config_media_type:
        fail(f"{image_key} BuildKit attestation config media type differs")
    if source_revision is None and "data" in attestation_config:
        fail(f"{image_key} BuildKit attestation config data is unexpected")
    attestation_config_raw = read_layout_blob(
        layout,
        attestation_config,
        f"{image_key} BuildKit attestation config",
        maximum_size=65_536,
    )
    if "data" in attestation_config:
        try:
            inline_config = base64.b64decode(attestation_config["data"], validate=True)
        except (TypeError, ValueError):
            fail(f"{image_key} BuildKit attestation config data is invalid")
        if inline_config != attestation_config_raw:
            fail(f"{image_key} BuildKit attestation config data differs")
    layers = attestation_manifest["layers"]
    if not isinstance(layers, list) or len(layers) != 2:
        fail(f"{image_key} BuildKit SBOM/provenance layer set differs")
    materials: dict[str, bytes] = {}
    for layer in layers:
        if not isinstance(layer, dict):
            fail(f"{image_key} BuildKit attestation descriptor differs")
        layer = exact_object(
            layer,
            {"mediaType", "digest", "size", "annotations"},
            f"{image_key} BuildKit attestation descriptor",
        )
        predicate_type = layer["annotations"].get("in-toto.io/predicate-type")
        if (
            layer["mediaType"] != "application/vnd.in-toto+json"
            or predicate_type not in {PROVENANCE_PREDICATE, SBOM_PREDICATE}
            or predicate_type in materials
        ):
            fail(f"{image_key} BuildKit predicate set differs")
        materials[predicate_type] = read_layout_blob(
            layout,
            layer,
            f"{image_key} {predicate_type}",
        )
    if set(materials) != {PROVENANCE_PREDICATE, SBOM_PREDICATE}:
        fail(f"{image_key} BuildKit predicate set is incomplete")
    builder_id = validate_buildkit_provenance(
        materials[PROVENANCE_PREDICATE],
        primary_digest,
        image_key,
        release,
        source_revision,
    )
    validate_sbom(materials[SBOM_PREDICATE], primary_digest, image_key)
    if access_artifacts is not None:
        provenance_statement = load_json_bytes(
            materials[PROVENANCE_PREDICATE],
            "Access embedded BuildKit provenance",
        )
        sbom_statement = load_json_bytes(
            materials[SBOM_PREDICATE],
            "Access embedded BuildKit SBOM",
        )
        if (
            provenance_statement.get("predicate")
            != access_artifacts.get("provenance_predicate")
            or sbom_statement.get("predicate")
            != access_artifacts.get("sbom_predicate")
        ):
            fail("Access OCI attestations differ from the receipt-bound build artifacts")

    required_bundles = {IMAGE_SIGNATURE_PREDICATE}
    if source_revision is not None:
        required_bundles.add(PROVENANCE_PREDICATE)
    bundles = locate_sigstore_bundles(
        layout,
        root_digest,
        required_bundles,
        issued_at,
        image_key,
    )
    signature_raw, signature_log_index = bundles[IMAGE_SIGNATURE_PREDICATE]
    verify_attestation_bundle(
        signature_raw,
        trusted_root,
        root_digest,
        IMAGE_SIGNATURE_PREDICATE,
        source_revision=source_revision,
        public_key=public_key,
        require_signed_timestamp=True,
        runner=runner,
    )
    verification_digests = [sha256_bytes(signature_raw)]
    if source_revision is not None:
        provenance_bundle_raw, _ = bundles[PROVENANCE_PREDICATE]
        verify_attestation_bundle(
            provenance_bundle_raw,
            trusted_root,
            root_digest,
            PROVENANCE_PREDICATE,
            source_revision=source_revision,
            public_key=None,
            require_signed_timestamp=False,
            runner=runner,
        )
        verification_digests.append(sha256_bytes(provenance_bundle_raw))
    verification_set = "".join(
        f"sha256={digest}\n" for digest in sorted(verification_digests)
    ).encode("utf-8")
    signature = (
        {
            "identity": COSIGN_IDENTITY,
            "issuer": COSIGN_ISSUER,
            "rekor_log_index": signature_log_index,
        }
        if public_key is None
        else {
            "mode": "key",
            "public_key_sha256": sha256_bytes(public_key),
            "rekor_log_index": signature_log_index,
        }
    )
    record = {
        "image": image,
        "manifest_digest": f"sha256:{root_digest}",
        "registry": image.split("/", 1)[0],
        "subject_digest": f"sha256:{root_digest}",
        "sbom": {
            "uri": f"oci://{image}#buildkit-spdx",
            "sha256": sha256_bytes(materials[SBOM_PREDICATE]),
        },
        "provenance": {
            "uri": f"oci://{image}#buildkit-slsa-v1",
            "sha256": sha256_bytes(materials[PROVENANCE_PREDICATE]),
            "builder_id": builder_id,
        },
        "attestation": {
            "uri": f"oci://{image}#offline-sigstore-verification-set-v1",
            "sha256": sha256_bytes(verification_set),
        },
        "signature": signature,
    }
    if set(record) != IMAGE_RECORD_FIELDS:
        fail(f"{image_key} registry record projection differs")
    return record


def verify_release_manifest(
    manifest_path: Path,
    bundle_path: Path,
    trusted_root: bytes,
    release: dict[str, str],
    source_revision: str,
    issued_at: datetime,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> str:
    manifest, manifest_raw = load_json(manifest_path, "Strad release manifest")
    bundle_raw = read_safe_bytes(
        bundle_path,
        "Strad release manifest Sigstore bundle",
        maximum_size=128 * 1024,
    )
    manifest = exact_object(
        manifest,
        {
            "schema_version",
            "issued_at",
            "source_repository",
            "source_revision",
            "platform",
            "images",
            "build_inputs",
        },
        "Strad release manifest",
    )
    manifest_issued_at = parse_timestamp(
        manifest["issued_at"], "Strad release manifest issued_at"
    )
    if manifest_issued_at > issued_at + MAX_CLOCK_SKEW:
        fail("Strad release manifest is newer than the assembly authority")
    if (
        manifest["schema_version"] != 1
        or manifest["source_repository"] != SOURCE_REPOSITORY
        or manifest["source_revision"] != source_revision
        or manifest["platform"] != "linux/amd64"
        or manifest["images"]
        != {
            "STRAD_IMAGE": release["STRAD_IMAGE"],
            "STRAD_ANALYZER_IMAGE": release["STRAD_ANALYZER_IMAGE"],
        }
        or manifest["build_inputs"]
        != {
            "STRAD_RUST_BUILDER_IMAGE": release["STRAD_RUST_BUILDER_IMAGE"],
            "STRAD_RUNTIME_IMAGE": release["STRAD_RUNTIME_IMAGE"],
            "STRAD_NODE_BUILDER_IMAGE": release["STRAD_NODE_BUILDER_IMAGE"],
            "RIKUNE_ANALYZER_IMAGE": release["RIKUNE_ANALYZER_IMAGE"],
            "RIKUNE_STATIC_LOCK_SHA256": STATIC_LOCK_SHA256,
        }
    ):
        fail("Strad release manifest differs from the Gen6 release pins")
    run_cosign(
        [
            "verify-blob",
            "--bundle",
            "/holdfast-input/release-images.sigstore.json",
            "--trusted-root",
            "/holdfast-input/trusted-root.json",
            "--certificate-identity",
            COSIGN_IDENTITY,
            "--certificate-oidc-issuer",
            COSIGN_ISSUER,
            "--certificate-github-workflow-sha",
            source_revision,
            "--use-signed-timestamps",
            "/holdfast-input/release-images.json",
        ],
        {
            "release-images.json": manifest_raw,
            "release-images.sigstore.json": bundle_raw,
            "trusted-root.json": trusted_root,
        },
        runner=runner,
    )
    return sha256_bytes(manifest_raw)


def validate_predecessor_release_bindings(
    release: dict[str, str], predecessor: dict[str, Any]
) -> None:
    bindings = {
        "ACCESS_GOVERNANCE_IMAGE": "access_image",
        "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": "access_build_input_sha256",
        "PERMISSION_CATALOG_SHA256": "permission_catalog_sha256",
        "PACKAGE_CATALOG_SHA256": "package_catalog_sha256",
    }
    for release_field, policy_field in bindings.items():
        if release.get(release_field) != predecessor.get(policy_field):
            fail(
                "Gen5 signed release differs from the predecessor policy: "
                f"{release_field}"
            )


def validate_predecessor_candidate_binding(
    previous_root: Path,
    release: dict[str, str],
    document: dict[str, Any],
    predecessor: dict[str, Any],
) -> None:
    receipt_raw = read_safe_bytes(
        previous_root / "ACCESS-BUILD.receipt",
        "Gen5 Access build receipt",
        allowed_modes={0o600},
        maximum_size=MAX_RECEIPT_BYTES,
    )
    receipt = parse_access_receipt(receipt_raw)
    fresh = exact_object(
        document.get("fresh_image_bindings"),
        FRESH_IMAGE_KEYS,
        "Gen5 fresh image bindings",
    )
    access_binding = exact_object(
        fresh.get("ACCESS_GOVERNANCE_IMAGE"),
        {
            "record_sha256",
            "build_input_sha256",
            "candidate_receipt_sha256",
        },
        "Gen5 fresh Access image binding",
    )
    if access_binding["candidate_receipt_sha256"] != sha256_bytes(receipt_raw):
        fail("Gen5 signed supply evidence does not bind the Access build receipt")
    expected = {
        "schema": "holdfast-access-candidate-build/1",
        "platform": "linux/amd64",
        "image": predecessor["access_image"],
        "build_input_schema": predecessor["access_build_input_schema"],
        "build_input_sha256": predecessor["access_build_input_sha256"],
        "candidate_evidence_sha256": predecessor["candidate_evidence_sha256"],
        "candidate_targets_sha256": predecessor["candidate_targets_sha256"],
        "holdfast_release_tool_revision": release[
            "HOLDFAST_RELEASE_TOOL_REVISION"
        ],
        "provenance": "mode.max",
        "sbom": "enabled",
    }
    for field, wanted in expected.items():
        if receipt[field] != wanted:
            fail(f"Gen5 Access build receipt differs from predecessor: {field}")
    candidate_root = previous_root / "rikune-candidate-source"
    artifacts = {
        "candidate_evidence_sha256": (
            candidate_root / "RELEASE-EVIDENCE.json",
            MAX_JSON_BYTES,
        ),
        "candidate_targets_sha256": (
            candidate_root / "TARGETS.sha256",
            MAX_MANIFEST_BYTES,
        ),
    }
    for field, (path, maximum_size) in artifacts.items():
        raw = read_safe_bytes(
            path,
            f"Gen5 predecessor {field}",
            allowed_modes={0o600},
            maximum_size=maximum_size,
        )
        if sha256_bytes(raw) != receipt[field]:
            fail(f"Gen5 predecessor candidate artifact differs: {field}")


def validate_previous_release(
    previous_root: Path,
    previous_policy_path: Path,
    current_state_path: Path,
    estate_root: Path,
    current_policy: dict[str, Any],
    current_policy_raw: bytes,
    snapshot_parent: Path,
) -> tuple[dict[str, str], dict[str, Any]]:
    predecessor = current_policy["predecessor"]
    estate = require_root_directory(estate_root, "estate root")
    current_raw = read_safe_bytes(
        current_state_path,
        "Gen5 CURRENT authority",
        allowed_modes={0o600},
        maximum_size=MAX_JSON_BYTES,
    )
    if sha256_bytes(current_raw) != predecessor["current_state_sha256"]:
        fail("Gen5 CURRENT authority differs from policy v5")
    current = load_json_bytes(current_raw, "Gen5 CURRENT authority")
    current = successor_binding.validate_gen5_current(current, estate=estate)
    backup = require_private_directory(
        Path(str(current["backup_dir"])), "Gen5 predecessor backup"
    )
    if backup.parent != Path("/secure/backups") or not backup.name.startswith(
        "holdfast-rikune-"
    ):
        fail("Gen5 predecessor backup is outside the canonical authority")
    successor_binding.validate_gen5_current(current, estate=estate, backup=backup)
    completion = successor_binding.validate_gen5_recovery_completion(
        completion_root=current_state_path.parent,
        predecessor=predecessor,
        state_path=current_state_path,
        state=current,
        state_raw=current_raw,
        estate=estate,
        backup=backup,
    )
    completion_raw: dict[str, bytes] = {}
    for name in ("archive", "receipt", "armed_receipt", "failure_receipt"):
        raw = completion.get(name)
        if not isinstance(raw, bytes):
            fail(f"Gen5 recovery completion snapshot is absent: {name}")
        completion_raw[name] = raw
    canonical_previous_policy = (
        backup / "successor-authority/successor-policy.json"
    )
    if canonical_absolute(
        previous_policy_path, "previous successor policy"
    ) != canonical_previous_policy:
        fail("previous successor policy is not the authenticated backup authority")

    authority_paths = {
        "control": (backup / "CONTROL.sha256", MAX_MANIFEST_BYTES),
        "runtime_manifest": (
            backup / "runtime/SHA256SUMS",
            MAX_MANIFEST_BYTES,
        ),
        "release_evidence": (
            backup / "RELEASE-EVIDENCE.json",
            MAX_JSON_BYTES,
        ),
        "release_env": (backup / "release.env", MAX_ENV_BYTES),
        "supply_evidence": (backup / "SUPPLY-CHAIN.json", MAX_JSON_BYTES),
        "supply_signature": (
            backup / "SUPPLY-CHAIN.sig",
            MAX_SIGNATURE_BYTES,
        ),
        "supply_public_key": (
            backup / "SUPPLY-CHAIN.pub",
            65_536,
        ),
        "previous_policy": (canonical_previous_policy, MAX_JSON_BYTES),
        "dockerfile": (
            backup / "successor-authority/Dockerfile.analyzer",
            32 * 1024 * 1024,
        ),
        "bridge_lock": (
            backup / "successor-authority/bridge-package-lock.json",
            32 * 1024 * 1024,
        ),
    }
    authority_raw = {
        name: read_safe_bytes(
            path,
            f"Gen5 predecessor {name}",
            allowed_modes={0o600},
            maximum_size=maximum_size,
        )
        for name, (path, maximum_size) in authority_paths.items()
    }
    policy_hashes = {
        "control": "control_sha256",
        "runtime_manifest": "runtime_manifest_sha256",
        "release_evidence": "release_evidence_sha256",
    }
    current_hash_fields = {
        "control": "control_sha256",
        "release_evidence": "release_evidence_sha256",
    }
    for name, policy_field in policy_hashes.items():
        observed = sha256_bytes(authority_raw[name])
        if observed != predecessor[policy_field]:
            fail(f"Gen5 predecessor authority differs: {policy_field}")
        current_field = current_hash_fields.get(name)
        if current_field is not None and observed != current[current_field]:
            fail(f"Gen5 CURRENT authority differs: {current_hash_fields[name]}")

    successor_binding.verify_checksum_manifest(
        backup,
        backup / "CONTROL.sha256",
        authority_raw["control"],
    )
    successor_binding.verify_checksum_manifest(
        backup / "runtime",
        backup / "runtime/SHA256SUMS",
        authority_raw["runtime_manifest"],
    )
    control = successor_binding.parse_checksum_manifest_bytes(
        authority_raw["control"], backup / "CONTROL.sha256"
    )
    control_bindings = {
        "RELEASE-EVIDENCE.json": "release_evidence",
        "release.env": "release_env",
        "SUPPLY-CHAIN.json": "supply_evidence",
        "SUPPLY-CHAIN.sig": "supply_signature",
        "SUPPLY-CHAIN.pub": "supply_public_key",
        "successor-authority/successor-policy.json": "previous_policy",
        "successor-authority/Dockerfile.analyzer": "dockerfile",
        "successor-authority/bridge-package-lock.json": "bridge_lock",
    }
    for relative, name in control_bindings.items():
        if control.get(relative) != sha256_bytes(authority_raw[name]):
            fail(f"Gen5 CONTROL does not bind the previous release: {relative}")

    carrier_paths = {
        "release_env": (previous_root / "rikune.release.env", MAX_ENV_BYTES),
        "supply_evidence": (
            previous_root / "SUPPLY-CHAIN.json",
            MAX_JSON_BYTES,
        ),
        "supply_signature": (
            previous_root / "SUPPLY-CHAIN.sig",
            MAX_SIGNATURE_BYTES,
        ),
        "supply_public_key": (
            previous_root / "release-authority.pub",
            65_536,
        ),
    }
    for name, (path, maximum_size) in carrier_paths.items():
        carrier_raw = read_safe_bytes(
            path,
            f"previous release carrier {name}",
            allowed_modes={0o600},
            maximum_size=maximum_size,
        )
        if carrier_raw != authority_raw[name]:
            fail(f"previous release carrier differs from authenticated backup: {name}")

    snapshot_files = {
        "current-policy.json": current_policy_raw,
        "CURRENT.json": current_raw,
        "APPLY-RECOVERY-COMPLETE.json": completion_raw["archive"],
        "APPLY-RECOVERY-COMPLETE.receipt": completion_raw["receipt"],
        "APPLY-RECOVERY-ARMED.receipt": completion_raw["armed_receipt"],
        "APPLY-ACTIVATION-FAILED.receipt": completion_raw["failure_receipt"],
        "CONTROL.sha256": authority_raw["control"],
        "RELEASE-EVIDENCE.json": authority_raw["release_evidence"],
        "rikune.release.env": authority_raw["release_env"],
        "SUPPLY-CHAIN.json": authority_raw["supply_evidence"],
        "SUPPLY-CHAIN.sig": authority_raw["supply_signature"],
        "release-authority.pub": authority_raw["supply_public_key"],
        "previous-successor-policy.json": authority_raw["previous_policy"],
        "Dockerfile.analyzer": authority_raw["dockerfile"],
        "bridge-package-lock.json": authority_raw["bridge_lock"],
    }
    release_keys = set(validator.SUCCESSOR_RELEASE_KEYS)
    previous_release = parse_release_env_bytes(
        authority_raw["release_env"],
        release_keys,
        "previous release env",
    )
    validate_predecessor_release_bindings(previous_release, predecessor)
    previous_document = load_json_bytes(
        authority_raw["supply_evidence"], "previous supply-chain evidence"
    )
    validate_predecessor_candidate_binding(
        previous_root,
        previous_release,
        previous_document,
        predecessor,
    )
    release_evidence = load_json_bytes(
        authority_raw["release_evidence"], "previous RELEASE-EVIDENCE"
    )
    with private_snapshot(snapshot_files, parent=snapshot_parent) as snapshot:
        if validate_policy_v5_snapshot(
            current_policy_raw, snapshot / "current-policy.json"
        ) != current_policy:
            fail("snapshot policy v5 differs from predecessor authority")
        previous_policy = validator.validate_successor_policy(
            snapshot / "previous-successor-policy.json"
        )
        release_validator.validate_evidence(
            release_evidence,
            snapshot / "previous-successor-policy.json",
        )
        validator.validate_document(
            previous_document,
            previous_release,
            sha256_bytes(authority_raw["release_env"]),
            previous_policy,
        )
        command = [
            sys.executable,
            str(PRODUCTION_VALIDATOR),
            "--release-env",
            str(snapshot / "rikune.release.env"),
            "--evidence",
            str(snapshot / "SUPPLY-CHAIN.json"),
            "--signature",
            str(snapshot / "SUPPLY-CHAIN.sig"),
            "--public-key",
            str(snapshot / "release-authority.pub"),
            "--dockerfile",
            str(snapshot / "Dockerfile.analyzer"),
            "--bridge-lock",
            str(snapshot / "bridge-package-lock.json"),
            "--release-evidence",
            str(snapshot / "RELEASE-EVIDENCE.json"),
            "--successor-policy",
            str(snapshot / "previous-successor-policy.json"),
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=OFFLINE_ENV,
        )
        if completed.returncode != 0:
            fail("previous release failed exact signed production validation")
    return previous_release, previous_document


def waiver_still_needed(waiver: dict[str, Any], record: dict[str, Any]) -> bool:
    if waiver.get("missing_field") == "provenance":
        return record.get("provenance") is None
    if waiver.get("missing_field") == "provenance.builder_id":
        provenance = record.get("provenance")
        return isinstance(provenance, dict) and provenance.get("builder_id") in (
            None,
            "",
        )
    return False


def assemble_release(
    previous_release: dict[str, str],
    previous_document: dict[str, Any],
    policy: dict[str, Any],
    records: dict[str, dict[str, Any]],
    access_receipt: dict[str, str],
    access_receipt_sha256: str,
    release_manifest_sha256: str,
    source_revision: str,
    issued_at_text: str,
    release_tool_revision: str,
    supply_public_key_sha256: str,
    verifier_identity: str,
    dockerfile: Path = DEFAULT_DOCKERFILE,
    bridge_lock: Path = DEFAULT_BRIDGE_LOCK,
) -> tuple[dict[str, str], dict[str, Any]]:
    issued_at = parse_timestamp(issued_at_text, "issued_at")
    require_hex40(source_revision, "Strad source revision")
    require_hex40(release_tool_revision, "release-tool revision")
    require_hex64(access_receipt_sha256, "Access candidate receipt")
    require_hex64(release_manifest_sha256, "Strad release manifest")
    require_hex64(supply_public_key_sha256, "supply-chain public key")
    if source_revision != release_tool_revision:
        fail("Strad source revision and Holdfast release-tool revision must match")
    if set(records) != FRESH_IMAGE_KEYS:
        fail("fresh registry record set is not exact")
    for image_key, record in records.items():
        if set(record) != IMAGE_RECORD_FIELDS:
            fail(f"fresh {image_key} registry record field set is not exact")
        if record["image"] == previous_release[image_key]:
            fail(f"fresh {image_key} does not advance its predecessor image")

    release_keys = set(validator.SUCCESSOR_RELEASE_KEYS)
    if set(previous_release) != release_keys:
        fail("previous release env field set differs from production")
    previous_registry = exact_object(
        previous_document.get("registry_verification"),
        {"verified_at", "verifier", "images"},
        "previous registry verification",
    )
    previous_images = exact_object(
        previous_registry["images"],
        set(validator.IMAGE_KEYS),
        "previous registry images",
    )
    for image_key in validator.IMAGE_KEYS:
        if previous_images[image_key].get("image") != previous_release[image_key]:
            fail(f"previous registry record differs from its pin: {image_key}")

    release = dict(previous_release)
    release.update(
        {
            "ACCESS_GOVERNANCE_IMAGE": records["ACCESS_GOVERNANCE_IMAGE"]["image"],
            "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": previous_release[
                "ACCESS_GOVERNANCE_IMAGE"
            ],
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": GEN6_ACCESS_BUILD_INPUT_SHA256,
            "STRAD_IMAGE": records["STRAD_IMAGE"]["image"],
            "STRAD_ANALYZER_IMAGE": records["STRAD_ANALYZER_IMAGE"]["image"],
            "STRAD_REVISION": source_revision,
            "HOLDFAST_RELEASE_TOOL_REVISION": release_tool_revision,
            "SUPPLY_CHAIN_PUBLIC_KEY_SHA256": supply_public_key_sha256,
            "SUPPLY_CHAIN_EVIDENCE_SHA256": "0" * 64,
            "SUPPLY_CHAIN_SIGNATURE_SHA256": UNSIGNED_SIGNATURE_PLACEHOLDER,
        }
    )
    predecessor = policy["predecessor"]
    access_provenance = records["ACCESS_GOVERNANCE_IMAGE"].get("provenance")
    if (
        predecessor["access_image"] != previous_release["ACCESS_GOVERNANCE_IMAGE"]
        or access_receipt["image"] != release["ACCESS_GOVERNANCE_IMAGE"]
        or access_receipt["build_input_sha256"] != GEN6_ACCESS_BUILD_INPUT_SHA256
        or access_receipt["holdfast_release_tool_revision"] != release_tool_revision
        or not isinstance(access_provenance, dict)
        or access_provenance.get("builder_id")
        != access_receipt["provenance_builder_id"]
    ):
        fail("fresh Access image, receipt, or predecessor binding differs")
    release["PERMISSION_CATALOG_SHA256"] = predecessor[
        "permission_catalog_sha256"
    ]
    release["PACKAGE_CATALOG_SHA256"] = predecessor["package_catalog_sha256"]
    if set(release) != release_keys:
        fail("assembled release field set differs from production")

    selected_records: dict[str, Any] = {}
    for image_key in validator.IMAGE_KEYS:
        if image_key in FRESH_IMAGE_KEYS:
            selected_records[image_key] = copy.deepcopy(records[image_key])
        elif image_key == "ACCESS_GOVERNANCE_ROLLBACK_IMAGE":
            selected_records[image_key] = copy.deepcopy(
                previous_images["ACCESS_GOVERNANCE_IMAGE"]
            )
        else:
            if release[image_key] != previous_release[image_key]:
                fail(f"carry-forward image pin drifted: {image_key}")
            selected_records[image_key] = copy.deepcopy(previous_images[image_key])
    if (
        selected_records["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]["image"]
        != release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]
    ):
        fail("Access rollback registry record is not the predecessor candidate")

    previous_waivers = previous_document.get("waivers")
    if not isinstance(previous_waivers, list):
        fail("previous supply-chain waiver array is absent")
    waivers: list[dict[str, Any]] = []
    for raw in previous_waivers:
        if not isinstance(raw, dict):
            fail("previous waiver is not an object")
        image_key = raw.get("image_key")
        if image_key in FRESH_IMAGE_KEYS | {"ACCESS_GOVERNANCE_ROLLBACK_IMAGE"}:
            continue
        if (
            isinstance(image_key, str)
            and image_key in selected_records
            and raw.get("image") == release[image_key]
            and waiver_still_needed(raw, selected_records[image_key])
        ):
            waivers.append(copy.deepcopy(raw))
    if len(validator.validate_waivers(waivers, release, issued_at, 5)) != len(waivers):
        fail("carried waiver set differs from production validation")

    dockerfile_raw = read_safe_bytes(
        dockerfile,
        "Dockerfile.analyzer",
        allowed_modes={0o644},
        maximum_size=MAX_JSON_BYTES,
    )
    bridge_lock_raw = read_safe_bytes(
        bridge_lock,
        "analyzer bridge lock",
        allowed_modes={0o644},
        maximum_size=MAX_JSON_BYTES,
    )
    overlay = {
        "base_image": release["RIKUNE_ANALYZER_IMAGE"],
        "overlay_image": release["STRAD_ANALYZER_IMAGE"],
        "dockerfile_sha256": sha256_bytes(dockerfile_raw),
        "bridge_lock_sha256": sha256_bytes(bridge_lock_raw),
        "static_lock_sha256": STATIC_LOCK_SHA256,
        "source_revision": source_revision,
    }
    access_candidate = {
        "image": release["ACCESS_GOVERNANCE_IMAGE"],
        "build_input_schema": "access-build-input/2",
        "build_input_sha256": GEN6_ACCESS_BUILD_INPUT_SHA256,
        "permission_catalog_sha256": release["PERMISSION_CATALOG_SHA256"],
        "package_catalog_sha256": release["PACKAGE_CATALOG_SHA256"],
        "tool_revision": release_tool_revision,
    }
    fresh_bindings = {
        "ACCESS_GOVERNANCE_IMAGE": {
            "record_sha256": validator.canonical_object_sha256(
                selected_records["ACCESS_GOVERNANCE_IMAGE"]
            ),
            "build_input_sha256": GEN6_ACCESS_BUILD_INPUT_SHA256,
            "candidate_receipt_sha256": access_receipt_sha256,
        },
        "STRAD_IMAGE": {
            "record_sha256": validator.canonical_object_sha256(
                selected_records["STRAD_IMAGE"]
            ),
            "source_revision": source_revision,
            "release_manifest_sha256": release_manifest_sha256,
        },
        "STRAD_ANALYZER_IMAGE": {
            "record_sha256": validator.canonical_object_sha256(
                selected_records["STRAD_ANALYZER_IMAGE"]
            ),
            "source_revision": source_revision,
            "release_manifest_sha256": release_manifest_sha256,
        },
    }
    document = {
        "schema_version": 5,
        "issued_at": issued_at_text,
        "platform": "linux/amd64",
        "release_pins_sha256": validator.release_pins_sha256(release),
        "registry_verification": {
            "verified_at": issued_at_text,
            "verifier": verifier_identity,
            "images": selected_records,
        },
        "waivers": waivers,
        "analyzer_overlay": overlay,
        "access_candidate": access_candidate,
        "successor_binding": copy.deepcopy(predecessor),
        "fresh_image_bindings": fresh_bindings,
        "predecessor_current_sha256": predecessor["current_state_sha256"],
        "predecessor_recovery_completion": copy.deepcopy(
            predecessor["recovery_completion"]
        ),
        "predecessor_release_generation": 5,
        "release_generation": 6,
    }
    validator.validate_document(document, release, "0" * 64, policy)
    return release, document


def validate_output_path(path: Path, release_root: Path, label: str) -> Path:
    destination = canonical_absolute(path, label)
    if destination.parent != release_root:
        fail(f"{label} must be a direct child of --release-root")
    try:
        os.lstat(destination)
    except FileNotFoundError:
        return destination
    fail(f"{label} must be a NEW_FILE")


def write_new_files(release_root: Path, values: dict[Path, bytes]) -> None:
    directory = os.open(
        release_root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    temporaries: dict[Path, str] = {}
    linked: list[str] = []
    try:
        for destination, content in values.items():
            temporary = f".{destination.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
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
            temporaries[destination] = temporary
        for destination, temporary in temporaries.items():
            os.link(
                temporary,
                destination.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            linked.append(destination.name)
        for temporary in temporaries.values():
            os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        for name in linked:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        for temporary in temporaries.values():
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.fsync(directory)
        raise
    finally:
        os.close(directory)


def build_evidence(args: argparse.Namespace) -> int:
    previous_root = require_private_directory(
        args.previous_release_root, "previous release root"
    )
    release_root = require_private_directory(args.release_root, "release root")
    candidate_root = require_private_directory(args.candidate_root, "candidate root")
    output_env = validate_output_path(
        args.output_release_env, release_root, "unsigned release env output"
    )
    output_evidence = validate_output_path(
        args.output_evidence, release_root, "supply-chain evidence output"
    )
    if output_env == output_evidence or not output_env.name.endswith(".unsigned"):
        fail("build-evidence output env must be a distinct *.unsigned NEW_FILE")
    source_revision = require_hex40(args.strad_revision, "Strad revision")
    release_tool_revision = require_hex40(
        args.release_tool_revision, "release-tool revision"
    )
    if source_revision != release_tool_revision:
        fail("Strad and release-tool revisions must be the same Gen6 commit")
    validate_checkout_revision(release_tool_revision)
    issued_at = parse_timestamp(args.issued_at, "issued_at")
    policy_raw = read_safe_bytes(args.successor_policy, "successor policy")
    with private_snapshot(
        {"successor-policy.json": policy_raw}, parent=release_root
    ) as policy_snapshot:
        policy = validate_policy_v5_snapshot(
            policy_raw, policy_snapshot / "successor-policy.json"
        )
        previous_release, previous_document = validate_previous_release(
            previous_root,
            args.previous_successor_policy,
            args.current_state,
            args.estate_root,
            policy,
            policy_raw,
            release_root,
        )
        access_receipt, access_receipt_sha, access_artifacts = (
            validate_access_candidate(
                release_root,
                candidate_root,
                policy,
                policy_snapshot / "successor-policy.json",
                sha256_bytes(policy_raw),
                release_tool_revision,
            )
        )
    trusted_root = read_safe_bytes(
        args.sigstore_trusted_root,
        "Sigstore trusted root",
        maximum_size=MAX_JSON_BYTES,
    )
    if sha256_bytes(trusted_root) != SIGSTORE_TRUSTED_ROOT_SHA256:
        fail("Sigstore trusted root differs from the frozen Gen6 authority")
    load_json_bytes(trusted_root, "Sigstore trusted root")
    access_public_key = read_safe_bytes(
        args.access_cosign_public_key,
        "Access Cosign public key",
        maximum_size=65_536,
    )
    validate_access_builder_key_binding(
        access_receipt["provenance_builder_id"], access_public_key
    )
    supply_public_key = read_safe_bytes(
        args.supply_chain_public_key,
        "supply-chain public key",
        maximum_size=65_536,
    )

    manifest_value, _ = load_json(args.strad_release_manifest, "Strad release manifest")
    manifest_images = manifest_value.get("images")
    if not isinstance(manifest_images, dict):
        fail("Strad release manifest image set is absent")
    provisional_release = dict(previous_release)
    provisional_release.update(
        {
            "ACCESS_GOVERNANCE_IMAGE": access_receipt["image"],
            "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": previous_release[
                "ACCESS_GOVERNANCE_IMAGE"
            ],
            "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": GEN6_ACCESS_BUILD_INPUT_SHA256,
            "STRAD_IMAGE": require_image(
                manifest_images.get("STRAD_IMAGE"), "release manifest STRAD_IMAGE"
            ),
            "STRAD_ANALYZER_IMAGE": require_image(
                manifest_images.get("STRAD_ANALYZER_IMAGE"),
                "release manifest STRAD_ANALYZER_IMAGE",
            ),
            "STRAD_REVISION": source_revision,
            "HOLDFAST_RELEASE_TOOL_REVISION": release_tool_revision,
        }
    )
    records = {
        "ACCESS_GOVERNANCE_IMAGE": validate_oci_layout(
            args.access_oci_layout,
            "ACCESS_GOVERNANCE_IMAGE",
            provisional_release["ACCESS_GOVERNANCE_IMAGE"],
            provisional_release,
            issued_at,
            trusted_root,
            source_revision=None,
            public_key=access_public_key,
            access_artifacts=access_artifacts,
        ),
        "STRAD_IMAGE": validate_oci_layout(
            args.strad_oci_layout,
            "STRAD_IMAGE",
            provisional_release["STRAD_IMAGE"],
            provisional_release,
            issued_at,
            trusted_root,
            source_revision=source_revision,
            public_key=None,
        ),
        "STRAD_ANALYZER_IMAGE": validate_oci_layout(
            args.strad_analyzer_oci_layout,
            "STRAD_ANALYZER_IMAGE",
            provisional_release["STRAD_ANALYZER_IMAGE"],
            provisional_release,
            issued_at,
            trusted_root,
            source_revision=source_revision,
            public_key=None,
        ),
    }
    release_manifest_sha = verify_release_manifest(
        args.strad_release_manifest,
        args.strad_release_bundle,
        trusted_root,
        provisional_release,
        source_revision,
        issued_at,
    )
    verifier_identity = (
        "cosign-offline-oci-layout/v1;"
        f"image={COSIGN_VERIFIER_IMAGE};"
        f"trusted_root_sha256={sha256_bytes(trusted_root)};"
        f"strad_release_manifest_sha256={release_manifest_sha}"
    )
    release, document = assemble_release(
        previous_release,
        previous_document,
        policy,
        records,
        access_receipt,
        access_receipt_sha,
        release_manifest_sha,
        source_revision,
        args.issued_at,
        release_tool_revision,
        sha256_bytes(supply_public_key),
        verifier_identity,
        args.dockerfile,
        args.bridge_lock,
    )
    validator.validate_local_binding(
        document,
        SimpleNamespace(
            dockerfile=args.dockerfile,
            bridge_lock=args.bridge_lock,
            release_evidence=None,
        ),
        release,
        "0" * 64,
    )
    evidence_raw = json_bytes(document)
    release["SUPPLY_CHAIN_EVIDENCE_SHA256"] = sha256_bytes(evidence_raw)
    if document["release_pins_sha256"] != validator.release_pins_sha256(release):
        fail("release pin hash changed after binding the evidence digest")
    write_new_files(
        release_root,
        {
            output_evidence: evidence_raw,
            output_env: unsigned_env_bytes(
                release, set(validator.SUCCESSOR_RELEASE_KEYS)
            ),
        },
    )
    print("schema-v5 evidence and unsigned release env assembled offline")
    return 0


def require_final_release_env(release: dict[str, str]) -> None:
    expected_keys = set(validator.SUCCESSOR_RELEASE_KEYS)
    if set(release) != expected_keys:
        fail("final release env field set is not exact")
    if release.get("SUPPLY_CHAIN_SIGNATURE_SHA256") == UNSIGNED_SIGNATURE_PLACEHOLDER:
        fail("final release env retains the unsigned signature placeholder")
    for key, value in release.items():
        if key.endswith("_SHA256"):
            require_hex64(value, f"final release env {key}")


def finalize_env(args: argparse.Namespace) -> int:
    release_root = require_private_directory(args.release_root, "release root")
    destination = validate_output_path(
        args.output_release_env, release_root, "final release env output"
    )
    if destination.name != "rikune.release.env":
        fail("final release env must be named rikune.release.env")
    release_keys = set(validator.SUCCESSOR_RELEASE_KEYS)
    unsigned_raw = read_safe_bytes(
        args.unsigned_release_env,
        "unsigned release env",
        allowed_modes={0o600},
        maximum_size=MAX_ENV_BYTES,
    )
    release = parse_release_env_bytes(
        unsigned_raw, release_keys, "unsigned release env"
    )
    if release["SUPPLY_CHAIN_SIGNATURE_SHA256"] != UNSIGNED_SIGNATURE_PLACEHOLDER:
        fail("unsigned release env has an unexpected signature placeholder")
    validate_checkout_revision(release["HOLDFAST_RELEASE_TOOL_REVISION"])
    evidence_raw = read_safe_bytes(
        args.evidence,
        "supply-chain evidence",
        allowed_modes={0o600},
        maximum_size=MAX_JSON_BYTES,
    )
    if release["SUPPLY_CHAIN_EVIDENCE_SHA256"] != sha256_bytes(evidence_raw):
        fail("supply-chain evidence differs from the unsigned release env")
    evidence = load_json_bytes(evidence_raw, "supply-chain evidence")
    if evidence.get("schema_version") != 5:
        fail("finalize-env only accepts schema-v5 evidence")
    signature_raw = read_safe_bytes(
        args.signature,
        "supply-chain signature",
        maximum_size=MAX_SIGNATURE_BYTES,
    )
    public_key_raw = read_safe_bytes(
        args.public_key,
        "supply-chain public key",
        maximum_size=65_536,
    )
    if release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"] != sha256_bytes(public_key_raw):
        fail("supply-chain public key differs from the release pin")
    policy_raw = read_safe_bytes(args.successor_policy, "successor policy")
    dockerfile_raw = read_safe_bytes(
        args.dockerfile,
        "Dockerfile.analyzer",
        maximum_size=32 * 1024 * 1024,
    )
    bridge_lock_raw = read_safe_bytes(
        args.bridge_lock,
        "bridge package lock",
        maximum_size=32 * 1024 * 1024,
    )
    signature_sha = sha256_bytes(signature_raw)
    if signature_sha == UNSIGNED_SIGNATURE_PLACEHOLDER:
        fail("detached signature digest equals the unsigned placeholder")
    release["SUPPLY_CHAIN_SIGNATURE_SHA256"] = signature_sha
    require_final_release_env(release)
    final_raw = canonical_env_bytes(release, release_keys)
    snapshot_files = {
        "rikune.release.env": final_raw,
        "SUPPLY-CHAIN.json": evidence_raw,
        "SUPPLY-CHAIN.sig": signature_raw,
        "release-authority.pub": public_key_raw,
        "successor-policy.json": policy_raw,
        "Dockerfile.analyzer": dockerfile_raw,
        "bridge-package-lock.json": bridge_lock_raw,
    }
    with private_snapshot(snapshot_files, parent=release_root) as snapshot:
        validate_policy_v5_snapshot(
            policy_raw, snapshot / "successor-policy.json"
        )
        command = [
            sys.executable,
            str(PRODUCTION_VALIDATOR),
            "--release-env",
            str(snapshot / "rikune.release.env"),
            "--evidence",
            str(snapshot / "SUPPLY-CHAIN.json"),
            "--signature",
            str(snapshot / "SUPPLY-CHAIN.sig"),
            "--public-key",
            str(snapshot / "release-authority.pub"),
            "--dockerfile",
            str(snapshot / "Dockerfile.analyzer"),
            "--bridge-lock",
            str(snapshot / "bridge-package-lock.json"),
            "--successor-policy",
            str(snapshot / "successor-policy.json"),
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=OFFLINE_ENV,
        )
        if completed.returncode != 0:
            fail("final env failed detached signature or production schema-v5 validation")
    final_inputs = (
        (
            args.unsigned_release_env,
            unsigned_raw,
            "unsigned release env",
            {0o600},
            MAX_ENV_BYTES,
        ),
        (
            args.evidence,
            evidence_raw,
            "supply-chain evidence",
            {0o600},
            MAX_JSON_BYTES,
        ),
        (
            args.signature,
            signature_raw,
            "supply-chain signature",
            {0o600, 0o644},
            MAX_SIGNATURE_BYTES,
        ),
        (
            args.public_key,
            public_key_raw,
            "supply-chain public key",
            {0o600, 0o644},
            65_536,
        ),
        (
            args.successor_policy,
            policy_raw,
            "successor policy",
            {0o600, 0o644},
            MAX_JSON_BYTES,
        ),
        (
            args.dockerfile,
            dockerfile_raw,
            "Dockerfile.analyzer",
            {0o600, 0o644},
            32 * 1024 * 1024,
        ),
        (
            args.bridge_lock,
            bridge_lock_raw,
            "bridge package lock",
            {0o600, 0o644},
            32 * 1024 * 1024,
        ),
    )
    for path, expected_raw, label, modes, maximum_size in final_inputs:
        observed_raw = read_safe_bytes(
            path,
            f"post-validation {label}",
            allowed_modes=modes,
            maximum_size=maximum_size,
        )
        if observed_raw != expected_raw:
            fail(f"{label} changed after snapshot validation")
    write_new_files(release_root, {destination: final_raw})
    print("final release env written after production detached-signature validation")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Offline fail-closed Holdfast schema-v5 supply-chain assembler"
    )
    commands = result.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-evidence")
    build.add_argument("--previous-release-root", required=True, type=Path)
    build.add_argument("--previous-successor-policy", required=True, type=Path)
    build.add_argument("--current-state", required=True, type=Path)
    build.add_argument("--estate-root", required=True, type=Path)
    build.add_argument("--release-root", required=True, type=Path)
    build.add_argument("--candidate-root", required=True, type=Path)
    build.add_argument("--successor-policy", required=True, type=Path)
    build.add_argument("--strad-revision", required=True)
    build.add_argument("--release-tool-revision", required=True)
    build.add_argument("--issued-at", required=True)
    build.add_argument("--access-oci-layout", required=True, type=Path)
    build.add_argument("--strad-oci-layout", required=True, type=Path)
    build.add_argument("--strad-analyzer-oci-layout", required=True, type=Path)
    build.add_argument("--strad-release-manifest", required=True, type=Path)
    build.add_argument("--strad-release-bundle", required=True, type=Path)
    build.add_argument("--access-cosign-public-key", required=True, type=Path)
    build.add_argument("--sigstore-trusted-root", required=True, type=Path)
    build.add_argument("--supply-chain-public-key", required=True, type=Path)
    build.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    build.add_argument("--bridge-lock", type=Path, default=DEFAULT_BRIDGE_LOCK)
    build.add_argument("--output-release-env", required=True, type=Path)
    build.add_argument("--output-evidence", required=True, type=Path)
    build.set_defaults(handler=build_evidence)

    finalize = commands.add_parser("finalize-env")
    finalize.add_argument("--release-root", required=True, type=Path)
    finalize.add_argument("--unsigned-release-env", required=True, type=Path)
    finalize.add_argument("--evidence", required=True, type=Path)
    finalize.add_argument("--signature", required=True, type=Path)
    finalize.add_argument("--public-key", required=True, type=Path)
    finalize.add_argument("--successor-policy", required=True, type=Path)
    finalize.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    finalize.add_argument("--bridge-lock", type=Path, default=DEFAULT_BRIDGE_LOCK)
    finalize.add_argument("--output-release-env", required=True, type=Path)
    finalize.set_defaults(handler=finalize_env)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.handler(args))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"schema-v5 supply-chain assembler: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
