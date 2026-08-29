#!/usr/bin/env python3
"""Bind render-time Holdfast authority inputs and verify them again at apply."""

from __future__ import annotations

import argparse
import fcntl
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
    verify_raw_bundle,
)

LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
STATIC_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
ACCESS_BUILD_INPUT_SCHEMA_V1 = "access-build-input/1"
ACCESS_BUILD_INPUT_SCHEMA_V2 = "access-build-input/2"
MAX_SUCCESSOR_OVERLAY_PATHS = 64
SUCCESSOR_POLICY_CEREMONIES = {
    1: "holdfast-rikune-successor-v1",
    2: "holdfast-rikune-successor-v2",
    3: "holdfast-rikune-successor-v3",
}
SECURE_DESCRIPTOR_TRAVERSAL_SUPPORTED = (
    all(
        hasattr(os, name)
        for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    )
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.listdir in os.supports_fd
)
SECURE_FILE_LEASES_SUPPORTED = all(
    hasattr(fcntl, name)
    for name in ("F_GETLEASE", "F_SETLEASE", "F_RDLCK")
)
BOUND_INPUTS = (
    "static-targets.sha256",
    "frozen-targets.json",
    "preimages.sha256",
    "absent.paths",
)
SUCCESSOR_BOUND_INPUTS = (
    "successor-static-targets.sha256",
    "successor-frozen-targets.json",
    "successor-preimages.sha256",
    "successor-absent.paths",
    "successor-supporting-targets.sha256",
    "successor-policy.json",
)
FROZEN_STATIC_PATHS = (
    "access-governance/catalog/cistern-authz-v1.json",
    "access-governance/catalog/rikune-authz-v1.json",
    "access-governance/catalog/permission.sources.v1.json",
    "access-governance/catalog/permissions.snapshot.json",
    "access-governance/catalog/packages.snapshot.json",
    "access-governance/scripts/generate_permission_catalog.sh",
    "access-governance/scripts/validate_authz_manifests.py",
    "access-governance/src/catalog.rs",
    "access-governance/src/package_catalog.rs",
    "access-governance/src/repository/postgres.rs",
    "access-governance/src/handlers/ui.rs",
    "deploy/routes.seed.json",
    "deploy/docker-compose.yml",
    "deploy/access-governance.env.example",
)
CATALOG_STATIC_PATHS = tuple(
    relative
    for relative in FROZEN_STATIC_PATHS
    if relative
    not in {
        "deploy/docker-compose.yml",
        "deploy/access-governance.env.example",
    }
)
FROZEN_FIELDS = (
    "permission_catalog_sha256",
    "package_catalog_sha256",
    "access_governance_build_input_sha256",
    "route_up_sha256",
    "route_down_sha256",
    "authz_manifest_sha256",
)
STAGE_SEMANTIC_PATHS = {
    "permission_catalog_sha256": "access-governance/catalog/permissions.snapshot.json",
    "package_catalog_sha256": "access-governance/catalog/packages.snapshot.json",
    "authz_manifest_sha256": "access-governance/catalog/rikune-authz-v1.json",
}
ROUTE_ASSET_PATHS = {
    "route_up_sha256": "assets/20260823_rikune_root_up.sql",
    "route_down_sha256": "assets/20260823_rikune_root_down.sql",
}
BASE_FULL_EVIDENCE_FIELDS = {
    "schema_version",
    "generator",
    "catalog_only",
    *FROZEN_FIELDS,
    "secret_references",
    "release",
    "release_env_sha256",
    "supply_chain_binding",
    "analyzer_image_binding",
}
SUCCESSOR_EVIDENCE_FIELDS = BASE_FULL_EVIDENCE_FIELDS | {
    "release_mode",
    "access_governance_build_input_schema",
    "holdfast_release_tool_revision",
    "predecessor_binding",
    "successor_delta_sha256",
}
SUCCESSOR_CATALOG_EVIDENCE_FIELDS = SUCCESSOR_EVIDENCE_FIELDS - {
    "release_env_sha256",
    "supply_chain_binding",
    "analyzer_image_binding",
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
RECOVERY_COMPLETION_FIELDS = {
    "kind",
    "attestation_sha256",
    "signature_sha256",
    "public_key_sha256",
}
RECOVERED_PREDECESSOR_FIELDS = (
    LEGACY_PREDECESSOR_FIELDS - {"apply_receipt_sha256"}
) | {"completion"}
# Compatibility alias for callers that bind the current v1/v2 schema exactly.
PREDECESSOR_FIELDS = LEGACY_PREDECESSOR_FIELDS
RECOVERY_COMPLETION_NAMES = {
    RECOVERY_ATTESTATION_NAME,
    RECOVERY_SIGNATURE_NAME,
    RECOVERY_PUBLIC_KEY_NAME,
}
SUCCESSOR_POLICY_FIELDS = {
    "generator",
    "access_build_input_schema",
    "source_access_build_input_sha256",
    "access_build_input_sha256",
    "preimages_manifest",
    "absent_manifest",
    "static_targets_manifest",
    "supporting_targets_manifest",
    "frozen_targets_manifest",
}
FROZEN_ROOT_FIELDS = {
    "schema_version",
    "generator",
    "release_epoch",
    *FROZEN_FIELDS,
    "tokenizer",
    "required_unresolved_inputs",
}
SUCCESSOR_UNRESOLVED_INPUTS = (
    "ACCESS_GOVERNANCE_IMAGE",
    "ACCESS_GOVERNANCE_ROLLBACK_IMAGE",
    "RIKUNE_ANALYZER_IMAGE",
    "STRAD_ANALYZER_IMAGE",
    "STRAD_IMAGE",
    "STRAD_VOLUME_INIT_IMAGE",
    "STRAD_REVISION",
    "HOLDFAST_RELEASE_TOOL_REVISION",
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
    "STRAD_DATABASE_URL",
    "STRAD_BRIDGE_TOKEN",
    "RIKUNE_FILE_SERVER_API_KEY",
    "STRAD_NEWAPI_KEY",
)


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def validate_completion_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECOVERY_COMPLETION_FIELDS:
        fail("recovery completion binding field set differs")
    if value.get("kind") != RECOVERY_COMPLETION_KIND:
        fail("recovery completion kind differs")
    for field in (
        "attestation_sha256",
        "signature_sha256",
        "public_key_sha256",
    ):
        raw = value.get(field)
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-f]{64}", raw):
            fail(f"recovery completion checksum is invalid: {field}")
    return value


def validate_adjacent_recovery_completion(
    stage_root: Path,
    predecessor: dict[str, Any],
    policy_version: int,
    source_estate_root: Path | None,
    require_root_owner: bool,
) -> None:
    if policy_version < 3:
        present = set(os.listdir(stage_root)) & RECOVERY_COMPLETION_NAMES
        if present:
            fail("legacy successor stage contains recovery completion authority")
        return
    directory = open_private_directory(stage_root)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
            fail("successor stage must have mode 0700")
        names = set(os.listdir(directory))
        present = names & RECOVERY_COMPLETION_NAMES
        if present != RECOVERY_COMPLETION_NAMES:
            fail("schema 3 successor stage lacks the exact recovery completion trio")
        completion = validate_completion_binding(predecessor.get("completion"))
        attestation = read_direct_child(
            directory, RECOVERY_ATTESTATION_NAME, "staged recovery attestation"
        )
        signature = read_direct_child(
            directory,
            RECOVERY_SIGNATURE_NAME,
            "staged recovery signature",
            maximum_size=65_536,
        )
        public_key = read_direct_child(
            directory,
            RECOVERY_PUBLIC_KEY_NAME,
            "staged recovery public key",
            maximum_size=65_536,
        )
    finally:
        os.close(directory)
    observed = recovery_artifact_result(attestation, signature, public_key)
    for field in (
        "attestation_sha256",
        "signature_sha256",
        "public_key_sha256",
    ):
        if observed[field] != completion[field]:
            fail(f"staged recovery completion differs: {field}")
    document = verify_raw_bundle(
        attestation, signature, public_key, completion["public_key_sha256"]
    )
    expected = {
        "current_sha256": predecessor.get("current_state_sha256"),
        "control_sha256": predecessor.get("control_sha256"),
        "release_evidence_sha256": predecessor.get("release_evidence_sha256"),
        "runtime_manifest_sha256": predecessor.get("runtime_manifest_sha256"),
        "predecessor_release_generation": 2,
        "release_generation": 3,
    }
    for field, wanted in expected.items():
        if document.get(field) != wanted:
            fail(f"staged recovery completion predecessor differs: {field}")
    if source_estate_root is not None and document.get("estate_root") != str(
        source_estate_root.absolute()
    ):
        fail("staged recovery completion estate root differs")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def require_regular(path: Path, require_root_owner: bool = False) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"required binding input is absent: {path}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
    ):
        fail(f"binding input must be a single-link regular file: {path}")
    if require_root_owner and metadata.st_uid != 0:
        fail(f"binding input must be root-owned: {path}")


def require_directory(path: Path, require_root_owner: bool = False) -> Path:
    if not path.is_absolute() or path == Path("/"):
        fail(f"unsafe binding root: {path}")
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or path.resolve() != path
    ):
        fail(f"unsafe binding root directory: {path}")
    if require_root_owner and metadata.st_uid != 0:
        fail(f"binding root directory must be root-owned: {path}")
    return path


def rooted_regular(root: Path, relative: str, require_root_owner: bool = False) -> Path:
    path = root / relative
    require_regular(path, require_root_owner)
    if path.resolve() != path or (
        path.parent != root and root not in path.parent.resolve().parents
    ):
        fail(f"binding path escapes its root: {relative}")
    return path


def parse_manifest(path: Path, require_root_owner: bool = False) -> dict[str, str]:
    require_regular(path, require_root_owner)
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = LINE.fullmatch(line)
        if not match or match.group(2) in values:
            fail(f"invalid or duplicate render-input binding line {line_number}")
        values[match.group(2)] = match.group(1)
    if tuple(values) not in (BOUND_INPUTS, SUCCESSOR_BOUND_INPUTS):
        fail("render-input binding field set or order differs from the contract")
    return values


def parse_static_manifest(
    path: Path, require_root_owner: bool = False
) -> dict[str, str]:
    require_regular(path, require_root_owner)
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = STATIC_LINE.fullmatch(line)
        if (
            not match
            or match.group(2).startswith("/")
            or ".." in Path(match.group(2)).parts
            or match.group(2) in values
        ):
            fail(f"invalid or duplicate static-target line {line_number}")
        values[match.group(2)] = match.group(1)
    if tuple(values) != FROZEN_STATIC_PATHS:
        fail("static-target field set or order differs from the apply contract")
    return values


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_object(path: Path, require_root_owner: bool = False) -> dict[str, object]:
    require_regular(path, require_root_owner)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except json.JSONDecodeError as error:
        fail(f"malformed binding JSON: {path}: {error}")
    if not isinstance(value, dict):
        fail(f"binding JSON root is not an object: {path}")
    return value


def access_build_input_sha(
    stage_root: Path, require_root_owner: bool = False
) -> str:
    base = require_directory(stage_root / "access-governance", require_root_owner)
    value = hashlib.sha256()
    files: list[Path] = []
    for current_root, directories, names in os.walk(base, followlinks=False):
        current = Path(current_root)
        for name in [*directories, *names]:
            candidate = current / name
            if candidate.is_symlink():
                fail(f"Access build input contains a symlink: {candidate}")
        directories[:] = sorted(
            name for name in directories if name not in {".git", "target", "__pycache__"}
        )
        for name in sorted(names):
            path = current / name
            if name.endswith(".pyc"):
                continue
            require_regular(path, require_root_owner)
            files.append(path)
    for path in sorted(files, key=lambda item: item.relative_to(base).as_posix()):
        relative = path.relative_to(base).as_posix()
        value.update(relative.encode("utf-8"))
        value.update(b"\0")
        value.update(digest(path).encode("ascii"))
        value.update(b"\n")
    return value.hexdigest()


def stable_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def stable_stat_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *stable_stat_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def require_stable_directory(
    metadata: os.stat_result,
    label: str,
    require_root_owner: bool,
    allow_shared_ancestor: bool = False,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"Access build input directory is not stable: {label}")
    permissions = stat.S_IMODE(metadata.st_mode)
    shared_ancestor = (
        allow_shared_ancestor
        and metadata.st_uid == 0
        and bool(permissions & stat.S_ISVTX)
    )
    if require_root_owner and (
        metadata.st_uid != 0
        or (permissions & 0o022 and not shared_ancestor)
    ):
        fail(
            "Access build input directory must be root-owned and not "
            f"group/world-writable: {label}"
        )


def require_stable_file(
    metadata: os.stat_result, label: str, require_root_owner: bool
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"Access build input must be a single-link regular file: {label}")
    if require_root_owner and (
        metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail(
            "Access build input file must be root-owned and not "
            f"group/world-writable: {label}"
        )


def secure_open_flags(directory: bool) -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    if directory:
        required += ("O_DIRECTORY",)
    else:
        required += ("O_NONBLOCK",)
    if any(not hasattr(os, name) for name in required) or not (
        SECURE_DESCRIPTOR_TRAVERSAL_SUPPORTED
    ):
        fail("secure Access build-input descriptor traversal is unsupported")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    return flags | (os.O_DIRECTORY if directory else os.O_NONBLOCK)


def open_access_root(
    access_root: Path, require_root_owner: bool
) -> tuple[int, list[tuple[int, str, int]], list[int]]:
    components = access_root.parts[1:]
    if (
        not access_root.is_absolute()
        or access_root.anchor != "/"
        or not components
        or os.path.normpath(os.fspath(access_root)) != os.fspath(access_root)
    ):
        fail(f"unsafe binding root: {access_root}")
    directory_flags = secure_open_flags(directory=True)
    descriptors: list[int] = []
    links: list[tuple[int, str, int]] = []
    try:
        root_descriptor = os.open("/", directory_flags)
        descriptors.append(root_descriptor)
        require_stable_directory(
            os.fstat(root_descriptor), "/", require_root_owner
        )
        for index, component in enumerate(components):
            parent_descriptor = descriptors[-1]
            try:
                before = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                fail(f"Access build input directory is absent: {access_root}")
            if stat.S_ISLNK(before.st_mode):
                fail(f"Access build input contains a symlink: {access_root}")
            is_access_root = index == len(components) - 1
            require_stable_directory(
                before,
                str(access_root),
                require_root_owner,
                allow_shared_ancestor=not is_access_root,
            )
            try:
                descriptor = os.open(
                    component, directory_flags, dir_fd=parent_descriptor
                )
            except OSError as error:
                fail(f"cannot securely open Access build input directory: {error}")
            descriptors.append(descriptor)
            after = os.fstat(descriptor)
            if stable_stat_identity(before) != stable_stat_identity(after):
                fail(
                    "Access build input directory changed while opening: "
                    f"{access_root}"
                )
            require_stable_directory(
                after,
                str(access_root),
                require_root_owner,
                allow_shared_ancestor=not is_access_root,
            )
            links.append((parent_descriptor, component, descriptor))
        return descriptors[-1], links, descriptors
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def read_descriptor_sha256(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            return value.hexdigest()
        value.update(block)


def acquire_stable_read_lease(descriptor: int, label: str) -> os.stat_result:
    if not SECURE_FILE_LEASES_SUPPORTED:
        fail("secure Access build-input file leases are unsupported")
    try:
        fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        lease = fcntl.fcntl(descriptor, fcntl.F_GETLEASE)
    except OSError as error:
        fail(f"cannot establish stable Access read lease for {label}: {error}")
    if lease != fcntl.F_RDLCK:
        fail(f"Access build input read lease is not stable: {label}")
    return os.fstat(descriptor)


def collect_access_tree_files(
    descriptor: int,
    relative_parts: tuple[str, ...],
    require_root_owner: bool,
    descriptors: list[int],
    files: list[tuple[str, int, tuple[int, ...]]],
    entries: list[tuple[int, str, tuple[int, ...], bool]],
    directories: list[tuple[str, int, tuple[str, ...], tuple[int, ...]]],
) -> None:
    label = "/".join(relative_parts) or "."
    before_directory = os.fstat(descriptor)
    require_stable_directory(before_directory, label, require_root_owner)
    before_names = sorted(os.listdir(descriptor))
    ignored_directories = {".git", ".workflow", "target", "__pycache__"}
    for name in before_names:
        relative = (*relative_parts, name)
        relative_label = "/".join(relative)
        try:
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            fail(f"Access build input changed during traversal: {relative_label}")
        if stat.S_ISLNK(before.st_mode):
            fail(f"Access build input contains a symlink: {relative_label}")
        if stat.S_ISDIR(before.st_mode):
            require_stable_directory(before, relative_label, require_root_owner)
            if name in ignored_directories:
                expected_identity = stable_stat_identity(before)
                compare_full_snapshot = False
            else:
                child_descriptor = os.open(
                    name, secure_open_flags(directory=True), dir_fd=descriptor
                )
                descriptors.append(child_descriptor)
                opened = os.fstat(child_descriptor)
                if stable_stat_snapshot(before) != stable_stat_snapshot(opened):
                    fail(
                        "Access build input directory changed while opening: "
                        f"{relative_label}"
                    )
                require_stable_directory(opened, relative_label, require_root_owner)
                collect_access_tree_files(
                    child_descriptor,
                    relative,
                    require_root_owner,
                    descriptors,
                    files,
                    entries,
                    directories,
                )
                expected_identity = stable_stat_snapshot(opened)
                compare_full_snapshot = True
        elif name.endswith(".pyc") or fnmatch.fnmatch(name, "*.log"):
            if require_root_owner:
                require_stable_file(before, relative_label, True)
            expected_identity = stable_stat_identity(before)
            compare_full_snapshot = False
        else:
            require_stable_file(before, relative_label, require_root_owner)
            file_descriptor = os.open(
                name, secure_open_flags(directory=False), dir_fd=descriptor
            )
            descriptors.append(file_descriptor)
            opened = os.fstat(file_descriptor)
            if stable_stat_snapshot(before) != stable_stat_snapshot(opened):
                fail(
                    "Access build input file changed while opening: "
                    f"{relative_label}"
                )
            require_stable_file(opened, relative_label, require_root_owner)
            stable_file = (
                acquire_stable_read_lease(file_descriptor, relative_label)
                if require_root_owner
                else opened
            )
            require_stable_file(stable_file, relative_label, require_root_owner)
            expected_identity = stable_stat_snapshot(stable_file)
            compare_full_snapshot = True
            files.append((relative_label, file_descriptor, expected_identity))
        try:
            mapped = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            fail(f"Access build input changed during traversal: {relative_label}")
        observed_identity = (
            stable_stat_snapshot(mapped)
            if compare_full_snapshot
            else stable_stat_identity(mapped)
        )
        if observed_identity != expected_identity:
            fail(f"Access build input changed during traversal: {relative_label}")
        entries.append(
            (descriptor, name, expected_identity, compare_full_snapshot)
        )
    if sorted(os.listdir(descriptor)) != before_names:
        fail(f"Access build input directory entries changed: {label}")
    after_directory = os.fstat(descriptor)
    if stable_stat_snapshot(before_directory) != stable_stat_snapshot(
        after_directory
    ):
        fail(f"Access build input directory changed during traversal: {label}")
    directories.append(
        (
            label,
            descriptor,
            tuple(before_names),
            stable_stat_snapshot(before_directory),
        )
    )


def validate_access_tree_snapshot(
    files: list[tuple[str, int, tuple[int, ...]]],
    entries: list[tuple[int, str, tuple[int, ...], bool]],
    directories: list[tuple[str, int, tuple[str, ...], tuple[int, ...]]],
    require_root_owner: bool,
) -> None:
    for relative, descriptor, expected in files:
        observed = os.fstat(descriptor)
        require_stable_file(observed, relative, require_root_owner)
        if stable_stat_snapshot(observed) != expected:
            fail(f"Access build input file changed during snapshot: {relative}")
        if require_root_owner and fcntl.fcntl(
            descriptor, fcntl.F_GETLEASE
        ) != fcntl.F_RDLCK:
            fail(f"Access build input read lease changed: {relative}")
    for parent_descriptor, name, expected, compare_full_snapshot in entries:
        try:
            mapped = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            fail(f"Access build input changed during snapshot: {name}")
        observed = (
            stable_stat_snapshot(mapped)
            if compare_full_snapshot
            else stable_stat_identity(mapped)
        )
        if observed != expected:
            fail(f"Access build input changed during snapshot: {name}")
    for label, descriptor, expected_names, expected in directories:
        if tuple(sorted(os.listdir(descriptor))) != expected_names:
            fail(f"Access build input directory entries changed: {label}")
        if stable_stat_snapshot(os.fstat(descriptor)) != expected:
            fail(f"Access build input directory changed during snapshot: {label}")


def read_access_tree_digests(
    files: list[tuple[str, int, tuple[int, ...]]],
    require_root_owner: bool,
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for relative, descriptor, expected in files:
        before = os.fstat(descriptor)
        if stable_stat_snapshot(before) != expected:
            fail(f"Access build input file changed before reading: {relative}")
        if require_root_owner and fcntl.fcntl(
            descriptor, fcntl.F_GETLEASE
        ) != fcntl.F_RDLCK:
            fail(f"Access build input read lease changed: {relative}")
        file_sha256 = read_descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        if stable_stat_snapshot(after) != expected:
            fail(f"Access build input file changed while reading: {relative}")
        result.append((relative, file_sha256))
    return result


def access_tree_build_input_sha_v2(
    access_root: Path, require_root_owner: bool = False
) -> str:
    """Hash one exact Docker-relevant Access tree without workflow/runtime debris."""
    descriptor, links, descriptors = open_access_root(
        access_root, require_root_owner
    )
    files: list[tuple[str, int, tuple[int, ...]]] = []
    entries: list[tuple[int, str, tuple[int, ...], bool]] = []
    directories: list[tuple[str, int, tuple[str, ...], tuple[int, ...]]] = []
    try:
        collect_access_tree_files(
            descriptor,
            (),
            require_root_owner,
            descriptors,
            files,
            entries,
            directories,
        )
        validate_access_tree_snapshot(
            files, entries, directories, require_root_owner
        )
        first_digests = read_access_tree_digests(files, require_root_owner)
        second_digests = read_access_tree_digests(files, require_root_owner)
        if first_digests != second_digests:
            fail("Access build input file digest changed during snapshot")
        validate_access_tree_snapshot(
            files, entries, directories, require_root_owner
        )
        for parent_descriptor, component, child_descriptor in links:
            mapped = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(child_descriptor)
            if stable_stat_identity(mapped) != stable_stat_identity(opened):
                fail(
                    "Access build input path changed during traversal: "
                    f"{access_root}"
                )
            require_stable_directory(
                opened,
                str(access_root),
                require_root_owner,
                allow_shared_ancestor=child_descriptor != descriptor,
            )
    finally:
        for open_descriptor in reversed(descriptors):
            os.close(open_descriptor)
    value = hashlib.sha256()
    for relative, file_sha256 in sorted(first_digests):
        value.update(relative.encode("utf-8"))
        value.update(b"\0")
        value.update(file_sha256.encode("ascii"))
        value.update(b"\n")
    return value.hexdigest()


def access_build_input_sha_v2(
    stage_root: Path, require_root_owner: bool = False
) -> str:
    return access_tree_build_input_sha_v2(
        stage_root / "access-governance", require_root_owner
    )


def access_build_input_sha_for_schema(
    stage_root: Path, schema: object, require_root_owner: bool = False
) -> str:
    if schema == ACCESS_BUILD_INPUT_SCHEMA_V1:
        return access_build_input_sha(stage_root, require_root_owner)
    if schema == ACCESS_BUILD_INPUT_SCHEMA_V2:
        return access_build_input_sha_v2(stage_root, require_root_owner)
    fail("unsupported Access build-input schema")


def write_binding(ops_root: Path, output: Path, successor: bool = False) -> None:
    root = require_directory(ops_root.absolute())
    destination = output.absolute()
    require_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        fail(f"render-input binding output already exists: {destination}")
    lines = []
    inputs = SUCCESSOR_BOUND_INPUTS if successor else BOUND_INPUTS
    for name in inputs:
        source = root / name
        require_regular(source)
        lines.append(f"{digest(source)}  {name}")
    with destination.open("x", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(destination, 0o600)


def verify_binding(
    ops_root: Path, manifest_path: Path, require_root_owner: bool = False
) -> None:
    root = require_directory(ops_root.absolute(), require_root_owner)
    expected = parse_manifest(manifest_path.absolute(), require_root_owner)
    for name in expected:
        source = root / name
        require_regular(source, require_root_owner)
        if digest(source) != expected[name]:
            fail(f"render-input binding drift: {name}")


def verify_apply_binding(
    ops_root: Path,
    manifest_path: Path,
    stage_root: Path,
    release_evidence_path: Path,
    expected_mode: str,
    require_root_owner: bool = False,
    source_estate_root: Path | None = None,
) -> None:
    root = require_directory(ops_root.absolute(), require_root_owner)
    stage = require_directory(stage_root.absolute(), require_root_owner)
    evidence_path = release_evidence_path.absolute()
    if evidence_path != stage / "RELEASE-EVIDENCE.json":
        fail("release evidence must be the canonical staged control file")
    evidence = load_object(evidence_path, require_root_owner)
    if expected_mode not in {"base", "successor", "successor-catalog"}:
        fail("expected release mode must be base, successor, or successor-catalog")
    successor = expected_mode in {"successor", "successor-catalog"}
    catalog_only = expected_mode == "successor-catalog"
    if source_estate_root is not None and expected_mode != "successor":
        fail("live source identity is valid only for a full successor apply")
    expected_evidence_fields = (
        SUCCESSOR_CATALOG_EVIDENCE_FIELDS
        if catalog_only
        else SUCCESSOR_EVIDENCE_FIELDS
        if successor
        else BASE_FULL_EVIDENCE_FIELDS
    )
    if set(evidence) != expected_evidence_fields:
        fail("release evidence field set differs from the apply contract")
    if type(evidence.get("schema_version")) is not int or evidence.get(
        "schema_version"
    ) != (2 if successor else 1):
        fail("release evidence schema differs from the expected release mode")
    if evidence.get("catalog_only") is not catalog_only:
        fail("release evidence catalog mode differs from the expected release mode")
    if successor:
        if (
            evidence.get("release_mode") != "successor"
            or evidence.get("access_governance_build_input_schema")
            != ACCESS_BUILD_INPUT_SCHEMA_V2
            or not isinstance(evidence.get("holdfast_release_tool_revision"), str)
            or not re.fullmatch(
                r"[0-9a-f]{40}", str(evidence["holdfast_release_tool_revision"])
            )
        ):
            fail("successor release identity differs from the apply contract")
    elif any(
        field in evidence
        for field in (
            "release_mode",
            "access_governance_build_input_schema",
            "holdfast_release_tool_revision",
            "predecessor_binding",
            "successor_delta_sha256",
        )
    ):
        fail("base release evidence contains successor-only authority")
    expected_inputs = SUCCESSOR_BOUND_INPUTS if successor else BOUND_INPUTS
    bound_inputs = parse_manifest(manifest_path.absolute(), require_root_owner)
    if tuple(bound_inputs) != expected_inputs:
        fail("render-input binding mode differs from release evidence")
    verify_binding(root, manifest_path, require_root_owner)

    static_targets = parse_static_manifest(
        root
        / (
            "successor-static-targets.sha256"
            if successor
            else "static-targets.sha256"
        ),
        require_root_owner,
    )
    static_paths = CATALOG_STATIC_PATHS if catalog_only else FROZEN_STATIC_PATHS
    for relative in static_paths:
        expected = static_targets[relative]
        observed = digest(rooted_regular(stage, relative, require_root_owner))
        if observed != expected:
            fail(f"stage static target drift: {relative}")

    frozen = load_object(
        root
        / (
            "successor-frozen-targets.json"
            if successor
            else "frozen-targets.json"
        ),
        require_root_owner,
    )
    expected_schema = 2 if successor else 1
    expected_frozen_fields = FROZEN_ROOT_FIELDS | (
        {"access_governance_build_input_schema"} if successor else set()
    )
    if (
        set(frozen) != expected_frozen_fields
        or
        type(frozen.get("schema_version")) is not int
        or frozen.get("schema_version") != expected_schema
        or frozen.get("generator") != evidence.get("generator")
    ):
        fail("frozen evidence contract version or generator differs")
    if successor:
        if tuple(frozen.get("required_unresolved_inputs", ())) != (
            SUCCESSOR_UNRESOLVED_INPUTS
        ):
            fail("successor unresolved-input contract differs")
        tokenizer = frozen.get("tokenizer")
        if (
            type(frozen.get("release_epoch")) is not int
            or not isinstance(tokenizer, dict)
            or set(tokenizer)
            != {
                "name",
                "package",
                "vocabulary_sha256",
                "minimum_context_tokens",
            }
            or type(tokenizer.get("minimum_context_tokens")) is not int
            or not isinstance(tokenizer.get("vocabulary_sha256"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(tokenizer["vocabulary_sha256"])
            )
        ):
            fail("successor tokenizer or epoch contract differs")
        policy = load_object(root / "successor-policy.json", require_root_owner)
        policy_version = policy.get("schema_version")
        if (
            set(policy)
            != {
                "schema_version",
                "ceremony",
                "predecessor",
                "successor",
                "overlay",
            }
            or type(policy_version) is not int
            or policy_version not in SUCCESSOR_POLICY_CEREMONIES
            or policy.get("ceremony")
            != SUCCESSOR_POLICY_CEREMONIES[policy_version]
        ):
            fail("successor policy field set or schema differs")
        predecessor = policy.get("predecessor")
        policy_successor = policy.get("successor")
        overlay = policy.get("overlay")
        expected_predecessor_fields = (
            RECOVERED_PREDECESSOR_FIELDS
            if policy_version == 3
            else LEGACY_PREDECESSOR_FIELDS
        )
        if (
            not isinstance(predecessor, dict)
            or set(predecessor) != expected_predecessor_fields
            or evidence.get("predecessor_binding") != predecessor
            or predecessor.get("access_build_input_schema")
            not in {
                ACCESS_BUILD_INPUT_SCHEMA_V1,
                ACCESS_BUILD_INPUT_SCHEMA_V2,
            }
            or (
                policy_version == 1
                and predecessor.get("access_build_input_schema")
                != ACCESS_BUILD_INPUT_SCHEMA_V1
            )
            or (
                policy_version == 3
                and predecessor.get("access_build_input_schema")
                != ACCESS_BUILD_INPUT_SCHEMA_V2
            )
            or not isinstance(policy_successor, dict)
            or set(policy_successor) != SUCCESSOR_POLICY_FIELDS
            or policy_successor.get("generator") != evidence.get("generator")
            or policy_successor.get("access_build_input_schema")
            != ACCESS_BUILD_INPUT_SCHEMA_V2
            or not isinstance(
                policy_successor.get("source_access_build_input_sha256"), str
            )
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(policy_successor["source_access_build_input_sha256"]),
            )
            or policy_successor.get("access_build_input_sha256")
            != frozen.get("access_governance_build_input_sha256")
            or predecessor.get("permission_catalog_sha256")
            != frozen.get("permission_catalog_sha256")
            or predecessor.get("package_catalog_sha256")
            != frozen.get("package_catalog_sha256")
            or frozen.get("access_governance_build_input_schema")
            != ACCESS_BUILD_INPUT_SCHEMA_V2
        ):
            fail("successor policy, frozen target and evidence bindings differ")
        if policy_version == 3:
            validate_completion_binding(predecessor.get("completion"))
        if not isinstance(overlay, list) or (
            policy_version == 1 and len(overlay) != 7
        ) or (
            policy_version in (2, 3)
            and (not overlay or len(overlay) > MAX_SUCCESSOR_OVERLAY_PATHS)
        ):
            fail("successor overlay field set differs")
        seen_overlay: set[str] = set()
        overlay_paths: list[str] = []
        for item in overlay:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "before_sha256",
                "after_sha256",
            }:
                fail("successor overlay entry field set differs")
            relative = item.get("path")
            before = item.get("before_sha256")
            after = item.get("after_sha256")
            if (
                not isinstance(relative, str)
                or not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
                or not relative.startswith("access-governance/")
                or len(Path(relative).parts) < 2
                or relative.startswith("/")
                or ".." in Path(relative).parts
                or Path(relative).as_posix() != relative
                or relative in seen_overlay
                or (before is not None and not isinstance(before, str))
                or (isinstance(before, str) and not re.fullmatch(r"[0-9a-f]{64}", before))
                or not isinstance(after, str)
                or not re.fullmatch(r"[0-9a-f]{64}", after)
            ):
                fail("successor overlay entry is invalid")
            if digest(rooted_regular(stage, relative, require_root_owner)) != after:
                fail(f"stage successor overlay differs: {relative}")
            seen_overlay.add(relative)
            overlay_paths.append(relative)
        if policy_version in (2, 3) and overlay_paths != sorted(overlay_paths):
            fail("successor overlay path order differs")
        validate_adjacent_recovery_completion(
            stage,
            predecessor,
            policy_version,
            source_estate_root,
            require_root_owner,
        )
        if source_estate_root is not None:
            source_estate = require_directory(
                source_estate_root.absolute(), require_root_owner
            )
            observed_source_build_input = access_tree_build_input_sha_v2(
                source_estate / "access-governance", require_root_owner
            )
            if observed_source_build_input != policy_successor.get(
                "source_access_build_input_sha256"
            ):
                fail("live successor Access source build input differs")
        release = evidence.get("release")
        if catalog_only:
            if release != {}:
                fail("successor catalog evidence must not contain release pins")
        elif (
            not isinstance(release, dict)
            or release.get("HOLDFAST_RELEASE_TOOL_REVISION")
            != evidence.get("holdfast_release_tool_revision")
            or release.get("ACCESS_GOVERNANCE_ROLLBACK_IMAGE")
            != predecessor.get("access_image")
        ):
            fail("successor release pins differ from predecessor or tool authority")
        delta_path = rooted_regular(
            stage, "SUCCESSOR-DELTA.sha256", require_root_owner
        )
        delta_sha = evidence.get("successor_delta_sha256")
        if not isinstance(delta_sha, str) or digest(delta_path) != delta_sha:
            fail("successor delta binding differs")
        expected_delta = "".join(
            f"{item['before_sha256'] or '0' * 64}  {item['after_sha256']}  {item['path']}\n"
            for item in overlay
        )
        if delta_path.read_text(encoding="utf-8") != expected_delta:
            fail("successor delta content differs from the policy")
    for field in FROZEN_FIELDS:
        expected = frozen.get(field)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            fail(f"invalid frozen semantic digest: {field}")
        if evidence.get(field) != expected:
            fail(f"release evidence frozen semantic drift: {field}")

    for field, relative in STAGE_SEMANTIC_PATHS.items():
        if digest(rooted_regular(stage, relative, require_root_owner)) != frozen[field]:
            fail(f"stage semantic digest differs from frozen authority: {field}")
    build_input = (
        access_build_input_sha_v2(stage, require_root_owner)
        if successor
        else access_build_input_sha(stage, require_root_owner)
    )
    if build_input != frozen[
        "access_governance_build_input_sha256"
    ]:
        fail(
            "stage semantic digest differs from frozen authority: "
            "access_governance_build_input_sha256"
        )
    for field, relative in ROUTE_ASSET_PATHS.items():
        if digest(rooted_regular(root, relative, require_root_owner)) != frozen[field]:
            fail(f"route asset digest differs from frozen authority: {field}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    write_parser = subparsers.add_parser("write")
    write_parser.add_argument("--ops-root", required=True, type=Path)
    write_parser.add_argument("--output", required=True, type=Path)
    write_parser.add_argument("--successor", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--ops-root", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    verify_parser.add_argument("--stage-root", type=Path)
    verify_parser.add_argument("--release-evidence", type=Path)
    verify_parser.add_argument(
        "--expected-mode", choices=("base", "successor", "successor-catalog")
    )
    verify_parser.add_argument("--source-estate-root", type=Path)
    verify_parser.add_argument("--require-root-owner", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "write":
            write_binding(args.ops_root, args.output, args.successor)
        else:
            if (args.stage_root is None) != (args.release_evidence is None):
                fail("--stage-root and --release-evidence must be provided together")
            if args.stage_root is None:
                if args.expected_mode is not None or args.source_estate_root is not None:
                    fail(
                        "--expected-mode and --source-estate-root require staged release evidence"
                    )
                verify_binding(args.ops_root, args.manifest, args.require_root_owner)
            else:
                if args.expected_mode is None:
                    fail("--expected-mode is required for staged release evidence")
                verify_apply_binding(
                    args.ops_root,
                    args.manifest,
                    args.stage_root,
                    args.release_evidence,
                    args.expected_mode,
                    args.require_root_owner,
                    args.source_estate_root,
                )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"render input binding: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
