#!/usr/bin/env python3
"""Validate the exact predecessor and TASK-001 delta for a Holdfast successor."""

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

from render_input_binding import (
    FROZEN_STATIC_PATHS,
    access_build_input_sha,
    access_tree_build_input_sha_v2,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9._/-]+$")
POLICY_CEREMONY = "holdfast-rikune-successor-v1"
BUILD_INPUT_V1 = "access-build-input/1"
BUILD_INPUT_V2 = "access-build-input/2"
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
    require_regular(path)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON authority {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON authority root must be an object: {path}")
    return value


def exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} field set is not exact")
    return value


def require_hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def safe_relative(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not SAFE_RELATIVE.fullmatch(value)
        or value.startswith("/")
        or ".." in Path(value).parts
    ):
        fail(f"{label} is not a safe relative path")
    return value


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    require_regular(path)
    result: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if (
            not match
            or match.group(2).startswith("/")
            or ".." in Path(match.group(2)).parts
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
            or relative in result
        ):
            fail(f"invalid or duplicate absent path line {line_number}: {path}")
        result.add(relative)
    return result


def validate_static_asset_transition(
    preimages: dict[str, str],
    static_targets: dict[str, str],
    authority_root: Path,
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
    if changed_paths != set(sources):
        fail("successor static asset transition path set is not exact")
    root = require_directory(authority_root)
    for relative, source_relative in sources.items():
        safe_relative(relative, "successor static asset target")
        safe_relative(source_relative, "successor static asset source")
        source = require_regular(root / source_relative)
        if source.resolve() != source or root not in source.resolve().parents:
            fail(f"successor static asset source escapes authority: {relative}")
        if sha256(source) != static_targets[relative]:
            fail(f"successor static asset source differs: {relative}")
    return sources


def verify_checksum_manifest(root: Path, manifest: Path) -> None:
    base = require_directory(root)
    for relative, expected in parse_checksum_manifest(manifest).items():
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
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or policy["ceremony"] != POLICY_CEREMONY
    ):
        fail("successor policy version or ceremony differs")
    predecessor = exact_object(
        policy["predecessor"],
        {
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
        },
        "predecessor policy",
    )
    for key in (
        "current_state_sha256",
        "control_sha256",
        "apply_receipt_sha256",
        "release_evidence_sha256",
        "runtime_manifest_sha256",
        "candidate_evidence_sha256",
        "candidate_targets_sha256",
        "access_build_input_sha256",
        "permission_catalog_sha256",
        "package_catalog_sha256",
    ):
        require_hex(predecessor[key], f"predecessor {key}")
    if predecessor["access_build_input_schema"] != BUILD_INPUT_V1:
        fail("predecessor build-input schema differs")
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
    if not isinstance(overlay, list) or len(overlay) != 7:
        fail("successor overlay must contain exactly seven paths")
    seen: set[str] = set()
    for index, item in enumerate(overlay):
        entry = exact_object(
            item,
            {"path", "before_sha256", "after_sha256"},
            f"overlay {index}",
        )
        relative = safe_relative(entry["path"], f"overlay {index} path")
        if not relative.startswith("access-governance/") or relative in seen:
            fail("successor overlay path is duplicate or outside Access")
        seen.add(relative)
        if entry["before_sha256"] is not None:
            require_hex(entry["before_sha256"], f"overlay {relative} before")
        require_hex(entry["after_sha256"], f"overlay {relative} after")
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
        fail(f"live Access delta differs from the exact TASK-001 overlay: {unexpected}")
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


def validate_predecessor(
    *,
    policy_path: Path,
    current_state_path: Path,
    estate_root: Path,
    predecessor_candidate: Path,
    predecessor_stage: Path,
    successor_preimages: Path,
) -> dict[str, Any]:
    policy = validate_policy(policy_path)
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
    validate_static_asset_transition(preimages, static_targets, authority_root)
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
    if sha256(state_path) != predecessor["current_state_sha256"]:
        fail("CURRENT authority differs from the successor policy")
    state = load_json(state_path)
    if (
        state.get("schema_version") != 2
        or state.get("state") != "applied_ingress_closed"
        or state.get("route_database_state") != "absent"
        or state.get("public_ipv4_ipv6_closed_status") != 404
        or state.get("ingress_opened") is not False
        or state.get("services_activated") is not True
        or state.get("runtime_verified") is not True
    ):
        fail("CURRENT is not a verified applied_ingress_closed predecessor")
    estate = require_directory(estate_root)
    if Path(str(state.get("estate_root"))).resolve() != estate:
        fail("CURRENT estate root differs")
    backup = require_directory(Path(str(state.get("backup_dir"))), private=True)
    if backup.parent != Path("/secure/backups") or not backup.name.startswith(
        "holdfast-rikune-"
    ):
        fail("CURRENT predecessor backup location is outside the release authority")
    authority_files = {
        "control_sha256": backup / "CONTROL.sha256",
        "apply_receipt_sha256": backup / "APPLY.receipt",
        "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
        "runtime_manifest_sha256": backup / "runtime/SHA256SUMS",
    }
    for key, path in authority_files.items():
        require_regular(path)
        if sha256(path) != predecessor[key]:
            fail(f"predecessor authority differs: {key}")
    if state.get("control_sha256") != predecessor["control_sha256"]:
        fail("CURRENT control binding differs")
    if state.get("apply_receipt_sha256") != predecessor["apply_receipt_sha256"]:
        fail("CURRENT apply receipt binding differs")
    if state.get("release_evidence_sha256") != predecessor["release_evidence_sha256"]:
        fail("CURRENT release evidence binding differs")
    verify_checksum_manifest(backup, backup / "CONTROL.sha256")
    verify_checksum_manifest(backup / "runtime", backup / "runtime/SHA256SUMS")

    candidate = require_directory(predecessor_candidate)
    stage = require_directory(predecessor_stage, private=True)
    if sha256(require_regular(candidate / "RELEASE-EVIDENCE.json")) != predecessor[
        "candidate_evidence_sha256"
    ]:
        fail("sealed predecessor candidate evidence differs")
    if sha256(require_regular(candidate / "TARGETS.sha256")) != predecessor[
        "candidate_targets_sha256"
    ]:
        fail("sealed predecessor candidate targets differ")
    verify_checksum_manifest(candidate, candidate / "TARGETS.sha256")
    if sha256(require_regular(stage / "RELEASE-EVIDENCE.json")) != predecessor[
        "release_evidence_sha256"
    ]:
        fail("sealed predecessor stage differs from live release evidence")
    if access_build_input_sha(candidate) != predecessor["access_build_input_sha256"]:
        fail("sealed predecessor Access build input differs")
    validate_supporting_snapshot(candidate, supporting_targets)
    release_evidence = load_json(stage / "RELEASE-EVIDENCE.json")
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
    return {
        "policy": policy,
        "state": state,
        "backup": backup,
        "predecessor_candidate": candidate,
        "predecessor_stage": stage,
        "successor_preimages": preimages,
        "successor_static_targets": static_targets,
        "successor_supporting_targets": supporting_targets,
    }


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
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--current-state", required=True, type=Path)
    parser.add_argument("--estate-root", required=True, type=Path)
    parser.add_argument("--predecessor-candidate", required=True, type=Path)
    parser.add_argument("--predecessor-stage", required=True, type=Path)
    parser.add_argument("--successor-preimages", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_predecessor(
            policy_path=args.policy.absolute(),
            current_state_path=args.current_state.absolute(),
            estate_root=args.estate_root.absolute(),
            predecessor_candidate=args.predecessor_candidate.absolute(),
            predecessor_stage=args.predecessor_stage.absolute(),
            successor_preimages=args.successor_preimages.absolute(),
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"holdfast successor binding: {error}", file=sys.stderr)
        return 1
    print("Holdfast successor predecessor and exact delta are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
