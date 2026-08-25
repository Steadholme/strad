#!/usr/bin/env python3
"""Bind render-time Holdfast authority inputs and verify them again at apply."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn


LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
STATIC_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
BOUND_INPUTS = (
    "static-targets.sha256",
    "frozen-targets.json",
    "preimages.sha256",
    "absent.paths",
)
FROZEN_STATIC_PATHS = (
    "access-governance/catalog/rikune-authz-v1.json",
    "access-governance/catalog/permission.sources.v1.json",
    "access-governance/catalog/permissions.snapshot.json",
    "access-governance/catalog/packages.snapshot.json",
    "access-governance/scripts/generate_permission_catalog.sh",
    "access-governance/scripts/validate_authz_manifests.py",
    "access-governance/src/catalog.rs",
    "access-governance/src/package_catalog.rs",
    "access-governance/src/handlers/ui.rs",
    "deploy/routes.seed.json",
    "deploy/docker-compose.yml",
    "deploy/access-governance.env.example",
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


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


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
    if tuple(values) != BOUND_INPUTS:
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


def load_object(path: Path, require_root_owner: bool = False) -> dict[str, object]:
    require_regular(path, require_root_owner)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
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


def write_binding(ops_root: Path, output: Path) -> None:
    root = require_directory(ops_root.absolute())
    destination = output.absolute()
    require_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        fail(f"render-input binding output already exists: {destination}")
    lines = []
    for name in BOUND_INPUTS:
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
    root = require_directory(ops_root.absolute())
    expected = parse_manifest(manifest_path.absolute(), require_root_owner)
    for name in BOUND_INPUTS:
        source = root / name
        require_regular(source, require_root_owner)
        if digest(source) != expected[name]:
            fail(f"render-input binding drift: {name}")


def verify_apply_binding(
    ops_root: Path,
    manifest_path: Path,
    stage_root: Path,
    release_evidence_path: Path,
    require_root_owner: bool = False,
) -> None:
    root = require_directory(ops_root.absolute(), require_root_owner)
    stage = require_directory(stage_root.absolute(), require_root_owner)
    evidence_path = release_evidence_path.absolute()
    if evidence_path != stage / "RELEASE-EVIDENCE.json":
        fail("release evidence must be the canonical staged control file")
    verify_binding(root, manifest_path, require_root_owner)

    static_targets = parse_static_manifest(
        root / "static-targets.sha256", require_root_owner
    )
    for relative, expected in static_targets.items():
        observed = digest(rooted_regular(stage, relative, require_root_owner))
        if observed != expected:
            fail(f"stage static target drift: {relative}")

    frozen = load_object(root / "frozen-targets.json", require_root_owner)
    evidence = load_object(evidence_path, require_root_owner)
    if (
        frozen.get("schema_version") != 1
        or evidence.get("schema_version") != 1
        or frozen.get("generator") != evidence.get("generator")
    ):
        fail("frozen evidence contract version or generator differs")
    for field in FROZEN_FIELDS:
        expected = frozen.get(field)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            fail(f"invalid frozen semantic digest: {field}")
        if evidence.get(field) != expected:
            fail(f"release evidence frozen semantic drift: {field}")

    for field, relative in STAGE_SEMANTIC_PATHS.items():
        if digest(rooted_regular(stage, relative, require_root_owner)) != frozen[field]:
            fail(f"stage semantic digest differs from frozen authority: {field}")
    if access_build_input_sha(stage, require_root_owner) != frozen[
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
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--ops-root", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    verify_parser.add_argument("--stage-root", type=Path)
    verify_parser.add_argument("--release-evidence", type=Path)
    verify_parser.add_argument("--require-root-owner", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "write":
            write_binding(args.ops_root, args.output)
        else:
            if (args.stage_root is None) != (args.release_evidence is None):
                fail("--stage-root and --release-evidence must be provided together")
            if args.stage_root is None:
                verify_binding(args.ops_root, args.manifest, args.require_root_owner)
            else:
                verify_apply_binding(
                    args.ops_root,
                    args.manifest,
                    args.stage_root,
                    args.release_evidence,
                    args.require_root_owner,
                )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"render input binding: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
