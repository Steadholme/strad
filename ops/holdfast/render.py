#!/usr/bin/env python3
"""Render the frozen Rikune estate target into an isolated staging tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from render_input_binding import (
    FROZEN_STATIC_PATHS,
    access_build_input_sha,
    access_build_input_sha_v2,
    write_binding,
)
from successor_binding import (
    MAX_SUCCESSOR_OVERLAY_PATHS,
    POLICY_CEREMONIES,
    SUCCESSOR_STATIC_ASSET_SOURCES,
    validate_predecessor,
    validate_static_asset_transition,
    validate_supporting_snapshot,
    write_delta_manifest,
)


OPS_ROOT = Path(__file__).resolve().parent
STRAD_ROOT = OPS_ROOT.parent.parent
ASSETS = OPS_ROOT / "assets"
GENERATOR_VERSION = "holdfast-rikune-estate/1.0.0"
SUCCESSOR_GENERATOR_VERSION = "holdfast-rikune-estate/2.0.0"
BUILD_INPUT_SCHEMA_V1 = "access-build-input/1"
BUILD_INPUT_SCHEMA_V2 = "access-build-input/2"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
RIKUNE_ACCEPTANCE_SUBJECT = re.compile(r"^user:usr_[A-Za-z0-9_-]{43}$")
MODEL_ALIAS = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
PRIVILEGED_ACCEPTANCE_SUBJECTS = frozenset({"user:u_admin", "user:w33d"})

MUTATED_PATHS = (
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
)

FULL_ONLY_PATHS = (
    "deploy/docker-compose.yml",
    "deploy/.env",
    "deploy/access-governance.env.example",
)

SECRET_KEYS = (
    "STRAD_DATABASE_URL",
    "STRAD_BRIDGE_TOKEN",
    "RIKUNE_FILE_SERVER_API_KEY",
    "STRAD_NEWAPI_KEY",
)

RELEASE_KEYS = (
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
)
SUCCESSOR_RELEASE_KEYS = RELEASE_KEYS + ("HOLDFAST_RELEASE_TOOL_REVISION",)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"holdfast render: {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"required path is absent: {path}")
    if not stat.S_ISREG(mode) or path.is_symlink():
        fail(f"path must be a regular non-symlink file: {path}")


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    require_regular(path)
    result: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if not match or match.group(2).startswith("/") or ".." in Path(match.group(2)).parts:
            fail(f"invalid checksum manifest line {line_number}")
        if match.group(2) in result:
            fail(f"duplicate checksum path: {match.group(2)}")
        result[match.group(2)] = match.group(1)
    if not result:
        fail("preimage manifest is empty")
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
            not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in result
        ):
            fail(f"invalid or duplicate path manifest line {line_number}")
        result.add(relative)
    return result


def write_apply_manifests(
    stage_root: Path, paths: list[str], successor: bool = False
) -> None:
    prefix = "successor-" if successor else ""
    source_preimages = parse_checksum_manifest(
        OPS_ROOT / f"{prefix}preimages.sha256"
    )
    source_absent = parse_path_manifest(OPS_ROOT / f"{prefix}absent.paths")
    target_set = set(paths)
    if len(target_set) != len(paths):
        fail("apply target paths contain duplicates")
    if set(source_preimages) & source_absent:
        fail("source preimage and absent manifests overlap")
    missing = target_set - (set(source_preimages) | source_absent)
    if missing:
        fail(f"apply targets lack preimage dispositions: {', '.join(sorted(missing))}")
    apply_preimages = [
        f"{source_preimages[relative]}  {relative}"
        for relative in paths
        if relative in source_preimages
    ]
    apply_absent = [relative for relative in paths if relative in source_absent]
    if target_set != {
        line.split("  ", 1)[1] for line in apply_preimages
    } | set(apply_absent):
        fail("generated apply manifests do not exactly cover the target set")
    preimages_path = stage_root / "APPLY-PREIMAGES.sha256"
    absent_path = stage_root / "APPLY-ABSENT.paths"
    preimages_path.write_text("\n".join(apply_preimages) + "\n", encoding="utf-8")
    absent_path.write_text(
        "".join(f"{relative}\n" for relative in apply_absent), encoding="utf-8"
    )
    os.chmod(preimages_path, 0o600)
    os.chmod(absent_path, 0o600)


def verify_preimages(estate_root: Path, successor: bool = False) -> None:
    prefix = "successor-" if successor else ""
    expected = parse_checksum_manifest(OPS_ROOT / f"{prefix}preimages.sha256")
    for relative, digest in expected.items():
        path = estate_root / relative
        require_regular(path)
        observed = sha256_file(path)
        if observed != digest:
            fail(f"preimage drift for {relative}: expected {digest}, got {observed}")
    for relative in (OPS_ROOT / f"{prefix}absent.paths").read_text(
        encoding="utf-8"
    ).splitlines():
        if not relative:
            continue
        if (estate_root / relative).exists() or (estate_root / relative).is_symlink():
            fail(f"expected-absent path now exists: {relative}")


def parse_env(
    path: Path, require_mode_0600: bool = False, allow_empty: bool = False
) -> dict[str, str]:
    require_regular(path)
    if require_mode_0600 and stat.S_IMODE(path.stat().st_mode) != 0o600:
        fail(f"secret env file must have mode 0600: {path}")
    return parse_env_text(path.read_text(encoding="utf-8"), path, allow_empty)


def parse_env_text(text: str, path: Path, allow_empty: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            fail(f"invalid env line {line_number} in {path}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            fail(f"invalid or duplicate env key on line {line_number} in {path}")
        if (not value and not allow_empty) or "\x00" in value or "\r" in value or "\n" in value:
            fail(f"empty or unsafe env value for {key}")
        values[key] = value
    return values


def read_private_env_snapshot(
    path: Path, label: str, allow_empty: bool = False
) -> tuple[dict[str, str], str]:
    source = path.absolute()
    parent = source.parent
    try:
        parent_metadata = parent.lstat()
    except FileNotFoundError:
        fail(f"{label} env parent is absent: {parent}")
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent.is_symlink()
        or parent.resolve() != parent
        or parent_metadata.st_uid != 0
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        fail(f"{label} env parent must be canonical, root-owned and private")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail(f"{label} env must be a root-owned single-link mode-0600 file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} env is not UTF-8: {error}")
    return parse_env_text(text, source, allow_empty), hashlib.sha256(raw).hexdigest()


def validate_release(
    values: dict[str, str], catalog_only: bool, successor: bool = False
) -> None:
    if catalog_only:
        return
    release_keys = SUCCESSOR_RELEASE_KEYS if successor else RELEASE_KEYS
    missing = [key for key in release_keys if key not in values]
    if missing:
        fail(f"release env is missing keys: {', '.join(missing)}")
    for key in (
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
    ):
        if not IMAGE_DIGEST.fullmatch(values[key]):
            fail(f"{key} must be an immutable lowercase repo digest")
    expected_rikune_prefix = "ghcr.io/last-emo-boy/rikune-analyzer-static@sha256:"
    if not values["RIKUNE_ANALYZER_IMAGE"].startswith(expected_rikune_prefix):
        fail("RIKUNE_ANALYZER_IMAGE has the wrong authoritative repository")
    for key in (
        "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256",
        "PERMISSION_CATALOG_SHA256",
        "PACKAGE_CATALOG_SHA256",
        "AUTHORITY_PUBLIC_KEY_SHA256",
        "SUPPLY_CHAIN_PUBLIC_KEY_SHA256",
        "SUPPLY_CHAIN_EVIDENCE_SHA256",
        "SUPPLY_CHAIN_SIGNATURE_SHA256",
    ):
        if not HEX64.fullmatch(values[key]):
            fail(f"{key} must be 64 lowercase hex characters")
    acceptance_subject = values["RIKUNE_ACCEPTANCE_SUBJECT"]
    if (
        acceptance_subject.startswith("REQUIRED")
        or acceptance_subject in PRIVILEGED_ACCEPTANCE_SUBJECTS
        or not RIKUNE_ACCEPTANCE_SUBJECT.fullmatch(acceptance_subject)
    ):
        fail(
            "RIKUNE_ACCEPTANCE_SUBJECT must be a non-placeholder, non-privileged "
            "user:usr_ subject with exactly 43 base64url characters"
        )
    if not HEX40.fullmatch(values["STRAD_REVISION"]):
        fail("STRAD_REVISION must be a 40-character lowercase commit id")
    if successor and not HEX40.fullmatch(values["HOLDFAST_RELEASE_TOOL_REVISION"]):
        fail("HOLDFAST_RELEASE_TOOL_REVISION must be a 40-character lowercase commit id")
    model = values["STRAD_NEWAPI_MODEL"]
    if not MODEL_ALIAS.fullmatch(model) or model.startswith("REQUIRED"):
        fail("STRAD_NEWAPI_MODEL must be a pinned existing alias")
    if values["ACCESS_GOVERNANCE_IMAGE"] == values["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"]:
        fail("Access Governance candidate and rollback images must differ")
    if values["RIKUNE_ANALYZER_IMAGE"] == values["STRAD_ANALYZER_IMAGE"]:
        fail(
            "RIKUNE_ANALYZER_IMAGE is the upstream static base while "
            "STRAD_ANALYZER_IMAGE is the bridge overlay; they must differ"
        )


def check_source_tree_for_symlinks(path: Path) -> None:
    for root, directories, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        directories[:] = [name for name in directories if name not in {".git", "target", "__pycache__"}]
        for name in [*directories, *files]:
            candidate = root_path / name
            if candidate.is_symlink():
                fail(f"source tree contains a symlink: {candidate}")


def copy_stage(estate_root: Path, stage_root: Path, catalog_only: bool) -> None:
    if stage_root.exists() or stage_root.is_symlink():
        fail(f"stage root must not already exist: {stage_root}")
    stage_root.mkdir(mode=0o700, parents=True)
    source_access = estate_root / "access-governance"
    check_source_tree_for_symlinks(source_access)
    shutil.copytree(
        source_access,
        stage_root / "access-governance",
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
    )
    source_verdict = estate_root / "verdict"
    check_source_tree_for_symlinks(source_verdict)
    shutil.copytree(
        source_verdict,
        stage_root / "verdict",
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc"),
    )
    (stage_root / "deploy").mkdir(mode=0o700)
    source_route_seed = estate_root / "deploy/routes.seed.json"
    route_seed = load_object(source_route_seed)
    routes = route_seed.get("routes")
    if not isinstance(routes, list) or len(routes) != 147:
        fail("route seed precondition failed")
    if any(
        item.get("name") == "rikune-root"
        for item in routes
        if isinstance(item, dict)
    ):
        fail("rikune-root already exists in the seed")
    staged_route_seed = stage_root / "deploy/routes.seed.json"
    shutil.copy2(source_route_seed, staged_route_seed)
    if sha256_file(source_route_seed) != sha256_file(staged_route_seed):
        fail("route seed copy differs from its estate preimage")
    if not catalog_only:
        for name in ("docker-compose.yml", ".env", "access-governance.env.example"):
            shutil.copy2(estate_root / f"deploy/{name}", stage_root / f"deploy/{name}")
        os.chmod(stage_root / "deploy/.env", 0o600)
    relay_dir = stage_root / "relay/upstream/new-api/router"
    relay_dir.mkdir(mode=0o700, parents=True)
    for name in ("enterprise_permissions.json", "newapi-authz-v1.json"):
        shutil.copy2(
            estate_root / f"relay/upstream/new-api/router/{name}", relay_dir / name
        )


def copy_successor_tree(source: Path, destination: Path) -> None:
    check_source_tree_for_symlinks(source)
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        ignore=shutil.ignore_patterns(
            ".git", ".workflow", "target", "__pycache__", "*.pyc", "*.log"
        ),
    )


def copy_successor_stage(
    estate_root: Path,
    predecessor_candidate: Path,
    stage_root: Path,
    catalog_only: bool,
    policy: dict[str, object],
    preimages: dict[str, str],
    static_targets: dict[str, str],
    authority_root: Path,
) -> None:
    if stage_root.exists() or stage_root.is_symlink():
        fail(f"stage root must not already exist: {stage_root}")
    stage_root.mkdir(mode=0o700, parents=True)
    copy_successor_tree(
        predecessor_candidate / "access-governance",
        stage_root / "access-governance",
    )
    overlay = policy.get("overlay")
    policy_version = policy.get("schema_version", 1)
    if (
        type(policy_version) is not int
        or policy_version not in POLICY_CEREMONIES
        or (
            "schema_version" in policy
            and policy.get("ceremony") != POLICY_CEREMONIES[policy_version]
        )
        or not isinstance(overlay, list)
        or (policy_version == 1 and len(overlay) != 7)
        or (
            policy_version == 2
            and (not overlay or len(overlay) > MAX_SUCCESSOR_OVERLAY_PATHS)
        )
    ):
        fail("successor overlay contract is absent")
    overlay_paths: list[str] = []
    for raw in overlay:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            fail("successor overlay entry is malformed")
        relative = raw["path"]
        if (
            not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
            or not relative.startswith("access-governance/")
            or len(Path(relative).parts) < 2
            or ".." in Path(relative).parts
            or Path(relative).as_posix() != relative
            or relative in overlay_paths
        ):
            fail("successor overlay path is invalid")
        overlay_paths.append(relative)
        source = estate_root / relative
        destination = stage_root / relative
        require_regular(source)
        if destination.exists() and destination.is_symlink():
            fail(f"successor overlay destination is a symlink: {relative}")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if sha256_file(destination) != raw.get("after_sha256"):
            fail(f"successor overlay copy differs: {relative}")
    if policy_version == 2 and overlay_paths != sorted(overlay_paths):
        fail("successor overlay path order differs")

    static_asset_sources = validate_static_asset_transition(
        preimages, static_targets, authority_root, policy_version
    )
    expected_static_asset_sources = tuple(
        (relative, source_relative)
        for relative, source_relative in SUCCESSOR_STATIC_ASSET_SOURCES
        if preimages[relative] != static_targets[relative]
    )
    if tuple(static_asset_sources.items()) != expected_static_asset_sources:
        fail("successor static asset source order differs")
    for relative, source_relative in static_asset_sources.items():
        source = authority_root / source_relative
        destination = stage_root / relative
        require_regular(source)
        require_regular(destination)
        if sha256_file(destination) != preimages[relative]:
            fail(f"successor static asset preimage differs: {relative}")
        shutil.copy2(source, destination)
        if sha256_file(destination) != static_targets[relative]:
            fail(f"successor static asset copy differs: {relative}")

    copy_successor_tree(
        predecessor_candidate / "verdict", stage_root / "verdict"
    )
    relay_source = predecessor_candidate / "relay/upstream/new-api/router"
    relay_destination = stage_root / "relay/upstream/new-api/router"
    relay_destination.mkdir(mode=0o700, parents=True)
    for name in ("enterprise_permissions.json", "newapi-authz-v1.json"):
        require_regular(relay_source / name)
        shutil.copy2(relay_source / name, relay_destination / name)

    deploy = stage_root / "deploy"
    deploy.mkdir(mode=0o700)
    deploy_source = predecessor_candidate if catalog_only else estate_root
    deploy_names = ["routes.seed.json"]
    if not catalog_only:
        deploy_names.extend(
            ("docker-compose.yml", ".env", "access-governance.env.example")
        )
    for name in deploy_names:
        source = deploy_source / f"deploy/{name}"
        require_regular(source)
        shutil.copy2(source, deploy / name)
    if not catalog_only:
        os.chmod(deploy / ".env", 0o600)


def validate_tool_revision(revision: str) -> None:
    if not HEX40.fullmatch(revision):
        fail("successor release tool revision must be a 40-character commit id")
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=STRAD_ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0 or completed.stdout.strip() != revision:
        fail("successor release tool revision differs from the checked-out Strad HEAD")
    status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "ops/holdfast",
        ],
        cwd=STRAD_ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if status.returncode != 0 or status.stdout:
        fail("successor release tooling checkout is not clean")


def validate_successor_snapshot(
    stage_root: Path,
    policy: dict[str, object],
    preimages: dict[str, str],
    supporting_targets: dict[str, str],
    catalog_only: bool,
) -> None:
    metadata = stage_root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stage_root.is_symlink()
        or stage_root.resolve() != stage_root
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        fail("successor snapshot must be a canonical root-owned private directory")
    successor = policy.get("successor")
    overlay = policy.get("overlay")
    if not isinstance(successor, dict) or not isinstance(overlay, list):
        fail("successor snapshot policy is malformed")
    if access_build_input_sha_v2(stage_root, require_root_owner=True) != successor.get(
        "access_build_input_sha256"
    ):
        fail("successor private snapshot build input differs from policy")
    for item in overlay:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            fail("successor private snapshot overlay is malformed")
        relative = item["path"]
        require_regular(stage_root / relative)
        if sha256_file(stage_root / relative) != item.get("after_sha256"):
            fail(f"successor private snapshot overlay differs: {relative}")
    deploy_paths = ["deploy/routes.seed.json"]
    if not catalog_only:
        deploy_paths.extend(
            (
                "deploy/docker-compose.yml",
                "deploy/.env",
                "deploy/access-governance.env.example",
            )
        )
    for relative in deploy_paths:
        expected = preimages.get(relative)
        if expected is None or sha256_file(stage_root / relative) != expected:
            fail(f"successor private deploy snapshot differs: {relative}")
    try:
        validate_supporting_snapshot(stage_root, supporting_targets)
    except ValueError as error:
        fail(str(error))


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def load_object(path: Path) -> dict:
    require_regular(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"malformed JSON in {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def replace_service(text: str, service: str, replacements: tuple[tuple[str, str], ...]) -> str:
    pattern = re.compile(rf"(?ms)^  {re.escape(service)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)")
    match = pattern.search(text)
    if not match:
        fail(f"Compose service marker is absent: {service}")
    block = match.group(0)
    for old, new in replacements:
        block = replace_once(block, old, new, f"{service} Compose")
    return text[: match.start()] + block + text[match.end() :]


def render_registry(stage_root: Path) -> None:
    path = stage_root / "access-governance/catalog/permission.sources.v1.json"
    value = load_object(path)
    sources = value.get("sources")
    if value.get("schema_version") != 1 or not isinstance(sources, list) or len(sources) != 6:
        fail("permission source registry precondition failed")
    added_sources = {"cistern-authz", "rikune-authz"}
    if any(
        isinstance(item, dict) and item.get("source") in added_sources for item in sources
    ):
        fail("Holdfast authorization source already exists")
    sources.extend(
        (
            {
                "path": "access-governance/catalog/cistern-authz-v1.json",
                "source": "cistern-authz",
                "schema_version": 1,
                "digest_scope": "permission-key-risk-v1",
            },
            {
                "path": "access-governance/catalog/rikune-authz-v1.json",
                "source": "rikune-authz",
                "schema_version": 1,
                "digest_scope": "permission-key-risk-v1",
            },
        )
    )
    write_json(path, value)


def render_generator(stage_root: Path) -> None:
    path = stage_root / "access-governance/scripts/generate_permission_catalog.sh"
    text = path.read_text(encoding="utf-8")
    replacements = (
        (
            'newapi_authz_source="$workspace_dir/relay/upstream/new-api/router/newapi-authz-v1.json"\n',
            'newapi_authz_source="$workspace_dir/relay/upstream/new-api/router/newapi-authz-v1.json"\n'
            'cistern_authz_source="$service_dir/catalog/cistern-authz-v1.json"\n'
            'rikune_authz_source="$service_dir/catalog/rikune-authz-v1.json"\n',
            "Holdfast generator sources",
        ),
        (
            '"$multica_authz_source" "$newapi_authz_source" "$source_registry"; do',
            '"$multica_authz_source" "$newapi_authz_source" "$cistern_authz_source" "$rikune_authz_source" "$source_registry"; do',
            "generator source loop",
        ),
        (
            'newapi_authz_canonical="$tmp_dir/newapi-authz.canonical.json"\n',
            'newapi_authz_canonical="$tmp_dir/newapi-authz.canonical.json"\n'
            'cistern_authz_canonical="$tmp_dir/cistern-authz.canonical.json"\n'
            'rikune_authz_canonical="$tmp_dir/rikune-authz.canonical.json"\n',
            "Holdfast canonical files",
        ),
        (
            '  --slurpfile newapi_authz "$newapi_authz_source" \'\n',
            '  --slurpfile newapi_authz "$newapi_authz_source" \\\n'
            '  --slurpfile cistern_authz "$cistern_authz_source" \\\n'
            '  --slurpfile rikune_authz "$rikune_authz_source" \'\n',
            "Holdfast jq slurp",
        ),
        (
            '     or $newapi_authz[0].schema_version != 1\n',
            '     or $newapi_authz[0].schema_version != 1 or $cistern_authz[0].schema_version != 1\n'
            '     or $rikune_authz[0].schema_version != 1\n',
            "Holdfast schema check",
        ),
        (
            '     or (($newapi_authz[0].permissions | type) != "array")\n',
            '     or (($newapi_authz[0].permissions | type) != "array")\n'
            '     or (($cistern_authz[0].permissions | type) != "array")\n'
            '     or (($rikune_authz[0].permissions | type) != "array")\n',
            "Holdfast permissions type",
        ),
        (
            '  | ([ $routes[0].routes[]\n'
            '       | select(.require_permission? != null and .require_permission != "")\n'
            '       | {key: .require_permission, risk: .risk, source: "sluice-routes"} ]) as $route_items\n',
            '  | ([ $routes[0].routes[]\n'
            '       | select(.require_permission? != null and .require_permission != "")\n'
            '       | {key: .require_permission, risk: .risk, source: "sluice-routes"} ]) as $route_items_raw\n'
            '  | if ($route_items_raw | group_by(.key)\n'
            '        | any(.[]; ([.[].risk] | unique | length) != 1))\n'
            '    then error("sluice route permission risk conflict") else . end\n'
            '  | ([ $route_items_raw | group_by(.key)[] | .[0] ]) as $route_items\n',
            "route duplicate canonicalization",
        ),
        (
            '  | ([ $newapi_authz[0].permissions[] | . + {source: "newapi-authz"} ]) as $newapi_authz_items\n'
            '  | ($access_items + $route_items + $newapi_items + $cpa_authz_items + $multica_authz_items + $newapi_authz_items) as $raw\n',
            '  | ([ $newapi_authz[0].permissions[] | . + {source: "newapi-authz"} ]) as $newapi_authz_items\n'
            '  | ([ $cistern_authz[0].permissions[] | . + {source: "cistern-authz"} ]) as $cistern_authz_items\n'
            '  | ([ $rikune_authz[0].permissions[] | . + {source: "rikune-authz"} ]) as $rikune_authz_items\n'
            '  | ($access_items + $route_items + $newapi_items + $cpa_authz_items + $multica_authz_items + $newapi_authz_items + $cistern_authz_items + $rikune_authz_items) as $raw\n',
            "Holdfast raw entries",
        ),
        (
            '[$access_items, $route_items, $newapi_items, $cpa_authz_items, $multica_authz_items, $newapi_authz_items][];',
            '[$access_items, $route_items, $newapi_items, $cpa_authz_items, $multica_authz_items, $newapi_authz_items, $cistern_authz_items, $rikune_authz_items][];',
            "Holdfast duplicate source list",
        ),
        (
            '      | {key: .require_permission, risk}] | sort_by(.key))\n',
            '      | {key: .require_permission, risk}]\n'
            '      | group_by(.key) | map(.[0]) | sort_by(.key))\n',
            "route canonical digest de-duplication",
        ),
        (
            '\' "$newapi_authz_source" >"$newapi_authz_canonical"\n',
            '\' "$newapi_authz_source" >"$newapi_authz_canonical"\n'
            'jq -cS \'\n'
            '  {\n'
            '    source: "cistern-authz",\n'
            '    schema_version: .schema_version,\n'
            '    permissions: ([.permissions[] | {key, risk}] | sort_by(.key))\n'
            '  }\n'
            '\' "$cistern_authz_source" >"$cistern_authz_canonical"\n'
            'jq -cS \'\n'
            '  {\n'
            '    source: "rikune-authz",\n'
            '    schema_version: .schema_version,\n'
            '    permissions: ([.permissions[] | {key, risk}] | sort_by(.key))\n'
            '  }\n'
            '\' "$rikune_authz_source" >"$rikune_authz_canonical"\n',
            "Holdfast canonical digest blocks",
        ),
        (
            '  --arg newapi_authz_digest "$(sha256sum "$newapi_authz_canonical" | cut -d\' \' -f1)" \'\n',
            '  --arg newapi_authz_digest "$(sha256sum "$newapi_authz_canonical" | cut -d\' \' -f1)" \\\n'
            '  --arg cistern_authz_path "access-governance/catalog/cistern-authz-v1.json" \\\n'
            '  --arg cistern_authz_digest "$(sha256sum "$cistern_authz_canonical" | cut -d\' \' -f1)" \\\n'
            '  --arg rikune_authz_path "access-governance/catalog/rikune-authz-v1.json" \\\n'
            '  --arg rikune_authz_digest "$(sha256sum "$rikune_authz_canonical" | cut -d\' \' -f1)" \'\n',
            "Holdfast metadata args",
        ),
        (
            '      {path: $newapi_authz_path, source: "newapi-authz", schema_version: 1,\n'
            '       digest_scope: "permission-key-risk-v1", sha256: $newapi_authz_digest}\n',
            '      {path: $newapi_authz_path, source: "newapi-authz", schema_version: 1,\n'
            '       digest_scope: "permission-key-risk-v1", sha256: $newapi_authz_digest},\n'
            '      {path: $cistern_authz_path, source: "cistern-authz", schema_version: 1,\n'
            '       digest_scope: "permission-key-risk-v1", sha256: $cistern_authz_digest},\n'
            '      {path: $rikune_authz_path, source: "rikune-authz", schema_version: 1,\n'
            '       digest_scope: "permission-key-risk-v1", sha256: $rikune_authz_digest}\n',
            "Holdfast generated_from",
        ),
    )
    for old, new, label in replacements:
        text = replace_once(text, old, new, label)
    path.write_text(text, encoding="utf-8")


def render_validator(stage_root: Path) -> None:
    path = stage_root / "access-governance/scripts/validate_authz_manifests.py"
    text = path.read_text(encoding="utf-8")
    old = '    SERVICE_DIR / "catalog" / "cpa-authz-v1.json",\n'
    new = (
        old
        + '    SERVICE_DIR / "catalog" / "cistern-authz-v1.json",\n'
        + '    SERVICE_DIR / "catalog" / "rikune-authz-v1.json",\n'
    )
    path.write_text(replace_once(text, old, new, "validator manifest"), encoding="utf-8")


def render_catalog_rs(stage_root: Path) -> None:
    path = stage_root / "access-governance/src/catalog.rs"
    text = path.read_text(encoding="utf-8")
    changes = (
        (
            'const MULTICA_AUTHZ_MANIFEST: &str = include_str!("../catalog/multica-authz-v1.json");\n',
            'const MULTICA_AUTHZ_MANIFEST: &str = include_str!("../catalog/multica-authz-v1.json");\n'
            'const CISTERN_AUTHZ_MANIFEST: &str = include_str!("../catalog/cistern-authz-v1.json");\n'
            'const RIKUNE_AUTHZ_MANIFEST: &str = include_str!("../catalog/rikune-authz-v1.json");\n',
            "Holdfast includes",
        ),
        (
            '    validate_service_manifest(&snapshot.entries, MULTICA_AUTHZ_MANIFEST, "multica-authz")?;\n',
            '    validate_service_manifest(&snapshot.entries, MULTICA_AUTHZ_MANIFEST, "multica-authz")?;\n'
            '    validate_service_manifest(&snapshot.entries, CISTERN_AUTHZ_MANIFEST, "cistern-authz")?;\n'
            '    validate_service_manifest(&snapshot.entries, RIKUNE_AUTHZ_MANIFEST, "rikune-authz")?;\n',
            "Holdfast service validation",
        ),
        (
            '    Ok(())\n}\n\nfn canonical_source_digest(',
            '    let cistern_source = sources\n'
            '        .iter()\n'
            '        .find(|source| source.source == "cistern-authz")\n'
            '        .ok_or_else(|| "Cistern authorization manifest source is missing".to_string())?;\n'
            '    let cistern_manifest: PermissionManifest = serde_json::from_str(CISTERN_AUTHZ_MANIFEST)\n'
            '        .map_err(|_| "Cistern authorization manifest is malformed".to_string())?;\n'
            '    if cistern_source.sha256\n'
            '        != canonical_source_digest(\n'
            '            "cistern-authz",\n'
            '            cistern_manifest.schema_version,\n'
            '            &cistern_manifest.permissions,\n'
            '        )?\n'
            '    {\n'
            '        return Err("Cistern authorization manifest source digest changed".to_string());\n'
            '    }\n'
            '    let rikune_source = sources\n'
            '        .iter()\n'
            '        .find(|source| source.source == "rikune-authz")\n'
            '        .ok_or_else(|| "Rikune authorization manifest source is missing".to_string())?;\n'
            '    let rikune_manifest: PermissionManifest = serde_json::from_str(RIKUNE_AUTHZ_MANIFEST)\n'
            '        .map_err(|_| "Rikune authorization manifest is malformed".to_string())?;\n'
            '    if rikune_source.sha256\n'
            '        != canonical_source_digest(\n'
            '            "rikune-authz",\n'
            '            rikune_manifest.schema_version,\n'
            '            &rikune_manifest.permissions,\n'
            '        )?\n'
            '    {\n'
            '        return Err("Rikune authorization manifest source digest changed".to_string());\n'
            '    }\n'
            '    Ok(())\n}\n\nfn canonical_source_digest(',
            "Holdfast source digest validation",
        ),
        (
            '                "access-manifest" | "newapi-enterprise" | "cpa-authz" | "multica-authz"\n'
            '                | "newapi-authz" => serde_json::from_value(value["permissions"].clone()).unwrap(),\n',
            '                "access-manifest" | "newapi-enterprise" | "cpa-authz" | "multica-authz"\n'
            '                | "newapi-authz" | "cistern-authz" | "rikune-authz" => {\n'
            '                    serde_json::from_value(value["permissions"].clone()).unwrap()\n'
            '                }\n',
            "Holdfast workspace source test",
        ),
        (
            '                        Some(PermissionSourceEntry {\n'
            '                            key: key.to_string(),\n'
            '                            risk: serde_json::from_value(route.get("risk")?.clone()).ok()?,\n'
            '                        })\n',
            '                        if !seen_route_keys.insert(key.to_string()) {\n'
            '                            return None;\n'
            '                        }\n'
            '                        Some(PermissionSourceEntry {\n'
            '                            key: key.to_string(),\n'
            '                            risk: serde_json::from_value(route.get("risk")?.clone()).ok()?,\n'
            '                        })\n',
            "route source test de-duplication",
        ),
        (
            '                "sluice-routes" => value["routes"]\n',
            '                "sluice-routes" => {\n'
            '                    let mut seen_route_keys = BTreeSet::new();\n'
            '                    value["routes"]\n',
            "route source test block open",
        ),
        (
            '                    })\n'
            '                    .collect(),\n',
            '                        })\n'
            '                        .collect()\n'
            '                }\n',
            "route source test block close",
        ),
    )
    for old, new, label in changes:
        text = replace_once(text, old, new, label)
    route_chain_start = (
        '                    value["routes"]\n'
        '                    .as_array()\n'
        '                    .unwrap()\n'
        '                    .iter()\n'
        '                    .filter_map(|route| {\n'
    )
    route_chain_formatted = (
        '                    value["routes"]\n'
        '                        .as_array()\n'
        '                        .unwrap()\n'
        '                        .iter()\n'
        '                        .filter_map(|route| {\n'
    )
    text = replace_once(text, route_chain_start, route_chain_formatted, "route test formatting")
    for old, new in (
        ('                        let key = route.get("require_permission")?.as_str()?;\n', '                            let key = route.get("require_permission")?.as_str()?;\n'),
        ('                        if key.is_empty() {\n                            return None;\n                        }\n', '                            if key.is_empty() {\n                                return None;\n                            }\n'),
        ('                        if !seen_route_keys.insert(key.to_string()) {\n                            return None;\n                        }\n', '                            if !seen_route_keys.insert(key.to_string()) {\n                                return None;\n                            }\n'),
        ('                        Some(PermissionSourceEntry {\n                            key: key.to_string(),\n                            risk: serde_json::from_value(route.get("risk")?.clone()).ok()?,\n                        })\n', '                            Some(PermissionSourceEntry {\n                                key: key.to_string(),\n                                risk: serde_json::from_value(route.get("risk")?.clone()).ok()?,\n                            })\n'),
    ):
        text = replace_once(text, old, new, "route test formatting")
    path.write_text(text, encoding="utf-8")


def render_repository_package_shape(stage_root: Path) -> None:
    repository_path = stage_root / "access-governance/src/repository/postgres.rs"
    repository_text = repository_path.read_text(encoding="utf-8")
    repository_text = replace_once(
        repository_text,
        "        if snapshot.packages.len() != 8\n"
        "            || snapshot.requestable_package_count != 7\n",
        "        if snapshot.packages.len() != 9\n"
        "            || snapshot.requestable_package_count != 8\n",
        "repository package snapshot shape",
    )
    repository_path.write_text(repository_text, encoding="utf-8")


def render_packages(stage_root: Path) -> None:
    snapshot_path = stage_root / "access-governance/catalog/packages.snapshot.json"
    permission_path = stage_root / "access-governance/catalog/permissions.snapshot.json"
    snapshot = load_object(snapshot_path)
    packages = snapshot.get("packages")
    expected_ids = [
        "pkg_registered_user_baseline",
        "pkg_vpn_profile",
        "pkg_ai_developer",
        "pkg_ai_operator",
        "pkg_cpa_operator",
        "pkg_access_reviewer",
        "pkg_iga_administrator",
        "pkg_newapi_administrator",
    ]
    if not isinstance(packages, list) or [item.get("package_id") for item in packages] != expected_ids:
        fail("package snapshot precondition failed")
    members = [
        "rikune.analysis.create",
        "rikune.analysis.delete",
        "rikune.analysis.promote",
        "rikune.analysis.read",
        "rikune.console.enter",
        "rikune.conversation.use",
        "rikune.upload.cancel",
    ]
    packages.append(
        {
            "package_id": "pkg_rikune_analyst",
            "display_name": "Rikune Analyst",
            "owner_sub": "user:u_admin",
            "requestable": True,
            "requestable_version": 1,
            "approval_floor": 2,
            "max_ttl_seconds": 2592000,
            "recert_mode": "interval",
            "recert_interval_seconds": 2592000,
            "step_up_required": True,
            "risk": "critical",
            "package_sod_class": None,
            "members": members,
            "member_count": 7,
            "membership_digest": "16b3b01187d066ce7a2e3b4b8c13185cae93bc9b64ee680ccf7c62b501df4b6c",
            "policy_digest": "6cb61051c0fdfea360a3fedc9b938a63581e4358d992bb418408eaeb024cdffa",
        }
    )
    snapshot["requestable_package_count"] = 8
    snapshot["permission_catalog_sha256"] = sha256_file(permission_path)
    write_json(snapshot_path, snapshot)

    code_path = stage_root / "access-governance/src/package_catalog.rs"
    text = code_path.read_text(encoding="utf-8")
    changes = (
        ('const PACKAGE_IDS: [&str; 8] = [', 'const PACKAGE_IDS: [&str; 9] = [', "package id count"),
        (
            '    "pkg_newapi_administrator",\n];',
            '    "pkg_newapi_administrator",\n    "pkg_rikune_analyst",\n];',
            "Rikune package id",
        ),
        (
            'const EXPECTED_PACKAGES: [ExpectedPackage; 8] = [',
            'const EXPECTED_PACKAGES: [ExpectedPackage; 9] = [',
            "expected package count",
        ),
        (
            '    ExpectedPackage {\n'
            '        package_id: "pkg_newapi_administrator",\n'
            '        display_name: "NewAPI Administrator",\n'
            '        requestable: true,\n'
            '        approval_floor: Some(2),\n'
            '        max_ttl_seconds: Some(2_592_000),\n'
            '        recert_mode: RecertMode::Interval,\n'
            '        recert_interval_seconds: Some(2_592_000),\n'
            '        step_up_required: true,\n'
            '        risk: PackageRisk::Critical,\n'
            '        package_sod_class: None,\n'
            '        member_count: 131,\n'
            '        membership_digest: "6de2d3cba76a9b6e89762262c088e548d9ddd905973d0f9df9f6c30a19dc4832",\n'
            '    },\n];',
            '    ExpectedPackage {\n'
            '        package_id: "pkg_newapi_administrator",\n'
            '        display_name: "NewAPI Administrator",\n'
            '        requestable: true,\n'
            '        approval_floor: Some(2),\n'
            '        max_ttl_seconds: Some(2_592_000),\n'
            '        recert_mode: RecertMode::Interval,\n'
            '        recert_interval_seconds: Some(2_592_000),\n'
            '        step_up_required: true,\n'
            '        risk: PackageRisk::Critical,\n'
            '        package_sod_class: None,\n'
            '        member_count: 131,\n'
            '        membership_digest: "6de2d3cba76a9b6e89762262c088e548d9ddd905973d0f9df9f6c30a19dc4832",\n'
            '    },\n'
            '    ExpectedPackage {\n'
            '        package_id: "pkg_rikune_analyst",\n'
            '        display_name: "Rikune Analyst",\n'
            '        requestable: true,\n'
            '        approval_floor: Some(2),\n'
            '        max_ttl_seconds: Some(2_592_000),\n'
            '        recert_mode: RecertMode::Interval,\n'
            '        recert_interval_seconds: Some(2_592_000),\n'
            '        step_up_required: true,\n'
            '        risk: PackageRisk::Critical,\n'
            '        package_sod_class: None,\n'
            '        member_count: 7,\n'
            '        membership_digest: "16b3b01187d066ce7a2e3b4b8c13185cae93bc9b64ee680ccf7c62b501df4b6c",\n'
            '    },\n];',
            "Rikune expected package",
        ),
        ('snapshot.requestable_package_count != 7', 'snapshot.requestable_package_count != 8', "requestable field count"),
        ('            != 7\n', '            != 8\n', "requestable computed count"),
        ('frozen eight-package set', 'frozen nine-package set', "package error text"),
    )
    for old, new, label in changes:
        text = replace_once(text, old, new, label)
    code_path.write_text(text, encoding="utf-8")

    render_repository_package_shape(stage_root)

    ui_path = stage_root / "access-governance/src/handlers/ui.rs"
    ui_text = ui_path.read_text(encoding="utf-8")
    ui_changes = (
        ("        assert_eq!(targets.len(), 7);", "        assert_eq!(targets.len(), 8);", "visible package count"),
        (
            "                .count(),\n            5\n",
            "                .count(),\n            6\n",
            "step-up package count",
        ),
    )
    for old, new, label in ui_changes:
        ui_text = replace_once(ui_text, old, new, label)
    ui_path.write_text(ui_text, encoding="utf-8")


def update_env_file(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    observed: dict[str, int] = {}
    for index, line in enumerate(lines):
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if not match:
            continue
        key = match.group(1)
        if key in observed:
            fail(f"duplicate key {key} in {path}")
        observed[key] = index
    for key, value in updates.items():
        rendered = f"{key}={value}"
        if key in observed:
            lines[observed[key]] = rendered
        else:
            lines.append(rendered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


COMPOSE_SERVICES = r'''
  rikune-volume-init:
    image: ${STRAD_VOLUME_INIT_IMAGE:?STRAD_VOLUME_INIT_IMAGE immutable digest is required}
    user: "0:0"
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]
    security_opt: ["no-new-privileges:true"]
    command:
      - /bin/sh
      - -ceu
      - |
        ensure_dir() {
          target="$$1"
          uid="$$2"
          gid="$$3"
          test ! -L "$$target"
          mkdir -p "$$target"
          test "$$(readlink -f "$$target")" = "$$target"
          chown "$$uid:$$gid" "$$target"
          test "$$(stat -c '%u:%g' "$$target")" = "$$uid:$$gid"
        }
        ensure_dir /var/lib/strad/uploads 65532 65532
        ensure_dir /data/workspaces 1000 1000
        ensure_dir /data/storage 1000 1000
        ensure_dir /data/state 1000 1000
        ensure_dir /data/cache 1000 1000
        ensure_dir /data/audit 1000 1000
        ensure_dir /data/workspaces/.ghidra-projects 1000 1000
        ensure_dir /data/audit/ghidra 1000 1000
    volumes:
      - strad_uploads:/var/lib/strad/uploads
      - rikune_workspaces:/data/workspaces
      - rikune_storage:/data/storage
      - rikune_state:/data/state
      - rikune_cache:/data/cache
      - rikune_audit:/data/audit
    restart: "no"

  rikune-analyzer:
    image: ${STRAD_ANALYZER_IMAGE:?STRAD_ANALYZER_IMAGE immutable digest is required}
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      STRAD_BRIDGE_HOST: 0.0.0.0
      STRAD_BRIDGE_PORT: "18090"
      STRAD_BRIDGE_TOKEN: ${STRAD_BRIDGE_TOKEN:?STRAD_BRIDGE_TOKEN is required}
      RIKUNE_FILE_SERVER_API_KEY: ${RIKUNE_FILE_SERVER_API_KEY:?RIKUNE_FILE_SERVER_API_KEY is required}
      STRAD_BRIDGE_STATE_ROOT: /data/state
      STRAD_BRIDGE_SPOOL_ROOT: /data/storage/bridge-ingest
      RIKUNE_STATIC_LOCK_PATH: /app/static-profile.lock.json
    depends_on:
      rikune-volume-init:
        condition: service_completed_successfully
    volumes:
      - rikune_workspaces:/data/workspaces
      - rikune_storage:/data/storage
      - rikune_state:/data/state
      - rikune_cache:/data/cache
      - rikune_audit:/data/audit
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700
    networks:
      - hf-rikune
    cpus: 8
    mem_limit: 16g
    pids_limit: 2048
    stop_grace_period: 2m
    restart: unless-stopped

  strad:
    image: ${STRAD_IMAGE:?STRAD_IMAGE immutable digest is required}
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      STRAD_DATABASE_URL: ${STRAD_DATABASE_URL:?STRAD_DATABASE_URL is required}
      STRAD_BIND_ADDR: 0.0.0.0:9360
      GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY:?GATEWAY_HMAC_KEY is required}
      GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY:?GATEWAY_ZONE_HMAC_KEY is required}
      VERDICT_URL: http://verdict:9140/api/v2/check
      VERDICT_DECISION_TOKEN: ${VERDICT_DECISION_TOKEN:?VERDICT_DECISION_TOKEN is required}
      STRAD_BRIDGE_URL: http://rikune-analyzer:18090
      STRAD_BRIDGE_TOKEN: ${STRAD_BRIDGE_TOKEN:?STRAD_BRIDGE_TOKEN is required}
      RIKUNE_FILE_SERVER_API_KEY: ${RIKUNE_FILE_SERVER_API_KEY:?RIKUNE_FILE_SERVER_API_KEY is required}
      STRAD_NEWAPI_URL: http://newapi:9080/v1/chat/completions
      STRAD_NEWAPI_KEY: ${STRAD_NEWAPI_KEY:?STRAD_NEWAPI_KEY is required}
      STRAD_NEWAPI_MODEL: ${STRAD_NEWAPI_MODEL:?STRAD_NEWAPI_MODEL is required}
      STRAD_NEWAPI_CONTEXT_TOKENS: ${STRAD_NEWAPI_CONTEXT_TOKENS:?STRAD_NEWAPI_CONTEXT_TOKENS is required}
      STRAD_TOKENIZER_VOCAB_SHA256: ${STRAD_TOKENIZER_VOCAB_SHA256:?STRAD_TOKENIZER_VOCAB_SHA256 is required}
      STRAD_UPLOAD_ROOT: /var/lib/strad/uploads
      STRAD_TEMPLATE_ROOT: /app/templates
    depends_on:
      postgres:
        condition: service_healthy
      newapi:
        condition: service_healthy
      rikune-analyzer:
        condition: service_healthy
      verdict:
        condition: service_started
    volumes:
      - strad_uploads:/var/lib/strad/uploads
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=128m,uid=65532,gid=65532,mode=0700
    networks:
      - steadholme
      - hf-rikune
      - hf-rikune-authz
    cpus: 2
    mem_limit: 2g
    pids_limit: 256
    stop_grace_period: 2m
    restart: unless-stopped

'''


def render_compose(stage_root: Path) -> None:
    path = stage_root / "deploy/docker-compose.yml"
    text = path.read_text(encoding="utf-8")
    if any(f"  {name}:" in text for name in ("strad", "rikune-analyzer", "rikune-volume-init")):
        fail("Rikune services already exist in Compose")
    text = replace_service(
        text,
        "sluice",
        (
            ("GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}", "GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY:?GATEWAY_HMAC_KEY is required}"),
            ("GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}", "GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY:?GATEWAY_ZONE_HMAC_KEY is required}"),
        ),
    )
    text = replace_service(
        text,
        "sluice-internal",
        (
            ("GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}", "GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY:?GATEWAY_HMAC_KEY is required}"),
            ("GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}", "GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY:?GATEWAY_ZONE_HMAC_KEY is required}"),
        ),
    )
    text = replace_service(
        text,
        "newapi",
        (
            (
                "image: steadholme/newapi@sha256:b864dc5a347c91ee60b5bab045fefc60f116bda75eb4c695d0c1305ef4981a7f",
                "image: ${NEWAPI_IMAGE:?NEWAPI_IMAGE immutable digest is required}",
            ),
            (
                "RELAY_SERVICE_KEYS: grimoire=${GRIMOIRE_RELAY_KEY},familiar=${FAMILIAR_RELAY_KEY},warden=${WARDEN_RELAY_KEY},canvas=${CANVAS_RELAY_KEY}",
                "RELAY_SERVICE_KEYS: grimoire=${GRIMOIRE_RELAY_KEY},familiar=${FAMILIAR_RELAY_KEY},warden=${WARDEN_RELAY_KEY},canvas=${CANVAS_RELAY_KEY},strad=${STRAD_NEWAPI_KEY:?STRAD_NEWAPI_KEY is required}",
            ),
        ),
    )
    text = replace_service(
        text,
        "verdict",
        (
            (
                "image: steadholme/verdict:web-assets-20260821",
                "image: ${VERDICT_IMAGE:?VERDICT_IMAGE immutable digest is required}",
            ),
            (
                "      - hf-cpa-mgmt\n",
                "      - hf-cpa-mgmt\n      - hf-rikune-authz\n",
            ),
        ),
    )
    for sluice_service in ("sluice", "sluice-internal"):
        text = replace_service(
            text,
            sluice_service,
            ((
                "image: steadholme/sluice:share-room-assets-20260821",
                "image: ${SLUICE_IMAGE:?SLUICE_IMAGE immutable digest is required}",
            ),),
        )
    text = replace_service(
        text,
        "access-governance",
        (
            (
                "    build:\n      context: ../access-governance\n    image: steadholme/access-governance:uiux-20260823-r2",
                "    image: ${ACCESS_GOVERNANCE_IMAGE:?ACCESS_GOVERNANCE_IMAGE immutable digest is required}",
            ),
            ("GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY}", "GATEWAY_HMAC_KEY: ${GATEWAY_HMAC_KEY:?GATEWAY_HMAC_KEY is required}"),
            ("GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY}", "GATEWAY_ZONE_HMAC_KEY: ${GATEWAY_ZONE_HMAC_KEY:?GATEWAY_ZONE_HMAC_KEY is required}"),
            (
                "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION: ${ACCESS_GOVERNANCE_BOOTSTRAP_VERSION:-5}",
                "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION: ${ACCESS_GOVERNANCE_BOOTSTRAP_VERSION:-7}",
            ),
        ),
    )
    text = replace_once(text, "\n  ark:\n", "\n" + COMPOSE_SERVICES + "  ark:\n", "Compose service insertion")
    network_marker = "  # Access capability snapshots are shared only with managed downstream PEPs.\n  hf-iga:\n    driver: bridge\n    internal: true\n"
    network_add = network_marker + (
        "  # Strad is the only caller shared with the analyzer and Verdict PEP.\n"
        "  hf-rikune:\n    driver: bridge\n    internal: true\n"
        "  hf-rikune-authz:\n    driver: bridge\n    internal: true\n"
    )
    text = replace_once(text, network_marker, network_add, "Rikune network insertion")
    text = replace_once(
        text,
        "volumes:\n  pgdata:\n",
        "volumes:\n"
        "  strad_uploads:\n"
        "  rikune_workspaces:\n"
        "  rikune_storage:\n"
        "  rikune_state:\n"
        "  rikune_cache:\n"
        "  rikune_audit:\n"
        "  pgdata:\n",
        "Rikune volume insertion",
    )
    if text.count("${STRAD_ANALYZER_IMAGE:") != 1:
        fail("Compose must consume the Strad analyzer overlay exactly once")
    if "${RIKUNE_ANALYZER_IMAGE" in text:
        fail("Compose must never run the upstream Rikune base image directly")
    path.write_text(text, encoding="utf-8")


def render_full_env(stage_root: Path, release: dict[str, str], secrets: dict[str, str]) -> None:
    env_path = stage_root / "deploy/.env"
    current = parse_env(env_path, allow_empty=True)
    missing_existing = [key for key in ("GATEWAY_HMAC_KEY", "GATEWAY_ZONE_HMAC_KEY", "VERDICT_DECISION_TOKEN") if not current.get(key)]
    if missing_existing:
        fail(f"live deploy env lacks existing required keys: {', '.join(missing_existing)}")
    missing_secrets = [key for key in SECRET_KEYS if not secrets.get(key) or secrets[key].startswith("REQUIRED")]
    if missing_secrets:
        fail(f"secret env lacks provisioned keys: {', '.join(missing_secrets)}")
    compared = {
        "GATEWAY_HMAC_KEY": current["GATEWAY_HMAC_KEY"],
        "GATEWAY_ZONE_HMAC_KEY": current["GATEWAY_ZONE_HMAC_KEY"],
        "VERDICT_DECISION_TOKEN": current["VERDICT_DECISION_TOKEN"],
        "STRAD_BRIDGE_TOKEN": secrets["STRAD_BRIDGE_TOKEN"],
        "RIKUNE_FILE_SERVER_API_KEY": secrets["RIKUNE_FILE_SERVER_API_KEY"],
        "STRAD_NEWAPI_KEY": secrets["STRAD_NEWAPI_KEY"],
    }
    if any(len(value.encode("utf-8")) < 32 for value in compared.values()):
        fail("all Strad/gateway/Verdict secrets must be at least 32 UTF-8 bytes")
    if len(set(compared.values())) != len(compared):
        fail("Strad/gateway/Verdict secrets must be pairwise distinct")
    updates = {
        "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION": "7",
        "ACCESS_GOVERNANCE_IMAGE": release["ACCESS_GOVERNANCE_IMAGE"],
        "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": release["ACCESS_GOVERNANCE_ROLLBACK_IMAGE"],
        "RIKUNE_ANALYZER_IMAGE": release["RIKUNE_ANALYZER_IMAGE"],
        "STRAD_ANALYZER_IMAGE": release["STRAD_ANALYZER_IMAGE"],
        "STRAD_IMAGE": release["STRAD_IMAGE"],
        "STRAD_VOLUME_INIT_IMAGE": release["STRAD_VOLUME_INIT_IMAGE"],
        "VERDICT_IMAGE": release["VERDICT_IMAGE"],
        "NEWAPI_IMAGE": release["NEWAPI_IMAGE"],
        "SLUICE_IMAGE": release["SLUICE_IMAGE"],
        "STRAD_NEWAPI_MODEL": release["STRAD_NEWAPI_MODEL"],
        "STRAD_NEWAPI_CONTEXT_TOKENS": "32768",
        "STRAD_TOKENIZER_VOCAB_SHA256": "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7",  # gitleaks:allow
        **secrets,
    }
    update_env_file(env_path, updates)
    os.chmod(env_path, 0o600)
    example = stage_root / "deploy/access-governance.env.example"
    example_text = example.read_text(encoding="utf-8")
    bootstrap_v1 = "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION=1"
    bootstrap_v7 = "ACCESS_GOVERNANCE_BOOTSTRAP_VERSION=7"
    if example_text.count(bootstrap_v7) == 1 and bootstrap_v1 not in example_text:
        rendered_example = example_text
    else:
        rendered_example = replace_once(
            example_text,
            bootstrap_v1,
            bootstrap_v7,
            "bootstrap example",
        )
    example.write_text(rendered_example, encoding="utf-8")


def run_checked(args: list[str], cwd: Path) -> None:
    completed = subprocess.run(args, cwd=cwd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        fail(f"command failed ({completed.returncode}): {' '.join(args)}")


def validate_static_targets(
    stage_root: Path, catalog_only: bool, successor: bool = False
) -> None:
    manifest = (
        "successor-static-targets.sha256" if successor else "static-targets.sha256"
    )
    frozen = parse_checksum_manifest(OPS_ROOT / manifest)
    if set(frozen) != set(FROZEN_STATIC_PATHS):
        fail("static target manifest field set differs from the renderer contract")
    paths = MUTATED_PATHS if catalog_only else FROZEN_STATIC_PATHS
    for relative in paths:
        observed = sha256_file(stage_root / relative)
        if observed != frozen[relative]:
            fail(
                f"rendered static target drift for {relative}: "
                f"expected {frozen[relative]}, got {observed}"
            )


def validate_render(
    stage_root: Path, catalog_only: bool, successor: bool = False
) -> None:
    access = stage_root / "access-governance"
    run_checked([sys.executable, "scripts/validate_authz_manifests.py"], access)
    run_checked(["scripts/generate_permission_catalog.sh", "--check"], access)
    for relative in MUTATED_PATHS:
        require_regular(stage_root / relative)
    validate_static_targets(stage_root, catalog_only, successor)


def validate_frozen_evidence(
    evidence: dict[str, object], successor: bool = False
) -> None:
    frozen_name = (
        "successor-frozen-targets.json" if successor else "frozen-targets.json"
    )
    frozen = load_object(OPS_ROOT / frozen_name)
    expected_schema = 2 if successor else 1
    expected_generator = SUCCESSOR_GENERATOR_VERSION if successor else GENERATOR_VERSION
    if (
        frozen.get("schema_version") != expected_schema
        or frozen.get("generator") != expected_generator
    ):
        fail("frozen target contract version differs from the renderer")
    for key in (
        "permission_catalog_sha256",
        "package_catalog_sha256",
        "access_governance_build_input_sha256",
        "route_up_sha256",
        "route_down_sha256",
        "authz_manifest_sha256",
    ):
        if evidence.get(key) != frozen.get(key):
            fail(f"release evidence differs from frozen target: {key}")
    if successor and (
        frozen.get("access_governance_build_input_schema") != BUILD_INPUT_SCHEMA_V2
        or evidence.get("access_governance_build_input_schema")
        != BUILD_INPUT_SCHEMA_V2
    ):
        fail("successor build-input schema differs from the frozen target")


def write_evidence(
    stage_root: Path,
    release: dict[str, str],
    catalog_only: bool,
    release_env_sha256: str | None,
    successor_context: dict[str, object] | None = None,
    release_tool_revision: str | None = None,
) -> None:
    successor = successor_context is not None
    if successor:
        policy = successor_context.get("policy")
        if not isinstance(policy, dict) or not isinstance(policy.get("overlay"), list):
            fail("successor evidence lacks its validated policy")
        paths = [item["path"] for item in policy["overlay"]]
        supporting_paths = MUTATED_PATHS if catalog_only else FROZEN_STATIC_PATHS
        paths.extend(relative for relative in supporting_paths if relative not in paths)
        if not catalog_only and "deploy/.env" not in paths:
            paths.append("deploy/.env")
        delta_path = write_delta_manifest(stage_root, policy)
    else:
        policy = None
        paths = list(MUTATED_PATHS) + ([] if catalog_only else list(FULL_ONLY_PATHS))
        delta_path = None
    targets = stage_root / "TARGETS.sha256"
    lines = [f"{sha256_file(stage_root / relative)}  {relative}" for relative in paths]
    targets.write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_apply_manifests(stage_root, paths, successor)
    write_binding(
        OPS_ROOT, stage_root / "RENDER-INPUTS.sha256", successor=successor
    )
    permission_digest = sha256_file(stage_root / "access-governance/catalog/permissions.snapshot.json")
    package_digest = sha256_file(stage_root / "access-governance/catalog/packages.snapshot.json")
    build_input = (
        access_build_input_sha_v2(stage_root)
        if successor
        else access_build_input_sha(stage_root)
    )
    schema_version = 2 if successor else 1
    generator = SUCCESSOR_GENERATOR_VERSION if successor else GENERATOR_VERSION
    release_keys = SUCCESSOR_RELEASE_KEYS if successor else RELEASE_KEYS
    evidence = {
        "schema_version": schema_version,
        "generator": generator,
        "catalog_only": catalog_only,
        "permission_catalog_sha256": permission_digest,
        "package_catalog_sha256": package_digest,
        "access_governance_build_input_sha256": build_input,
        "route_up_sha256": sha256_file(ASSETS / "20260823_rikune_root_up.sql"),
        "route_down_sha256": sha256_file(ASSETS / "20260823_rikune_root_down.sql"),
        "authz_manifest_sha256": sha256_file(stage_root / "access-governance/catalog/rikune-authz-v1.json"),
        "secret_references": list(SECRET_KEYS),
        "release": {} if catalog_only else {key: release[key] for key in release_keys},
    }
    if successor:
        if release_tool_revision is None or not HEX40.fullmatch(release_tool_revision):
            fail("successor evidence lacks the release tool revision")
        predecessor = policy.get("predecessor") if policy is not None else None
        if not isinstance(predecessor, dict):
            fail("successor evidence lacks the predecessor binding")
        evidence.update(
            {
                "release_mode": "successor",
                "access_governance_build_input_schema": BUILD_INPUT_SCHEMA_V2,
                "holdfast_release_tool_revision": release_tool_revision,
                "predecessor_binding": dict(predecessor),
                "successor_delta_sha256": sha256_file(delta_path),
            }
        )
    if not catalog_only:
        if release_env_sha256 is None or not HEX64.fullmatch(release_env_sha256):
            fail("full release evidence lacks the release env identity")
        evidence["release_env_sha256"] = release_env_sha256
        evidence["supply_chain_binding"] = {
            "evidence_sha256": release["SUPPLY_CHAIN_EVIDENCE_SHA256"],
            "signature_sha256": release["SUPPLY_CHAIN_SIGNATURE_SHA256"],
            "public_key_sha256": release["SUPPLY_CHAIN_PUBLIC_KEY_SHA256"],
            "platform": "linux/amd64",
        }
        analyzer_dockerfile = STRAD_ROOT / "Dockerfile.analyzer"
        bridge_lock = STRAD_ROOT / "bridge/package-lock.json"
        require_regular(analyzer_dockerfile)
        require_regular(bridge_lock)
        evidence["analyzer_image_binding"] = {
            "schema_version": 1,
            "relation": "strad-bridge-overlay-built-from-rikune-static-base",
            "base_build_arg": "RIKUNE_ANALYZER_IMAGE",
            "base_image": release["RIKUNE_ANALYZER_IMAGE"],
            "overlay_image": release["STRAD_ANALYZER_IMAGE"],
            "dockerfile": "strad/Dockerfile.analyzer",
            "dockerfile_sha256": sha256_file(analyzer_dockerfile),
            "bridge_lock": "strad/bridge/package-lock.json",
            "bridge_lock_sha256": sha256_file(bridge_lock),
            "source_revision": release["STRAD_REVISION"],
        }
        if permission_digest != release["PERMISSION_CATALOG_SHA256"]:
            fail("rendered permission catalog digest differs from the frozen release pin")
        if package_digest != release["PACKAGE_CATALOG_SHA256"]:
            fail("rendered package catalog digest differs from the frozen release pin")
        if build_input != release["ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"]:
            fail("Access Governance build-input digest differs from the frozen release pin")
    validate_frozen_evidence(evidence, successor)
    write_json(stage_root / "RELEASE-EVIDENCE.json", evidence)


def validate_successor_release(
    release: dict[str, str], policy: dict[str, object]
) -> None:
    predecessor = policy.get("predecessor")
    successor = policy.get("successor")
    if not isinstance(predecessor, dict) or not isinstance(successor, dict):
        fail("successor policy release binding is malformed")
    expected = {
        "ACCESS_GOVERNANCE_ROLLBACK_IMAGE": predecessor.get("access_image"),
        "ACCESS_GOVERNANCE_BUILD_INPUT_SHA256": successor.get(
            "access_build_input_sha256"
        ),
        "PERMISSION_CATALOG_SHA256": predecessor.get(
            "permission_catalog_sha256"
        ),
        "PACKAGE_CATALOG_SHA256": predecessor.get("package_catalog_sha256"),
    }
    for key, value in expected.items():
        if release.get(key) != value:
            fail(f"successor release pin differs from its policy: {key}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--estate-root", required=True, type=Path)
    parser.add_argument("--stage-root", required=True, type=Path)
    parser.add_argument("--release-env", type=Path)
    parser.add_argument("--secret-env", type=Path)
    parser.add_argument("--catalog-only", action="store_true")
    parser.add_argument("--successor", action="store_true")
    parser.add_argument("--current-state", type=Path)
    parser.add_argument("--predecessor-candidate", type=Path)
    parser.add_argument("--predecessor-stage", type=Path)
    parser.add_argument("--release-tool-revision")
    args = parser.parse_args()

    estate_root = args.estate_root.absolute()
    stage_root = args.stage_root.absolute()
    estate_mode = estate_root.lstat()
    if (
        estate_root == Path("/")
        or not stat.S_ISDIR(estate_mode.st_mode)
        or estate_root.is_symlink()
        or estate_root.resolve() != estate_root
        or not (estate_root / "access-governance").is_dir()
    ):
        fail("estate root is invalid")
    stage_parent = stage_root.parent
    parent_mode = stage_parent.lstat()
    if (
        not stat.S_ISDIR(parent_mode.st_mode)
        or stage_parent.is_symlink()
        or stage_parent.resolve() != stage_parent
    ):
        fail("stage parent is invalid")
    successor_args = (
        args.current_state,
        args.predecessor_candidate,
        args.predecessor_stage,
    )
    if args.successor and any(value is None for value in successor_args):
        fail(
            "--successor requires --current-state, --predecessor-candidate "
            "and --predecessor-stage"
        )
    if not args.successor and (
        any(value is not None for value in successor_args)
        or args.release_tool_revision is not None
    ):
        fail("successor-only arguments require --successor")

    successor_context: dict[str, object] | None = None
    if args.successor:
        successor_context = validate_predecessor(
            policy_path=OPS_ROOT / "successor-policy.json",
            current_state_path=args.current_state.absolute(),
            estate_root=estate_root,
            predecessor_candidate=args.predecessor_candidate.absolute(),
            predecessor_stage=args.predecessor_stage.absolute(),
            successor_preimages=OPS_ROOT / "successor-preimages.sha256",
        )
    else:
        verify_preimages(estate_root)
    release_env_sha256: str | None = None
    if args.release_env is None:
        release = {}
    elif args.successor and not args.catalog_only:
        release, release_env_sha256 = read_private_env_snapshot(
            args.release_env, "release"
        )
    else:
        release = parse_env(args.release_env.absolute())
        release_env_sha256 = sha256_file(args.release_env.absolute())
    validate_release(release, args.catalog_only, args.successor)
    if not args.catalog_only and args.secret_env is None:
        fail("--secret-env is required for a full render")
    if args.catalog_only:
        secrets = {}
    elif args.successor:
        secrets, _ = read_private_env_snapshot(args.secret_env, "secret")
    else:
        secrets = parse_env(args.secret_env.absolute(), require_mode_0600=True)

    release_tool_revision: str | None = None
    if args.successor:
        release_tool_revision = (
            args.release_tool_revision
            if args.catalog_only
            else release["HOLDFAST_RELEASE_TOOL_REVISION"]
        )
        if release_tool_revision is None:
            fail("successor catalog render requires --release-tool-revision")
        if (
            args.release_tool_revision is not None
            and args.release_tool_revision != release_tool_revision
        ):
            fail("successor tool revision arguments differ")
        validate_tool_revision(release_tool_revision)
        assert successor_context is not None
        policy = successor_context["policy"]
        if not isinstance(policy, dict):
            fail("successor policy validation returned an invalid value")
        if not args.catalog_only:
            validate_successor_release(release, policy)
        successor_preimages = successor_context.get("successor_preimages")
        if not isinstance(successor_preimages, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in successor_preimages.items()
        ):
            fail("successor validation returned invalid preimage authority")
        static_targets = successor_context.get("successor_static_targets")
        if not isinstance(static_targets, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in static_targets.items()
        ):
            fail("successor validation returned invalid static target authority")
        supporting_targets = successor_context.get("successor_supporting_targets")
        if not isinstance(supporting_targets, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in supporting_targets.items()
        ):
            fail("successor validation returned invalid supporting authority")
        copy_successor_stage(
            estate_root,
            successor_context["predecessor_candidate"],
            stage_root,
            args.catalog_only,
            policy,
            successor_preimages,
            static_targets,
            OPS_ROOT,
        )
        validate_successor_snapshot(
            stage_root,
            policy,
            successor_preimages,
            supporting_targets,
            args.catalog_only,
        )
        validate_predecessor(
            policy_path=OPS_ROOT / "successor-policy.json",
            current_state_path=args.current_state.absolute(),
            estate_root=estate_root,
            predecessor_candidate=args.predecessor_candidate.absolute(),
            predecessor_stage=args.predecessor_stage.absolute(),
            successor_preimages=OPS_ROOT / "successor-preimages.sha256",
        )
        if not args.catalog_only:
            render_full_env(stage_root, release, secrets)
    else:
        copy_stage(estate_root, stage_root, args.catalog_only)
        for manifest in ("cistern-authz-v1.json", "rikune-authz-v1.json"):
            shutil.copy2(ASSETS / manifest, stage_root / f"access-governance/catalog/{manifest}")
        render_registry(stage_root)
        render_generator(stage_root)
        render_validator(stage_root)
        render_catalog_rs(stage_root)
        generator = stage_root / "access-governance/scripts/generate_permission_catalog.sh"
        run_checked([str(generator)], stage_root / "access-governance")
        render_packages(stage_root)
        if not args.catalog_only:
            render_compose(stage_root)
            render_full_env(stage_root, release, secrets)
    validate_render(stage_root, args.catalog_only, args.successor)
    write_evidence(
        stage_root,
        release,
        args.catalog_only,
        release_env_sha256,
        successor_context,
        release_tool_revision,
    )
    run_checked(
        [
            sys.executable,
            str(OPS_ROOT / "validate_release_evidence.py"),
            "--evidence",
            str(stage_root / "RELEASE-EVIDENCE.json"),
        ],
        OPS_ROOT,
    )
    print(f"rendered immutable staging tree: {stage_root}")
    print(f"release evidence: {stage_root / 'RELEASE-EVIDENCE.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
