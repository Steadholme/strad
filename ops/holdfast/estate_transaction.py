#!/usr/bin/env python3
"""Crash-auditable, checksum-bound estate file transaction and mixed-state restore."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import NoReturn


LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def regular(path: Path) -> bool:
    try:
        mode = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode.st_mode) and not path.is_symlink() and mode.st_nlink == 1


def manifest(path: Path) -> dict[str, str]:
    if not regular(path):
        fail(f"unsafe checksum manifest: {path}")
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = LINE.fullmatch(line)
        if not match:
            fail(f"invalid checksum manifest line {number}: {path}")
        relative = match.group(2)
        if relative.startswith("/") or ".." in Path(relative).parts or relative in result:
            fail(f"unsafe or duplicate manifest path: {relative}")
        result[relative] = match.group(1)
    if not result:
        fail(f"empty checksum manifest: {path}")
    return result


def absent_paths(path: Path) -> set[str]:
    if not regular(path):
        fail(f"unsafe absent-path manifest: {path}")
    values: set[str] = set()
    for relative in path.read_text(encoding="utf-8").splitlines():
        if not relative:
            continue
        if (
            not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in values
        ):
            fail(f"unsafe or duplicate absent path: {relative}")
        values.add(relative)
    return values


def safe_root(path: Path, must_exist: bool = True) -> Path:
    if not path.is_absolute() or path == Path("/"):
        fail(f"unsafe root: {path}")
    if must_exist:
        mode = path.lstat()
        if not stat.S_ISDIR(mode.st_mode) or path.is_symlink() or path.resolve() != path:
            fail(f"unsafe root directory: {path}")
    return path


def target_path(root: Path, relative: str) -> Path:
    target = root / relative
    parent = target.parent
    resolved_parent = parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        fail(f"target parent escapes estate: {relative}")
    parent_mode = parent.lstat()
    if not stat.S_ISDIR(parent_mode.st_mode) or parent.is_symlink():
        fail(f"unsafe target parent: {relative}")
    return target


def fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_copy(source: Path, target: Path) -> None:
    if not regular(source):
        fail(f"unsafe source file: {source}")
    mode = stat.S_IMODE(source.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".holdfast-transaction-", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, target)
        fsync_dir(target.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def durable_unlink(target: Path) -> None:
    target.unlink()
    fsync_dir(target.parent)


def disposition(path: Path, expected_digest: str | None) -> str:
    if not path.exists() and not path.is_symlink():
        return "absent"
    if not regular(path):
        return "unsafe"
    observed = digest(path)
    return "expected" if expected_digest is not None and observed == expected_digest else observed


def write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    fsync_dir(path.parent)


def verify_preimage(
    estate: Path, targets: dict[str, str], preimages: dict[str, str], absent: set[str]
) -> None:
    if set(targets) != set(preimages) | absent or set(preimages) & absent:
        fail("preimage and absent manifests do not exactly cover the apply targets")
    for relative in targets:
        target = target_path(estate, relative)
        if relative in preimages:
            if disposition(target, preimages[relative]) != "expected":
                fail(f"preimage drift: {relative}")
        elif target.exists() or target.is_symlink():
            fail(f"expected-absent target exists: {relative}")


def snapshot(
    estate: Path,
    backup: Path,
    targets: dict[str, str],
    preimages: dict[str, str],
    absent: set[str],
) -> None:
    if backup.exists() or backup.is_symlink():
        fail(f"backup already exists: {backup}")
    backup.mkdir(mode=0o700, parents=False)
    tree = backup / "tree"
    tree.mkdir(mode=0o700)
    for relative in targets:
        source = target_path(estate, relative)
        if relative in preimages:
            destination = tree / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
            if digest(destination) != preimages[relative]:
                fail(f"backup copy verification failed: {relative}")
            fsync_file(destination)
    (backup / "ABSENT.before").write_text(
        "".join(f"{item}\n" for item in sorted(absent)), encoding="utf-8"
    )
    (backup / "PREIMAGES.sha256").write_text(
        "".join(f"{value}  {item}\n" for item, value in preimages.items()),
        encoding="utf-8",
    )
    (backup / "APPLIED-TARGETS.sha256").write_text(
        "".join(f"{value}  {item}\n" for item, value in targets.items()),
        encoding="utf-8",
    )
    for name in ("ABSENT.before", "PREIMAGES.sha256", "APPLIED-TARGETS.sha256"):
        os.chmod(backup / name, 0o600)
        fsync_file(backup / name)
    fsync_dir(tree)
    fsync_dir(backup)


def restore_mixed(estate: Path, backup: Path) -> None:
    targets = manifest(backup / "APPLIED-TARGETS.sha256")
    preimages = manifest(backup / "PREIMAGES.sha256")
    absent = absent_paths(backup / "ABSENT.before")
    if set(targets) != set(preimages) | absent:
        fail("backup dispositions do not exactly cover applied targets")
    for relative, expected in preimages.items():
        backup_file = backup / "tree" / relative
        if not regular(backup_file) or digest(backup_file) != expected:
            fail(f"backup tree checksum mismatch: {relative}")
    for relative, applied_digest in targets.items():
        target = target_path(estate, relative)
        state = disposition(target, applied_digest)
        allowed = {"expected"}
        if relative in preimages:
            old = disposition(target, preimages[relative])
            if old == "expected":
                state = "preimage"
            allowed.add("preimage")
        else:
            allowed.add("absent")
        if state not in allowed:
            fail(f"mixed estate contains third-party drift: {relative}")

    for relative in targets:
        target = target_path(estate, relative)
        if relative in preimages:
            atomic_copy(backup / "tree" / relative, target)
        elif target.exists() and not target.is_symlink():
            if not regular(target):
                fail(f"unsafe applied target during restore: {relative}")
            durable_unlink(target)
        elif target.is_symlink():
            fail(f"unsafe applied symlink during restore: {relative}")
    verify_preimage(estate, targets, preimages, absent)


def apply_transaction(args: argparse.Namespace) -> None:
    # Preserve the caller-visible path for lstat/realpath checks.  Resolving
    # first would turn a symlinked root into an apparently safe directory.
    estate = safe_root(args.estate_root.absolute())
    stage = safe_root(args.stage_root.absolute())
    backup = safe_root(args.backup_dir.absolute(), must_exist=False)
    targets = manifest(args.targets.absolute())
    preimages = manifest(args.preimages.absolute())
    absent = absent_paths(args.absent.absolute())
    for relative, expected in targets.items():
        source = target_path(stage, relative)
        if disposition(source, expected) != "expected":
            fail(f"staged target checksum mismatch: {relative}")
    verify_preimage(estate, targets, preimages, absent)
    snapshot(estate, backup, targets, preimages, absent)
    write_json(backup / "TRANSACTION.json", {"schema_version": 1, "state": "prepared"})
    fault_after = args.test_fault_after
    if fault_after is not None and os.environ.get("HOLDFAST_TEST_MODE") != "1":
        fail("fault injection is test-only")
    try:
        for index, (relative, expected) in enumerate(targets.items(), 1):
            atomic_copy(target_path(stage, relative), target_path(estate, relative))
            if disposition(target_path(estate, relative), expected) != "expected":
                fail(f"post-install checksum mismatch: {relative}")
            if fault_after is not None and index == fault_after:
                fail("injected partial-apply failure")
        write_json(
            backup / "TRANSACTION.json",
            {"schema_version": 1, "state": "applied", "target_count": len(targets)},
        )
    except Exception as apply_error:
        try:
            restore_mixed(estate, backup)
            write_json(
                backup / "TRANSACTION.json",
                {
                    "schema_version": 1,
                    "state": "rolled_back_after_failure",
                    "error": str(apply_error),
                },
            )
        except Exception as recovery_error:
            write_json(
                backup / "RECOVERY-REQUIRED.json",
                {
                    "schema_version": 1,
                    "apply_error": str(apply_error),
                    "recovery_error": str(recovery_error),
                },
            )
            raise RuntimeError(
                f"apply failed and automatic recovery failed: {recovery_error}"
            ) from apply_error
        raise RuntimeError(f"apply failed and was automatically rolled back: {apply_error}")


def restore_transaction(args: argparse.Namespace) -> None:
    estate = safe_root(args.estate_root.absolute())
    backup = safe_root(args.backup_dir.absolute())
    restore_mixed(estate, backup)
    write_json(
        backup / "TRANSACTION.json",
        {"schema_version": 1, "state": "restored", "mixed_estate_supported": True},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--estate-root", required=True, type=Path)
    apply_parser.add_argument("--stage-root", required=True, type=Path)
    apply_parser.add_argument("--targets", required=True, type=Path)
    apply_parser.add_argument("--preimages", required=True, type=Path)
    apply_parser.add_argument("--absent", required=True, type=Path)
    apply_parser.add_argument("--backup-dir", required=True, type=Path)
    apply_parser.add_argument("--test-fault-after", type=int)
    apply_parser.set_defaults(handler=apply_transaction)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--estate-root", required=True, type=Path)
    restore_parser.add_argument("--backup-dir", required=True, type=Path)
    restore_parser.set_defaults(handler=restore_transaction)
    args = parser.parse_args()
    try:
        args.handler(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"estate transaction: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
