#!/usr/bin/env python3
"""Issue and verify exact signed Holdfast recovery-completion attestations."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn


ATTESTATION_NAME = "RECOVERY-COMPLETION-ATTESTATION.json"
SIGNATURE_NAME = "RECOVERY-COMPLETION-ATTESTATION.sig"
PUBLIC_KEY_NAME = "RECOVERY-COMPLETION-ATTESTATION.pub"
PENDING_NAMES = {
    PUBLIC_KEY_NAME: f".{PUBLIC_KEY_NAME}.pending",
    ATTESTATION_NAME: f".{ATTESTATION_NAME}.pending",
    SIGNATURE_NAME: f".{SIGNATURE_NAME}.pending",
}
KIND = "recovery-completion-attestation-v1"
CEREMONY = "holdfast-rikune-recovery-completion-v1"
SIGNATURE_ALGORITHM = "rsa-pkcs1v15-sha256"
CANONICALIZATION_ALGORITHM = "json-sort-keys-utf8-no-whitespace-lf-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9]+$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
EXPECTED_FIELDS = {
    "schema_version",
    "kind",
    "ceremony",
    "signature_algorithm",
    "canonicalization_algorithm",
    "issued_at",
    "mode",
    "successor",
    "recovery_schema_version",
    "recovery_attempt_id",
    "recovery_prior_state",
    "prior_failure_kind",
    "prior_failure_receipt",
    "prior_failure_receipt_sha256",
    "apply_armed_at",
    "recovery_armed_at",
    "recovery_completed_at",
    "estate_root",
    "backup_dir",
    "current_file",
    "current_sha256",
    "completion_receipt",
    "completion_receipt_sha256",
    "completion_archive",
    "completion_archive_sha256",
    "recovery_armed_receipt",
    "recovery_armed_receipt_sha256",
    "control_file",
    "control_sha256",
    "release_env_file",
    "release_env_sha256",
    "release_evidence_file",
    "release_evidence_sha256",
    "transaction_file",
    "transaction_sha256",
    "applied_targets_file",
    "applied_targets_sha256",
    "runtime_backup_schema",
    "runtime_receipt_file",
    "runtime_receipt_sha256",
    "runtime_manifest_file",
    "runtime_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "services_activated",
    "runtime_verified",
    "route_database_state",
    "public_ipv4_ipv6_closed_status",
    "db_public_db_bracket",
    "ingress_opened",
    "apply_receipt_created",
    "public_key_sha256",
}
HISTORICAL_APPLY_ARMED_KEYS = (
    "schema_version",
    "armed_at",
    "estate_root",
    "backup_dir",
    "dry_run_dir",
    "release_env_sha256",
    "release_evidence_sha256",
    "dry_run_receipt_sha256",
    "targets_sha256",
    "apply_preimages_sha256",
    "apply_absent_sha256",
    "render_inputs_sha256",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
    "runtime_backup_caller_armed_sha256",
    "runtime_backup_stop_authority_sha256",
    "ingress_opened",
    "successor",
    "successor_armed_receipt",
    "successor_armed_receipt_sha256",
    "predecessor_current_file",
    "predecessor_current_sha256",
    "predecessor_backup_dir",
    "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation",
    "release_generation",
    "runtime_backup_receipt_sha256",
    "runtime_backup_manifest_sha256",
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {json.dumps(key, ensure_ascii=True)}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def parse_canonical_document(raw: bytes) -> dict[str, Any]:
    if b"\r" in raw:
        fail("attestation must not contain CR or CRLF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"attestation is not UTF-8: {error}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        fail(f"attestation is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail("attestation root must be an object")
    if raw != canonical_bytes(value):
        fail("attestation is not exact canonical JSON")
    validate_document(value)
    return value


def require_hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")
    return value


def require_absolute_canonical(value: object, label: str) -> str:
    if not isinstance(value, str) or CONTROL_CHARACTER.search(value):
        fail(f"{label} must be a canonical absolute path")
    if not os.path.isabs(value) or value == "/" or os.path.normpath(value) != value:
        fail(f"{label} must be a canonical absolute path")
    return value


def require_rfc3339_utc(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        fail(f"{label} must be an RFC3339 UTC timestamp")
    return parsed


def validate_document(value: dict[str, Any]) -> None:
    if set(value) != EXPECTED_FIELDS:
        fail("attestation field set is not exact")
    if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
        fail("attestation schema_version must equal 1")
    if value["successor"] is not True:
        fail("successor differs from the frozen recovery-completion contract")
    constants = {
        "kind": KIND,
        "ceremony": CEREMONY,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "canonicalization_algorithm": CANONICALIZATION_ALGORITHM,
        "mode": "resume",
        "successor": True,
        "recovery_prior_state": "apply_activation_failed",
        "prior_failure_kind": "activation",
        "current_file": "CURRENT.json",
        "control_file": "CONTROL.sha256",
        "release_env_file": "release.env",
        "release_evidence_file": "RELEASE-EVIDENCE.json",
        "transaction_file": "estate/TRANSACTION.json",
        "applied_targets_file": "estate/APPLIED-TARGETS.sha256",
        "runtime_receipt_file": "runtime/BACKUP.receipt",
        "runtime_manifest_file": "runtime/SHA256SUMS",
        "route_database_state": "absent",
        "db_public_db_bracket": "absent-404-absent",
    }
    for field, expected in constants.items():
        if value[field] != expected:
            fail(f"{field} differs from the frozen recovery-completion contract")
    if value["recovery_schema_version"] != 2 or isinstance(
        value["recovery_schema_version"], bool
    ):
        fail("recovery_schema_version must equal 2")
    if value["runtime_backup_schema"] != 2 or isinstance(
        value["runtime_backup_schema"], bool
    ):
        fail("runtime_backup_schema must equal 2")
    attempt = value["recovery_attempt_id"]
    if not isinstance(attempt, str) or not ATTEMPT_ID.fullmatch(attempt):
        fail("recovery_attempt_id is unsafe")
    expected_names = {
        "completion_receipt": f"APPLY-RECOVERY-COMPLETE-{attempt}.receipt",
        "completion_archive": f"APPLY-RECOVERY-COMPLETE-{attempt}.json",
        "recovery_armed_receipt": f"APPLY-RECOVERY-ARMED-{attempt}.receipt",
    }
    for field, expected in expected_names.items():
        if value[field] != expected:
            fail(f"{field} differs from recovery_attempt_id")
    prior_failure_receipt = value["prior_failure_receipt"]
    if not isinstance(prior_failure_receipt, str) or not re.fullmatch(
        r"APPLY-ACTIVATION-FAILED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt",
        prior_failure_receipt,
    ):
        fail("prior_failure_receipt identity is unsafe")
    apply_armed_at = require_rfc3339_utc(value["apply_armed_at"], "apply_armed_at")
    recovery_armed_at = require_rfc3339_utc(
        value["recovery_armed_at"], "recovery_armed_at"
    )
    recovery_completed_at = require_rfc3339_utc(
        value["recovery_completed_at"], "recovery_completed_at"
    )
    issued_at = require_rfc3339_utc(value["issued_at"], "issued_at")
    if not apply_armed_at <= recovery_armed_at <= recovery_completed_at <= issued_at:
        fail("recovery timestamp ordering is invalid")
    require_absolute_canonical(value["estate_root"], "estate_root")
    require_absolute_canonical(value["backup_dir"], "backup_dir")
    for field in EXPECTED_FIELDS:
        if field.endswith("_sha256"):
            require_hex(value[field], field)
    predecessor = value["predecessor_release_generation"]
    generation = value["release_generation"]
    if (
        not isinstance(predecessor, int)
        or isinstance(predecessor, bool)
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or predecessor != 2
        or generation != 3
    ):
        fail("current-production successor generation linkage must be 2 -> 3")
    booleans = {
        "services_activated": True,
        "runtime_verified": True,
        "ingress_opened": False,
        "apply_receipt_created": False,
    }
    for field, expected in booleans.items():
        if value[field] is not expected:
            fail(f"{field} differs from the completed resume contract")
    status = value["public_ipv4_ipv6_closed_status"]
    if not isinstance(status, int) or isinstance(status, bool) or status != 404:
        fail("public_ipv4_ipv6_closed_status must equal integer 404")


def canonical_path(path: Path, label: str) -> Path:
    raw = str(path)
    require_absolute_canonical(raw, label)
    return Path(raw)


def open_canonical(path: Path, flags: int) -> int:
    path = canonical_path(path, "file path")
    components = path.parts[1:]
    directory = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        for component in components[:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        return os.open(
            components[-1], flags | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory
        )
    finally:
        os.close(directory)


def read_safe_regular(
    path: Path, label: str, *, private: bool = False, maximum_size: int = 262_144
) -> bytes:
    descriptor = open_canonical(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or (private and metadata.st_mode & 0o077)
            or metadata.st_size < 1
            or metadata.st_size > maximum_size
        ):
            fail(f"{label} must be a safe root-owned single-link regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def open_private_directory(path: Path) -> int:
    path = canonical_path(path, "release root")
    descriptor = open_canonical(path / ".", os.O_RDONLY | os.O_DIRECTORY)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        os.close(descriptor)
        fail("release root must be a private root-owned directory")
    return descriptor


def read_direct_child(
    directory: int, name: str, label: str, *, maximum_size: int = 262_144
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 1
            or metadata.st_size > maximum_size
        ):
            fail(f"{label} must be a mode-0600 root-owned single-link regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def run_openssl(arguments: list[str], *, input_bytes: bytes, pass_fds: tuple[int, ...]) -> bytes:
    result = subprocess.run(
        ["openssl", *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        pass_fds=pass_fds,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(
            "OpenSSL ceremony failed: "
            f"{json.dumps(detail, ensure_ascii=True)}"
        )
    return result.stdout


def require_rsa_modulus(public_key: bytes) -> None:
    public_read = os.memfd_create("holdfast-recovery-rsa-modulus", os.MFD_CLOEXEC)
    try:
        offset = 0
        while offset < len(public_key):
            offset += os.write(public_read, public_key[offset:])
        os.lseek(public_read, 0, os.SEEK_SET)
        description = run_openssl(
            [
                "pkey",
                "-pubin",
                "-in",
                f"/proc/self/fd/{public_read}",
                "-text_pub",
                "-noout",
            ],
            input_bytes=b"",
            pass_fds=(public_read,),
        )
    finally:
        os.close(public_read)
    match = re.search(rb"^Public-Key: \(([0-9]+) bit\)$", description, re.MULTILINE)
    if match is None or int(match.group(1)) < 2048:
        fail("RSA public-key modulus must be at least 2048 bits")


def validate_rsa_key_pair(private_key: Path, public_key: Path) -> tuple[int, int, bytes]:
    private_descriptor = open_canonical(private_key, os.O_RDONLY)
    public_descriptor = open_canonical(public_key, os.O_RDONLY)
    try:
        private_metadata = os.fstat(private_descriptor)
        public_metadata = os.fstat(public_descriptor)
        if (
            not stat.S_ISREG(private_metadata.st_mode)
            or private_metadata.st_uid != 0
            or private_metadata.st_nlink != 1
            or private_metadata.st_mode & 0o077
            or private_metadata.st_size < 1
            or private_metadata.st_size > 65_536
        ):
            fail("private key must be a mode-private root-owned single-link regular file")
        if (
            not stat.S_ISREG(public_metadata.st_mode)
            or public_metadata.st_uid != 0
            or public_metadata.st_nlink != 1
            or public_metadata.st_mode & 0o022
            or public_metadata.st_size < 1
            or public_metadata.st_size > 65_536
        ):
            fail("public key must be a safe root-owned single-link regular file")
        with os.fdopen(public_descriptor, "rb", closefd=False) as handle:
            public_bytes = handle.read()
        run_openssl(
            ["rsa", "-in", f"/proc/self/fd/{private_descriptor}", "-check", "-noout"],
            input_bytes=b"",
            pass_fds=(private_descriptor,),
        )
        derived_public = run_openssl(
            ["pkey", "-in", f"/proc/self/fd/{private_descriptor}", "-pubout", "-outform", "DER"],
            input_bytes=b"",
            pass_fds=(private_descriptor,),
        )
        supplied_public = run_openssl(
            ["pkey", "-pubin", "-in", f"/proc/self/fd/{public_descriptor}", "-pubout", "-outform", "DER"],
            input_bytes=b"",
            pass_fds=(public_descriptor,),
        )
        if derived_public != supplied_public:
            fail("private key and public key do not match")
        require_rsa_modulus(public_bytes)
        return private_descriptor, public_descriptor, public_bytes
    except Exception:
        os.close(private_descriptor)
        os.close(public_descriptor)
        raise


def sign(payload: bytes, private_descriptor: int) -> bytes:
    return run_openssl(
        [
            "dgst",
            "-sha256",
            "-sign",
            f"/proc/self/fd/{private_descriptor}",
            "-sigopt",
            "rsa_padding_mode:pkcs1",
        ],
        input_bytes=payload,
        pass_fds=(private_descriptor,),
    )


def verify_signature(
    payload: bytes, signature: bytes, public_key: bytes, expected_key_sha256: str
) -> None:
    require_hex(expected_key_sha256, "public key pin")
    if sha256_bytes(public_key) != expected_key_sha256:
        fail("public key differs from the fixed release pin")
    if not signature or len(signature) > 65_536 or not public_key or len(public_key) > 65_536:
        fail("signature or public key size is unsafe")
    require_rsa_modulus(public_key)
    public_read = os.memfd_create("holdfast-recovery-public-key", os.MFD_CLOEXEC)
    signature_read = os.memfd_create("holdfast-recovery-signature", os.MFD_CLOEXEC)
    try:
        for descriptor, value in (
            (public_read, public_key),
            (signature_read, signature),
        ):
            offset = 0
            while offset < len(value):
                offset += os.write(descriptor, value[offset:])
            os.lseek(descriptor, 0, os.SEEK_SET)
        output = run_openssl(
            [
                "dgst",
                "-sha256",
                "-verify",
                f"/proc/self/fd/{public_read}",
                "-signature",
                f"/proc/self/fd/{signature_read}",
                "-sigopt",
                "rsa_padding_mode:pkcs1",
            ],
            input_bytes=payload,
            pass_fds=(public_read, signature_read),
        )
        if b"Verified OK" not in output:
            fail("detached recovery-completion signature verification failed")
    finally:
        os.close(public_read)
        os.close(signature_read)


def rename_noreplace(directory: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        fail("renameat2 is required for exclusive atomic publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory,
        os.fsencode(source),
        directory,
        os.fsencode(target),
        1,
    ) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            fail(f"attestation output already exists: {target}")
        raise OSError(error, os.strerror(error), target)


def stage_file(directory: int, target: str, content: bytes) -> str:
    temporary = PENDING_NAMES[target]
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
        os.close(descriptor)
        descriptor = -1
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        except FileNotFoundError:
            pass
        raise
    return temporary


def validate_uncommitted_child(directory: int, name: str) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        fail(
            "uncommitted recovery-completion output is unsafe: "
            f"{json.dumps(name, ensure_ascii=True)}"
        )


def require_publication_namespace(directory: int) -> set[str]:
    allowed = {
        ATTESTATION_NAME,
        SIGNATURE_NAME,
        PUBLIC_KEY_NAME,
        *PENDING_NAMES.values(),
    }
    names = set(os.listdir(directory))
    for name in names:
        if name not in allowed:
            fail(
                "unexpected recovery-completion output exists: "
                f"{json.dumps(name, ensure_ascii=True)}"
            )
    return names


def cleanup_uncommitted_bundle(directory: int, names: set[str]) -> None:
    for name in (
        PENDING_NAMES[SIGNATURE_NAME],
        PENDING_NAMES[ATTESTATION_NAME],
        PENDING_NAMES[PUBLIC_KEY_NAME],
        ATTESTATION_NAME,
        PUBLIC_KEY_NAME,
    ):
        if name not in names:
            continue
        validate_uncommitted_child(directory, name)
        os.unlink(name, dir_fd=directory)
    os.fsync(directory)
    publication_boundary("fsync:cleanup")


def publication_boundary(name: str) -> None:
    """Test-only process-death seam at durable publication boundaries."""

    if (
        os.environ.get("HOLDFAST_TEST_MODE") == "1"
        and os.environ.get("HOLDFAST_TEST_PUBLISH_DEATH_BOUNDARY") == name
    ):
        os._exit(79)


def publish_bundle(
    directory: int, content: dict[str, bytes], expected_key_sha256: str
) -> None:
    expected = {ATTESTATION_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}
    if set(content) != expected:
        fail("publication content must be an exact three-file bundle")

    for target in (PUBLIC_KEY_NAME, ATTESTATION_NAME):
        temporary = stage_file(directory, target, content[target])
        publication_boundary(f"stage:{target}")
        rename_noreplace(directory, temporary, target)
        publication_boundary(f"rename:{target}")
    os.fsync(directory)
    publication_boundary("fsync:payload")

    temporary = stage_file(directory, SIGNATURE_NAME, content[SIGNATURE_NAME])
    publication_boundary(f"stage:{SIGNATURE_NAME}")
    published_attestation = read_direct_child(
        directory, ATTESTATION_NAME, "published attestation"
    )
    published_public_key = read_direct_child(
        directory, PUBLIC_KEY_NAME, "published public key"
    )
    pending_signature = read_direct_child(
        directory, temporary, "pending signature", maximum_size=65_536
    )
    if (
        published_attestation != content[ATTESTATION_NAME]
        or published_public_key != content[PUBLIC_KEY_NAME]
        or pending_signature != content[SIGNATURE_NAME]
    ):
        fail("staged recovery-completion bundle differs before commit")
    verify_raw_bundle(
        published_attestation,
        pending_signature,
        published_public_key,
        expected_key_sha256,
    )
    rename_noreplace(directory, temporary, SIGNATURE_NAME)
    publication_boundary(f"rename:{SIGNATURE_NAME}")
    os.fsync(directory)
    publication_boundary("fsync:commit")


def artifact_result(attestation: bytes, signature: bytes, public_key: bytes) -> dict[str, str]:
    return {
        "attestation": ATTESTATION_NAME,
        "attestation_sha256": sha256_bytes(attestation),
        "signature": SIGNATURE_NAME,
        "signature_sha256": sha256_bytes(signature),
        "public_key": PUBLIC_KEY_NAME,
        "public_key_sha256": sha256_bytes(public_key),
    }


def verify_raw_bundle(
    attestation: bytes, signature: bytes, public_key: bytes, expected_key_sha256: str
) -> dict[str, Any]:
    value = parse_canonical_document(attestation)
    if value["public_key_sha256"] != expected_key_sha256:
        fail("attestation public key pin differs")
    verify_signature(attestation, signature, public_key, expected_key_sha256)
    return value


def verify_paths(args: argparse.Namespace) -> dict[str, str]:
    attestation = read_safe_regular(args.attestation, "attestation", private=True)
    signature = read_safe_regular(
        args.signature, "signature", private=True, maximum_size=65_536
    )
    public_key = read_safe_regular(
        args.public_key, "public key", private=True, maximum_size=65_536
    )
    verify_raw_bundle(attestation, signature, public_key, args.public_key_sha256)
    return artifact_result(attestation, signature, public_key)


def build_document(args: argparse.Namespace, issued_at: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": KIND,
        "ceremony": CEREMONY,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "canonicalization_algorithm": CANONICALIZATION_ALGORITHM,
        "issued_at": issued_at,
        "mode": "resume",
        "successor": True,
        "recovery_schema_version": 2,
        "recovery_attempt_id": args.recovery_attempt_id,
        "recovery_prior_state": "apply_activation_failed",
        "prior_failure_kind": "activation",
        "prior_failure_receipt": args.prior_failure_receipt,
        "prior_failure_receipt_sha256": args.prior_failure_receipt_sha256,
        "apply_armed_at": args.apply_armed_at,
        "recovery_armed_at": args.recovery_armed_at,
        "recovery_completed_at": args.recovery_completed_at,
        "estate_root": str(args.estate_root),
        "backup_dir": str(args.backup_dir),
        "current_file": "CURRENT.json",
        "current_sha256": args.current_sha256,
        "completion_receipt": args.completion_receipt,
        "completion_receipt_sha256": args.completion_receipt_sha256,
        "completion_archive": args.completion_archive,
        "completion_archive_sha256": args.completion_archive_sha256,
        "recovery_armed_receipt": args.recovery_armed_receipt,
        "recovery_armed_receipt_sha256": args.recovery_armed_receipt_sha256,
        "control_file": "CONTROL.sha256",
        "control_sha256": args.control_sha256,
        "release_env_file": "release.env",
        "release_env_sha256": args.release_env_sha256,
        "release_evidence_file": "RELEASE-EVIDENCE.json",
        "release_evidence_sha256": args.release_evidence_sha256,
        "transaction_file": "estate/TRANSACTION.json",
        "transaction_sha256": args.transaction_sha256,
        "applied_targets_file": "estate/APPLIED-TARGETS.sha256",
        "applied_targets_sha256": args.applied_targets_sha256,
        "runtime_backup_schema": 2,
        "runtime_receipt_file": "runtime/BACKUP.receipt",
        "runtime_receipt_sha256": args.runtime_receipt_sha256,
        "runtime_manifest_file": "runtime/SHA256SUMS",
        "runtime_manifest_sha256": args.runtime_manifest_sha256,
        "predecessor_release_generation": args.predecessor_release_generation,
        "release_generation": args.release_generation,
        "services_activated": True,
        "runtime_verified": True,
        "route_database_state": "absent",
        "public_ipv4_ipv6_closed_status": 404,
        "db_public_db_bracket": "absent-404-absent",
        "ingress_opened": False,
        "apply_receipt_created": False,
        "public_key_sha256": args.public_key_sha256,
    }


def semantic_document(value: dict[str, Any]) -> dict[str, Any]:
    semantic = dict(value)
    del semantic["issued_at"]
    return semantic


def commit_prepared_bundle(
    directory: int,
    content: dict[str, bytes],
    prepared_document: dict[str, Any],
    expected_key_sha256: str,
) -> dict[str, str]:
    expected_names = {ATTESTATION_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}
    fcntl.flock(directory, fcntl.LOCK_EX)
    names = require_publication_namespace(directory)
    if SIGNATURE_NAME in names:
        if names != expected_names:
            fail("committed recovery-completion output set is not exact")
        existing_attestation = read_direct_child(
            directory, ATTESTATION_NAME, "attestation"
        )
        existing_signature = read_direct_child(directory, SIGNATURE_NAME, "signature")
        existing_public_key = read_direct_child(directory, PUBLIC_KEY_NAME, "public key")
        existing_document = verify_raw_bundle(
            existing_attestation,
            existing_signature,
            existing_public_key,
            expected_key_sha256,
        )
        if (
            semantic_document(existing_document) != semantic_document(prepared_document)
            or existing_public_key != content[PUBLIC_KEY_NAME]
        ):
            fail("existing recovery-completion bundle differs from prepared authority")
        os.fsync(directory)
        return artifact_result(
            existing_attestation, existing_signature, existing_public_key
        )

    cleanup_uncommitted_bundle(directory, names)
    publish_bundle(directory, content, expected_key_sha256)
    return artifact_result(
        content[ATTESTATION_NAME], content[SIGNATURE_NAME], content[PUBLIC_KEY_NAME]
    )


def issue(args: argparse.Namespace) -> dict[str, str]:
    require_hex(args.public_key_sha256, "public key pin")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    document = build_document(args, now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    validate_document(document)
    attestation = canonical_bytes(document)
    private_descriptor = -1
    public_descriptor = -1
    release_directory = -1
    try:
        private_descriptor, public_descriptor, public_key = validate_rsa_key_pair(
            args.private_key, args.source_public_key
        )
        if sha256_bytes(public_key) != args.public_key_sha256:
            fail("source public key differs from the fixed release pin")
        signature = sign(attestation, private_descriptor)
        verify_signature(attestation, signature, public_key, args.public_key_sha256)
        release_directory = open_private_directory(args.release_root)
        return commit_prepared_bundle(
            release_directory,
            {
                ATTESTATION_NAME: attestation,
                SIGNATURE_NAME: signature,
                PUBLIC_KEY_NAME: public_key,
            },
            document,
            args.public_key_sha256,
        )
    finally:
        if release_directory >= 0:
            os.close(release_directory)
        if private_descriptor >= 0:
            os.close(private_descriptor)
        if public_descriptor >= 0:
            os.close(public_descriptor)


def publish(args: argparse.Namespace) -> dict[str, str]:
    source_directory = open_private_directory(args.source_root)
    release_directory = open_private_directory(args.release_root)
    try:
        source_metadata = os.fstat(source_directory)
        release_metadata = os.fstat(release_directory)
        if (source_metadata.st_dev, source_metadata.st_ino) == (
            release_metadata.st_dev,
            release_metadata.st_ino,
        ):
            fail("source root and release root must differ")
        source_names = set(os.listdir(source_directory))
        expected_names = {ATTESTATION_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}
        if source_names != expected_names:
            fail("staged recovery-completion bundle file set is not exact")
        attestation = read_direct_child(
            source_directory, ATTESTATION_NAME, "staged attestation"
        )
        signature = read_direct_child(
            source_directory, SIGNATURE_NAME, "staged signature"
        )
        public_key = read_direct_child(
            source_directory, PUBLIC_KEY_NAME, "staged public key"
        )
        document = verify_raw_bundle(
            attestation, signature, public_key, args.public_key_sha256
        )
        return commit_prepared_bundle(
            release_directory,
            {
                ATTESTATION_NAME: attestation,
                SIGNATURE_NAME: signature,
                PUBLIC_KEY_NAME: public_key,
            },
            document,
            args.public_key_sha256,
        )
    finally:
        os.close(source_directory)
        os.close(release_directory)


def parse_structural_json(raw: bytes, label: str) -> dict[str, Any]:
    if b"\r" in raw:
        fail(f"{label} must not contain CR or CRLF")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    reject_structural_controls(value, label)
    return value


def reject_structural_controls(value: Any, label: str) -> None:
    if isinstance(value, str):
        if CONTROL_CHARACTER.search(value):
            fail(f"{label} contains a control character")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            reject_structural_controls(key, label)
            reject_structural_controls(child, label)
        return
    if isinstance(value, list):
        for child in value:
            reject_structural_controls(child, label)


def parse_structural_receipt(raw: bytes, label: str) -> dict[str, str]:
    if b"\r" in raw:
        fail(f"{label} must not contain CR or CRLF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            fail(f"{label} contains a malformed receipt line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            fail(f"{label} contains an unsafe receipt key")
        if CONTROL_CHARACTER.search(value):
            fail(f"{label} contains a control character")
        if key in result:
            fail(f"duplicate receipt key: {json.dumps(key, ensure_ascii=True)}")
        result[key] = value
    if not result:
        fail(f"{label} is empty")
    return result


def parse_historical_apply_armed(raw: bytes) -> dict[str, str]:
    label = "historical APPLY-ARMED receipt"
    if b"\r" in raw:
        fail(f"{label} must not contain CR or CRLF")
    if not raw.endswith(b"\n"):
        fail(f"{label} must end with LF")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")
    pairs: list[tuple[str, str]] = []
    for line in lines:
        if "=" not in line:
            fail(f"{label} contains a malformed receipt line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            fail(f"{label} contains an unsafe receipt key")
        if CONTROL_CHARACTER.search(value):
            fail(f"{label} contains a control character")
        pairs.append((key, value))
    if tuple(key for key, _ in pairs) != HISTORICAL_APPLY_ARMED_KEYS:
        fail(f"{label} key order and multiplicity are not exact")
    if pairs[12][1] != pairs[30][1]:
        fail(f"{label} runtime backup receipt duplicates differ")
    if pairs[13][1] != pairs[31][1]:
        fail(f"{label} runtime backup manifest duplicates differ")
    result: dict[str, str] = {}
    for key, value in pairs:
        result.setdefault(key, value)
    return result


def structure(args: argparse.Namespace) -> dict[str, int]:
    if (
        not args.json_file
        and not args.receipt_file
        and not args.historical_apply_armed_file
    ):
        fail("structure check requires at least one input")
    for path in args.json_file:
        parse_structural_json(
            read_safe_regular(path, "JSON structure"), "JSON structure"
        )
    for path in args.receipt_file:
        parse_structural_receipt(
            read_safe_regular(path, "receipt structure"),
            "receipt structure",
        )
    for path in args.historical_apply_armed_file:
        parse_historical_apply_armed(
            read_safe_regular(path, "historical APPLY-ARMED receipt")
        )
    return {
        "json_files": len(args.json_file),
        "receipt_files": len(args.receipt_file),
        "historical_apply_armed_files": len(args.historical_apply_armed_file),
    }


def path_value(value: str) -> Path:
    return canonical_path(Path(value), "CLI path")


def add_issue_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-root", required=True, type=path_value)
    parser.add_argument("--private-key", required=True, type=path_value)
    parser.add_argument("--source-public-key", required=True, type=path_value)
    parser.add_argument("--public-key-sha256", required=True)
    parser.add_argument("--recovery-attempt-id", required=True)
    parser.add_argument("--prior-failure-receipt", required=True)
    parser.add_argument("--prior-failure-receipt-sha256", required=True)
    parser.add_argument("--apply-armed-at", required=True)
    parser.add_argument("--recovery-armed-at", required=True)
    parser.add_argument("--recovery-completed-at", required=True)
    parser.add_argument("--estate-root", required=True, type=path_value)
    parser.add_argument("--backup-dir", required=True, type=path_value)
    parser.add_argument("--current-sha256", required=True)
    parser.add_argument("--completion-receipt", required=True)
    parser.add_argument("--completion-receipt-sha256", required=True)
    parser.add_argument("--completion-archive", required=True)
    parser.add_argument("--completion-archive-sha256", required=True)
    parser.add_argument("--recovery-armed-receipt", required=True)
    parser.add_argument("--recovery-armed-receipt-sha256", required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--release-env-sha256", required=True)
    parser.add_argument("--release-evidence-sha256", required=True)
    parser.add_argument("--transaction-sha256", required=True)
    parser.add_argument("--applied-targets-sha256", required=True)
    parser.add_argument("--runtime-receipt-sha256", required=True)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--predecessor-release-generation", required=True, type=int)
    parser.add_argument("--release-generation", required=True, type=int)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    issue_parser = commands.add_parser("issue")
    add_issue_arguments(issue_parser)
    issue_parser.set_defaults(handler=issue)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--attestation", required=True, type=path_value)
    verify_parser.add_argument("--signature", required=True, type=path_value)
    verify_parser.add_argument("--public-key", required=True, type=path_value)
    verify_parser.add_argument("--public-key-sha256", required=True)
    verify_parser.set_defaults(handler=verify_paths)
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--source-root", required=True, type=path_value)
    publish_parser.add_argument("--release-root", required=True, type=path_value)
    publish_parser.add_argument("--public-key-sha256", required=True)
    publish_parser.set_defaults(handler=publish)
    structure_parser = commands.add_parser("structure")
    structure_parser.add_argument(
        "--json-file", action="append", default=[], type=path_value
    )
    structure_parser.add_argument(
        "--receipt-file", action="append", default=[], type=path_value
    )
    structure_parser.add_argument(
        "--historical-apply-armed-file",
        action="append",
        default=[],
        type=path_value,
    )
    structure_parser.set_defaults(handler=structure)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        result = args.handler(args)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"recovery completion attestation rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
