#!/usr/bin/env python3
"""Validate detached-signed, checksum-bound authority open and rollback ceremonies."""

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


PERMISSIONS = {
    "rikune.analysis.create",
    "rikune.analysis.delete",
    "rikune.analysis.promote",
    "rikune.analysis.read",
    "rikune.console.enter",
    "rikune.conversation.use",
    "rikune.upload.cancel",
}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def load_object(path: Path) -> dict[str, Any]:
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or path.is_symlink() or mode.st_nlink != 1:
        fail("evidence must be a single-link regular file")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value


def parse_release(path: Path) -> dict[str, str]:
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


def receipt(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            fail(f"malformed receipt: {path}")
        key, value = line.split("=", 1)
        if key in result:
            fail(f"duplicate receipt key: {key}")
        result[key] = value
    return result


def require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value) or value.startswith("REQUIRED"):
        fail(f"{field} is not immutable ceremony evidence")
    return value


def timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{field} is invalid: {error}")
    if parsed.tzinfo != timezone.utc:
        fail(f"{field} must be UTC")
    return parsed


def exact_edges(value: object, field: str) -> list[datetime]:
    if not isinstance(value, list) or len(value) != 7:
        fail(f"{field} must contain exactly seven entries")
    observed: set[str] = set()
    times: list[datetime] = []
    for edge in value:
        if not isinstance(edge, dict) or set(edge) != {
            "permission",
            "epoch",
            "ack",
            "acknowledged_at",
        }:
            fail(f"{field} has an invalid entry")
        permission = edge["permission"]
        if permission not in PERMISSIONS or permission in observed:
            fail(f"{field} has duplicate or unexpected permission evidence")
        if not isinstance(edge["epoch"], int) or edge["epoch"] < 1 or edge["ack"] is not True:
            fail(f"{field} lacks a positive acknowledged epoch")
        times.append(timestamp(edge["acknowledged_at"], f"{field}.acknowledged_at"))
        observed.add(permission)
    if observed != PERMISSIONS:
        fail(f"{field} differs from the frozen permission set")
    return times


def verify_signature(evidence: Path, signature: Path, public_key: Path, release: dict[str, str]) -> None:
    key_sha = sha256(public_key)
    if key_sha != release.get("AUTHORITY_PUBLIC_KEY_SHA256"):
        fail("authority public key differs from the release pin")
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
        fail("detached authority signature verification failed")


def validate_common(value: dict[str, Any], release: dict[str, str], args: argparse.Namespace) -> None:
    if value.get("schema_version") != 2:
        fail("schema_version must equal 2")
    if value.get("beneficiary") != "user:rikune-acceptance":
        fail("beneficiary must be the independent acceptance subject")
    if value.get("package_id") != "pkg_rikune_analyst":
        fail("package_id differs from the frozen package")
    require_id(value.get("source_grant_id"), "source_grant_id")
    expected = {
        "release_env_sha256": sha256(args.release_env),
        "release_evidence_sha256": sha256(args.release_evidence),
        "signature_key_sha256": sha256(args.public_key),
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            fail(f"{field} differs from the immutable ceremony inputs")
    release_evidence = load_object(args.release_evidence)
    if release_evidence.get("release_env_sha256") != expected["release_env_sha256"]:
        fail("RELEASE-EVIDENCE is not bound to the authority release env")
    issued = timestamp(value.get("issued_at"), "issued_at")
    if issued > datetime.now(timezone.utc):
        fail("authority evidence is future-dated")


def validate_open(value: dict[str, Any], release: dict[str, str], args: argparse.Namespace) -> None:
    expected_fields = {
        "schema_version",
        "ceremony",
        "issued_at",
        "expires_at",
        "release_env_sha256",
        "release_evidence_sha256",
        "dry_run_receipt_sha256",
        "signature_key_sha256",
        "candidate_image_digest",
        "build_input_sha256",
        "permission_catalog_sha256",
        "package_catalog_sha256",
        "bootstrap_version",
        "package_id",
        "requestable_version",
        "beneficiary",
        "promotion_ceremony_id",
        "package_request_id",
        "source_grant_id",
        "projection_edges",
    }
    if set(value) != expected_fields or value.get("ceremony") != "holdfast-rikune-open-v2":
        fail("open ceremony field set or name is invalid")
    validate_common(value, release, args)
    if args.dry_run_receipt is None:
        fail("--dry-run-receipt is required for open evidence")
    if value.get("dry_run_receipt_sha256") != sha256(args.dry_run_receipt):
        fail("open evidence differs from the dry-run receipt")
    expected = {
        "candidate_image_digest": release.get("ACCESS_GOVERNANCE_IMAGE"),
        "build_input_sha256": release.get("ACCESS_GOVERNANCE_BUILD_INPUT_SHA256"),
        "permission_catalog_sha256": release.get("PERMISSION_CATALOG_SHA256"),
        "package_catalog_sha256": release.get("PACKAGE_CATALOG_SHA256"),
    }
    for field, expected_value in expected.items():
        if not expected_value or value.get(field) != expected_value:
            fail(f"{field} differs from the release pin")
    if value.get("bootstrap_version") != 6 or value.get("requestable_version") != 2:
        fail("bootstrap/requestable version evidence is incomplete")
    require_id(value.get("promotion_ceremony_id"), "promotion_ceremony_id")
    require_id(value.get("package_request_id"), "package_request_id")
    edge_times = exact_edges(value.get("projection_edges"), "projection_edges")
    issued = timestamp(value["issued_at"], "issued_at")
    expires = timestamp(value.get("expires_at"), "expires_at")
    if expires <= issued or expires - issued > timedelta(days=30) or any(item > issued for item in edge_times):
        fail("open ceremony timestamps are out of order")


def validate_rollback(value: dict[str, Any], release: dict[str, str], args: argparse.Namespace) -> None:
    expected_fields = {
        "schema_version",
        "ceremony",
        "issued_at",
        "release_env_sha256",
        "release_evidence_sha256",
        "signature_key_sha256",
        "package_id",
        "beneficiary",
        "source_grant_id",
        "open_evidence_sha256",
        "route_close_receipt_sha256",
        "route_closed_at",
        "grant_revoked_at",
        "revocation_ceremony_id",
        "projection_tombstones",
    }
    if set(value) != expected_fields or value.get("ceremony") != "holdfast-rikune-rollback-v2":
        fail("rollback ceremony field set or name is invalid")
    validate_common(value, release, args)
    if args.open_evidence is None or args.route_close_receipt is None:
        fail("rollback validation requires open evidence and route-close receipt")
    open_value = load_object(args.open_evidence)
    close_receipt = receipt(args.route_close_receipt)
    expected_open_sha = sha256(args.open_evidence)
    expected_close_sha = sha256(args.route_close_receipt)
    if value.get("open_evidence_sha256") != expected_open_sha:
        fail("rollback is not bound to the open ceremony")
    if value.get("route_close_receipt_sha256") != expected_close_sha:
        fail("rollback is not bound to the route-close receipt")
    if open_value.get("source_grant_id") != value.get("source_grant_id"):
        fail("rollback does not revoke the exact open ceremony grant")
    if close_receipt.get("open_evidence_sha256") != expected_open_sha:
        fail("route-close receipt does not bind the open ceremony")
    if close_receipt.get("source_grant_id") != value.get("source_grant_id"):
        fail("route-close receipt names a different grant")
    route_closed = timestamp(value.get("route_closed_at"), "route_closed_at")
    if close_receipt.get("route_closed_at") != value.get("route_closed_at"):
        fail("route close time differs from its receipt")
    revoked = timestamp(value.get("grant_revoked_at"), "grant_revoked_at")
    tombstones = exact_edges(value.get("projection_tombstones"), "projection_tombstones")
    issued = timestamp(value.get("issued_at"), "issued_at")
    if not route_closed < revoked or any(item < revoked for item in tombstones):
        fail("rollback order must be route close, grant revoke, then seven tombstone acknowledgements")
    if any(item > issued for item in tombstones):
        fail("rollback evidence predates a tombstone acknowledgement")
    require_id(value.get("revocation_ceremony_id"), "revocation_ceremony_id")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("open", "rollback"))
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--release-env", required=True, type=Path)
    parser.add_argument("--release-evidence", required=True, type=Path)
    parser.add_argument("--dry-run-receipt", type=Path)
    parser.add_argument("--open-evidence", type=Path)
    parser.add_argument("--route-close-receipt", type=Path)
    args = parser.parse_args()
    try:
        release = parse_release(args.release_env)
        verify_signature(args.evidence, args.signature, args.public_key, release)
        value = load_object(args.evidence)
        if args.mode == "open":
            validate_open(value, release, args)
        else:
            validate_rollback(value, release, args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"authority evidence: {error}", file=sys.stderr)
        return 1
    print(f"signed {args.mode} authority evidence is exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
