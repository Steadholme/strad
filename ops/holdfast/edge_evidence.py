#!/usr/bin/env python3
"""Validate signed evidence for the existing W33D Sluice public edge."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from successor_binding import validate_policy


HEX64 = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_HOST = "rikune.w33d.xyz"
PUBLIC_URL = f"https://{PUBLIC_HOST}/"
LEGACY_PUBLIC_HOST = "analyze.w33d.xyz"
LEGACY_PUBLIC_URL = f"https://{LEGACY_PUBLIC_HOST}/"
EDGE_OWNER = "existing-w33d-sluice"
ROUTE_STATE = "absent"
LEGACY_CONTRACT = "legacy-analyze-v2"
DUAL_HOST_CONTRACT = "rikune-dual-v3"


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def safe_regular(path: Path, label: str) -> None:
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or path.is_symlink() or mode.st_nlink != 1:
        fail(f"unsafe {label} file: {path}")


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict[str, Any]:
    safe_regular(path, "evidence")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value


def release(path: Path) -> dict[str, str]:
    safe_regular(path, "release env")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            fail("malformed release env")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"duplicate release key: {key}")
        values[key] = value
    return values


def receipt(path: Path) -> dict[str, str]:
    safe_regular(path, "receipt")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or "=" not in line:
            fail("malformed receipt")
        key, value = line.split("=", 1)
        if not key or key in values:
            fail(f"duplicate or empty receipt key: {key}")
        values[key] = value
    return values


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} field set is not exact")
    return value


def hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail(f"{label} is not a lowercase SHA-256")
    return value


def moment(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{label} must be UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"invalid {label}: {error}")


def verify_signature(evidence: Path, signature: Path, public_key: Path, values: dict[str, str]) -> None:
    safe_regular(evidence, "edge evidence")
    safe_regular(signature, "edge signature")
    safe_regular(public_key, "authority public key")
    if sha256(public_key) != values.get("AUTHORITY_PUBLIC_KEY_SHA256"):
        fail("edge evidence signing key differs from the release authority key")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(evidence)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0 or "Verified OK" not in result.stdout:
        fail("detached edge evidence signature verification failed")


def validate_frozen_contract(
    args: argparse.Namespace,
) -> tuple[str, str | None, int | None]:
    release_value = load(args.release_evidence)
    is_successor = (
        release_value.get("schema_version") == 2
        and release_value.get("release_mode") == "successor"
    )
    if not is_successor:
        if args.successor_policy is not None:
            fail("legacy edge evidence must not claim successor policy authority")
        return LEGACY_CONTRACT, None, None
    if args.successor_policy is None:
        fail("successor edge evidence requires its frozen successor policy")
    policy = validate_policy(args.successor_policy)
    if release_value.get("predecessor_binding") != policy["predecessor"]:
        fail("release evidence differs from the frozen successor policy")
    policy_version = policy["schema_version"]
    if policy_version in (4, 5):
        return DUAL_HOST_CONTRACT, sha256(args.successor_policy), policy_version + 1
    return LEGACY_CONTRACT, sha256(args.successor_policy), None


def validate_edge_identity(
    value: dict[str, Any], label: str, expected_host: str
) -> None:
    if value.get("host") != expected_host:
        fail(f"{label} host is not {expected_host}")
    if value.get("edge_owner") != EDGE_OWNER:
        fail(f"{label} is not attributed to the existing W33D Sluice edge")
    if value.get("route_state") != ROUTE_STATE:
        fail(f"{label} does not prove route-absent state")
    if value.get("external_edge_mutations") != []:
        fail(f"{label} must not claim GitHub Pages, Cloudflare, or DNS mutation")


def validate_closed_probes(
    value: object,
    not_before: datetime,
    label: str,
    expected_urls: set[str],
) -> datetime:
    expected_pairs = {
        (url, family)
        for url in expected_urls
        for family in ("ipv4", "ipv6")
    }
    if not isinstance(value, list) or len(value) != len(expected_pairs):
        fail(f"{label} requires exactly one IPv4 and one IPv6 probe per host")
    observed_pairs: set[tuple[str, str]] = set()
    latest = not_before
    for item in value:
        probe = exact(
            item,
            {
                "family",
                "observed_at",
                "url",
                "status",
                "edge_owner",
                "route_state",
                "response_headers_sha256",
            },
            f"{label} public probe",
        )
        family = probe["family"]
        url = probe["url"]
        pair = (url, family)
        if pair not in expected_pairs or pair in observed_pairs:
            fail(f"{label} public probe host/family is duplicate or invalid")
        observed_pairs.add(pair)
        if url not in expected_urls:
            fail(f"{label} public probe targets the wrong host")
        if probe["status"] != 404:
            fail(f"{label} public probe must return exact 404")
        if probe["edge_owner"] != EDGE_OWNER:
            fail(f"{label} public probe is not attributed to the existing W33D Sluice edge")
        if probe["route_state"] != ROUTE_STATE:
            fail(f"{label} public probe does not prove route-absent state")
        hex64(probe["response_headers_sha256"], f"{label} public response headers")
        observed = moment(probe["observed_at"], f"{label} public probe observed_at")
        if observed < not_before:
            fail(f"{label} public probe predates the closed-state receipt")
        latest = max(latest, observed)
    if observed_pairs != expected_pairs:
        fail(f"{label} does not prove the exact host set over IPv4 and IPv6")
    return latest


def validate_legacy_prepare_receipt(
    path: Path,
) -> tuple[dict[str, str], datetime]:
    values = receipt(path)
    required = {
        "prepared_at",
        "release_evidence_sha256",
        "open_evidence_sha256",
        "source_grant_id",
        "route_state",
        "public_host",
        "edge_owner",
        "public_ipv4_ipv6_closed_status",
        "db_public_db_bracket",
        "external_edge_mutation",
    }
    if set(values) != required:
        fail("legacy open prepare receipt field set is not exact")
    if (
        values["route_state"] != ROUTE_STATE
        or values["public_host"] != LEGACY_PUBLIC_HOST
        or values["edge_owner"] != EDGE_OWNER
        or values["public_ipv4_ipv6_closed_status"] != "404"
        or values["db_public_db_bracket"] != "absent-404-absent"
        or values["external_edge_mutation"] != "none"
    ):
        fail("legacy open prepare receipt does not prove the exact closed Sluice edge")
    for name in ("release_evidence_sha256", "open_evidence_sha256"):
        hex64(values[name], f"open prepare receipt {name}")
    return values, moment(values["prepared_at"], "open prepare time")


def validate_dual_prepare_receipt(
    path: Path,
    expected_generation: int,
) -> tuple[dict[str, str], datetime]:
    values = receipt(path)
    required = {
        "schema_version",
        "prepared_at",
        "release_generation",
        "release_evidence_sha256",
        "open_evidence_sha256",
        "source_grant_id",
        "route_state",
        "public_host",
        "legacy_public_host",
        "legacy_route_state",
        "legacy_public_ipv4_ipv6_closed_status",
        "edge_owner",
        "public_ipv4_ipv6_closed_status",
        "db_public_db_bracket",
        "external_edge_mutation",
    }
    if set(values) != required:
        fail("dual-host open prepare receipt field set is not exact")
    if (
        values["schema_version"] != "3"
        or values["release_generation"] != str(expected_generation)
        or values["route_state"] != ROUTE_STATE
        or values["public_host"] != PUBLIC_HOST
        or values["legacy_public_host"] != LEGACY_PUBLIC_HOST
        or values["legacy_route_state"] != ROUTE_STATE
        or values["legacy_public_ipv4_ipv6_closed_status"] != "404"
        or values["edge_owner"] != EDGE_OWNER
        or values["public_ipv4_ipv6_closed_status"] != "404"
        or values["db_public_db_bracket"] != "absent-404-absent"
        or values["external_edge_mutation"] != "none"
    ):
        fail("dual-host open prepare receipt does not prove the exact closed edge")
    for name in ("release_evidence_sha256", "open_evidence_sha256"):
        hex64(values[name], f"dual-host open prepare receipt {name}")
    return values, moment(values["prepared_at"], "open prepare time")


def evidence_fields(mode: str, contract: str) -> set[str]:
    fields = {
        "schema_version",
        "ceremony",
        "issued_at",
        "signature_key_sha256",
        "release_evidence_sha256",
        "source_grant_id",
        "host",
        "edge_owner",
        "route_state",
        "external_edge_mutations",
        "public_probes",
    }
    if mode == "preopen":
        fields.update({"open_evidence_sha256", "open_prepare_receipt_sha256"})
    else:
        fields.update(
            {
                "preopen_edge_evidence_sha256",
                "route_close_receipt_sha256",
                "revocation_evidence_sha256",
            }
        )
    if contract == DUAL_HOST_CONTRACT:
        fields.add("successor_policy_sha256")
    return fields


def validate_document_shape(
    value: dict[str, Any], mode: str, contract: str, policy_sha: str | None
) -> None:
    schema = 3 if contract == DUAL_HOST_CONTRACT else 2
    ceremony = f"holdfast-rikune-edge-{mode}-v{schema}"
    if (
        set(value) != evidence_fields(mode, contract)
        or value.get("schema_version") != schema
        or value.get("ceremony") != ceremony
    ):
        fail(f"edge {mode} field set or v{schema} ceremony is invalid")
    expected_host = (
        PUBLIC_HOST if contract == DUAL_HOST_CONTRACT else LEGACY_PUBLIC_HOST
    )
    validate_edge_identity(value, f"edge {mode} evidence", expected_host)
    if contract == DUAL_HOST_CONTRACT:
        if value.get("successor_policy_sha256") != policy_sha:
            fail(f"edge {mode} frozen successor policy binding differs")


def validate_preopen(
    value: dict[str, Any],
    args: argparse.Namespace,
    contract: str,
    policy_sha: str | None,
    release_generation: int | None,
) -> None:
    validate_document_shape(value, "preopen", contract, policy_sha)
    if args.open_evidence is None or args.prepare_receipt is None:
        fail("pre-open validation requires open evidence and prepare receipt")
    open_value = load(args.open_evidence)
    if contract == DUAL_HOST_CONTRACT:
        if release_generation is None:
            fail("dual-host pre-open lacks frozen release generation authority")
        prepare_value, prepared_at = validate_dual_prepare_receipt(
            args.prepare_receipt, release_generation
        )
        expected_urls = {PUBLIC_URL, LEGACY_PUBLIC_URL}
    else:
        prepare_value, prepared_at = validate_legacy_prepare_receipt(
            args.prepare_receipt
        )
        expected_urls = {LEGACY_PUBLIC_URL}
    expected = {
        "signature_key_sha256": sha256(args.public_key),
        "release_evidence_sha256": sha256(args.release_evidence),
        "open_evidence_sha256": sha256(args.open_evidence),
        "source_grant_id": open_value.get("source_grant_id"),
        "open_prepare_receipt_sha256": sha256(args.prepare_receipt),
    }
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            fail(f"edge pre-open binding differs: {name}")
    if (
        prepare_value["release_evidence_sha256"] != expected["release_evidence_sha256"]
        or prepare_value["open_evidence_sha256"] != expected["open_evidence_sha256"]
        or prepare_value["source_grant_id"] != expected["source_grant_id"]
    ):
        fail("open prepare receipt differs from the release authority binding")
    latest_probe = validate_closed_probes(
        value["public_probes"], prepared_at, "edge pre-open", expected_urls
    )
    if moment(value["issued_at"], "issued_at") < latest_probe:
        fail("edge pre-open evidence predates its public probes")


def validate_preopen_reference(
    value: dict[str, Any], contract: str, policy_sha: str | None
) -> None:
    validate_document_shape(value, "preopen", contract, policy_sha)


def validate_route_close_receipt(
    path: Path, contract: str
) -> tuple[dict[str, str], datetime]:
    values = receipt(path)
    required = {
        "schema_version",
        "route_closed_at",
        "source_state",
        "estate_root",
        "backup_dir",
        "control_sha256",
        "state_before_sha256",
        "route_down_sha256",
        "route_down_execution_evidence_sha256",
        "open_evidence_sha256",
        "source_grant_id",
        "was_public_open",
        "preopen_edge_evidence_sha256",
        "route_preimage_sha256",
        "route_conflict_cleanup",
        "route_state",
        "public_host",
        "edge_owner",
        "public_ipv4_ipv6_closed_status",
        "db_public_db_bracket",
        "external_edge_mutation",
    }
    if contract == DUAL_HOST_CONTRACT:
        required.update(
            {
                "legacy_public_host",
                "legacy_route_state",
                "legacy_public_ipv4_ipv6_closed_status",
            }
        )
    if set(values) != required:
        fail("route-close receipt field set is not exact")
    expected_schema = "3" if contract == DUAL_HOST_CONTRACT else "2"
    expected_host = (
        PUBLIC_HOST if contract == DUAL_HOST_CONTRACT else LEGACY_PUBLIC_HOST
    )
    expected_cleanup = (
        "same-name-or-rikune-root-or-analyze-host"
        if contract == DUAL_HOST_CONTRACT
        else "same-name-or-analyze-root"
    )
    if (
        values["schema_version"] != expected_schema
        or values["source_state"]
        not in {
            "ingress_open",
            "finalizing_route_armed",
            "ingress_compensation_unverified",
        }
        or values["was_public_open"] != "true"
        or values["route_state"] != ROUTE_STATE
        or values["public_host"] != expected_host
        or values["edge_owner"] != EDGE_OWNER
        or values["public_ipv4_ipv6_closed_status"] != "404"
        or values["db_public_db_bracket"] != "absent-404-absent"
        or values["route_conflict_cleanup"] != expected_cleanup
        or values["external_edge_mutation"] != "none"
    ):
        fail("route-close receipt does not prove a formerly-open route is closed on Sluice")
    if contract == DUAL_HOST_CONTRACT and (
        values["legacy_public_host"] != LEGACY_PUBLIC_HOST
        or values["legacy_route_state"] != ROUTE_STATE
        or values["legacy_public_ipv4_ipv6_closed_status"] != "404"
    ):
        fail("route-close receipt does not prove the analyze tombstone")
    for name in (
        "control_sha256",
        "state_before_sha256",
        "route_down_sha256",
        "route_down_execution_evidence_sha256",
        "open_evidence_sha256",
        "preopen_edge_evidence_sha256",
        "route_preimage_sha256",
    ):
        hex64(values[name], f"route-close receipt {name}")
    for name in ("estate_root", "backup_dir"):
        raw_path = values[name]
        path_value = Path(raw_path)
        if (
            not path_value.is_absolute()
            or "." in path_value.parts
            or ".." in path_value.parts
            or str(path_value) != raw_path
        ):
            fail(f"route-close receipt {name} is not a canonical absolute path")
    return values, moment(values["route_closed_at"], "route close time")


def validate_rollback(
    value: dict[str, Any],
    args: argparse.Namespace,
    contract: str,
    policy_sha: str | None,
) -> None:
    validate_document_shape(value, "rollback", contract, policy_sha)
    if args.open_edge_evidence is None or args.route_close_receipt is None or args.revocation_evidence is None:
        fail("edge rollback requires pre-open edge, route-close, and revocation evidence")
    preopen = load(args.open_edge_evidence)
    validate_preopen_reference(preopen, contract, policy_sha)
    close_value, route_closed_at = validate_route_close_receipt(
        args.route_close_receipt, contract
    )
    revocation = load(args.revocation_evidence)
    revocation_issued = moment(revocation.get("issued_at"), "revocation issued_at")
    expected = {
        "signature_key_sha256": sha256(args.public_key),
        "release_evidence_sha256": sha256(args.release_evidence),
        "preopen_edge_evidence_sha256": sha256(args.open_edge_evidence),
        "route_close_receipt_sha256": sha256(args.route_close_receipt),
        "revocation_evidence_sha256": sha256(args.revocation_evidence),
        "source_grant_id": close_value["source_grant_id"],
    }
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            fail(f"edge rollback binding differs: {name}")
    if (
        close_value["preopen_edge_evidence_sha256"] != expected["preopen_edge_evidence_sha256"]
        or preopen.get("source_grant_id") != expected["source_grant_id"]
        or revocation.get("source_grant_id") != expected["source_grant_id"]
    ):
        fail("edge rollback does not bind the same pre-open evidence and source grant")
    expected_urls = (
        {PUBLIC_URL, LEGACY_PUBLIC_URL}
        if contract == DUAL_HOST_CONTRACT
        else {LEGACY_PUBLIC_URL}
    )
    latest_probe = validate_closed_probes(
        value["public_probes"],
        max(route_closed_at, revocation_issued),
        "edge rollback",
        expected_urls,
    )
    if moment(value["issued_at"], "issued_at") < latest_probe:
        fail("edge rollback evidence predates its public probes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("preopen", "rollback"))
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--release-env", required=True, type=Path)
    parser.add_argument("--release-evidence", required=True, type=Path)
    parser.add_argument("--successor-policy", type=Path)
    parser.add_argument("--open-evidence", type=Path)
    parser.add_argument("--prepare-receipt", type=Path)
    parser.add_argument("--open-edge-evidence", type=Path)
    parser.add_argument("--route-close-receipt", type=Path)
    parser.add_argument("--revocation-evidence", type=Path)
    args = parser.parse_args()
    try:
        values = release(args.release_env)
        verify_signature(args.evidence, args.signature, args.public_key, values)
        contract, policy_sha, release_generation = validate_frozen_contract(args)
        if args.mode == "preopen":
            validate_preopen(
                load(args.evidence),
                args,
                contract,
                policy_sha,
                release_generation,
            )
            success = f"signed edge pre-open evidence is valid for {contract}"
        else:
            validate_rollback(load(args.evidence), args, contract, policy_sha)
            success = f"signed edge rollback evidence is valid for {contract}"
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"edge evidence: {error}", file=sys.stderr)
        return 1
    print(success)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
