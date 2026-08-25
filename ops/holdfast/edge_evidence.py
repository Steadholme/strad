#!/usr/bin/env python3
"""Validate signed GitHub Pages and Cloudflare cutover/restore evidence."""

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


HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{8,255}$")


def fail(message: str) -> NoReturn:
    raise ValueError(message)


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
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or path.is_symlink() or mode.st_nlink != 1:
        fail(f"unsafe evidence file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value


def release(path: Path) -> dict[str, str]:
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
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"invalid {label}: {error}")
    return parsed


def verify_signature(evidence: Path, signature: Path, public_key: Path, values: dict[str, str]) -> None:
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


def validate_pages_snapshot(value: object) -> None:
    pages = exact(
        value,
        {"repository", "source_branch", "source_path", "cname", "status", "api_response_sha256", "observed_at"},
        "GitHub Pages snapshot",
    )
    if pages != {
        **pages,
        "repository": "Last-emo-boy/rikune",
        "source_branch": "main",
        "source_path": "/docs",
        "cname": "rikune.w33d.xyz",
        "status": "built",
    }:
        fail("GitHub Pages preflight differs from the existing owner")
    hex64(pages["api_response_sha256"], "GitHub Pages snapshot")
    moment(pages["observed_at"], "GitHub Pages observed_at")


def validate_cloudflare(value: object) -> tuple[datetime, datetime, datetime]:
    fields = {
        "token_secret_path",
        "token_scopes",
        "zone_id_sha256",
        "record_id_sha256",
        "pre_record_sha256",
        "post_record_sha256",
        "patch_method",
        "patch_path_sha256",
        "patch_request_sha256",
        "patch_response_sha256",
        "patched_at",
        "origin",
        "pre_ttl_seconds",
        "post_ttl_seconds",
        "ttl_wait_seconds",
        "ttl_converged_at",
        "purge_method",
        "purge_request_sha256",
        "purge_response_id",
        "purge_response_sha256",
        "purged_at",
    }
    edge = exact(value, fields, "Cloudflare cutover")
    secret_path = edge["token_secret_path"]
    if not isinstance(secret_path, str) or not secret_path.startswith("/") or secret_path.startswith("/root/w33d_infra/"):
        fail("Cloudflare token must be referenced by an external absolute secret path")
    if edge["token_scopes"] != ["Cache Purge", "DNS Write"]:
        fail("Cloudflare token scopes must be the exact least-privilege pair")
    for name in (
        "zone_id_sha256",
        "record_id_sha256",
        "pre_record_sha256",
        "post_record_sha256",
        "patch_path_sha256",
        "patch_request_sha256",
        "patch_response_sha256",
        "purge_request_sha256",
        "purge_response_sha256",
    ):
        hex64(edge[name], f"Cloudflare {name}")
    if edge["patch_method"] != "PATCH" or edge["purge_method"] != "POST":
        fail("Cloudflare API method evidence is invalid")
    if edge["origin"] != "w33d-sluice-ingress":
        fail("Cloudflare origin is not the W33D ingress")
    pre_ttl = edge["pre_ttl_seconds"]
    post_ttl = edge["post_ttl_seconds"]
    ttl_wait = edge["ttl_wait_seconds"]
    if (
        not isinstance(pre_ttl, int)
        or isinstance(pre_ttl, bool)
        or not 1 <= pre_ttl <= 86400
        or not isinstance(post_ttl, int)
        or isinstance(post_ttl, bool)
        or not 1 <= post_ttl <= 86400
        or not isinstance(ttl_wait, int)
        or isinstance(ttl_wait, bool)
        or ttl_wait < max(pre_ttl, post_ttl)
        or ttl_wait > 86400
    ):
        fail("Cloudflare TTL convergence evidence is invalid")
    if not isinstance(edge["purge_response_id"], str) or not SAFE_ID.fullmatch(edge["purge_response_id"]):
        fail("Cloudflare purge response id is absent")
    patched = moment(edge["patched_at"], "Cloudflare patched_at")
    converged = moment(edge["ttl_converged_at"], "Cloudflare ttl_converged_at")
    purged = moment(edge["purged_at"], "Cloudflare purged_at")
    if purged < patched:
        fail("Cloudflare cache purge predates DNS/origin cutover")
    if converged < patched + timedelta(seconds=ttl_wait):
        fail("Cloudflare DNS TTL wait has not converged")
    return patched, purged, converged


def validate_probes(value: object, not_before: datetime) -> None:
    if not isinstance(value, list) or len(value) < 2:
        fail("public cutover requires IPv4 and IPv6 probe evidence")
    families: set[str] = set()
    for item in value:
        probe = exact(
            item,
            {"family", "observed_at", "status", "cache_control", "github_request_id", "proxy_cache", "fastly_via", "origin", "response_headers_sha256"},
            "public probe",
        )
        family = probe["family"]
        if family not in {"ipv4", "ipv6"} or family in families:
            fail("public probe family is duplicate or invalid")
        families.add(family)
        if probe["status"] not in {200, 302, 401, 403}:
            fail("public probe status is not a bounded private-route response")
        if probe["cache_control"].replace(" ", "") != "private,no-store":
            fail("public workbench response is not private,no-store")
        if any(probe[name] is not None for name in ("github_request_id", "proxy_cache", "fastly_via")):
            fail("public probe still contains GitHub Pages/Fastly cache evidence")
        if probe["origin"] != "sluice-strad":
            fail("public probe is not attributed to Sluice/Strad")
        hex64(probe["response_headers_sha256"], "public response headers")
        if moment(probe["observed_at"], "public probe observed_at") < not_before:
            fail("public probe predates cache purge")
    if families != {"ipv4", "ipv6"}:
        fail("both IPv4 and IPv6 probes are mandatory")


def validate_cutover(value: dict[str, Any], args: argparse.Namespace) -> None:
    fields = {
        "schema_version",
        "ceremony",
        "issued_at",
        "signature_key_sha256",
        "release_evidence_sha256",
        "open_evidence_sha256",
        "source_grant_id",
        "open_prepare_receipt_sha256",
        "github_pages_preflight",
        "github_pages_detach",
        "cloudflare",
        "public_probes",
    }
    if set(value) != fields or value.get("schema_version") != 1 or value.get("ceremony") != "holdfast-rikune-edge-cutover-v1":
        fail("edge cutover field set or ceremony is invalid")
    if args.open_evidence is None or args.prepare_receipt is None:
        fail("cutover validation requires open evidence and prepare receipt")
    open_value = load(args.open_evidence)
    expected = {
        "signature_key_sha256": sha256(args.public_key),
        "release_evidence_sha256": sha256(args.release_evidence),
        "open_evidence_sha256": sha256(args.open_evidence),
        "source_grant_id": open_value.get("source_grant_id"),
        "open_prepare_receipt_sha256": sha256(args.prepare_receipt),
    }
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            fail(f"edge cutover binding differs: {name}")
    validate_pages_snapshot(value["github_pages_preflight"])
    detach = exact(
        value["github_pages_detach"],
        {"method", "path", "api_version", "request_body_sha256", "response_status", "completed_at", "post_get_sha256", "post_cname"},
        "GitHub Pages detach",
    )
    if detach["method"] != "PUT" or detach["path"] != "/repos/Last-emo-boy/rikune/pages" or detach["api_version"] != "2026-03-10":
        fail("GitHub Pages detach API evidence is invalid")
    if detach["response_status"] != 204 or detach["post_cname"] is not None:
        fail("GitHub Pages custom domain was not proven detached")
    for name in ("request_body_sha256", "post_get_sha256"):
        hex64(detach[name], f"GitHub Pages detach {name}")
    detached = moment(detach["completed_at"], "GitHub Pages detached_at")
    patched, purged, converged = validate_cloudflare(value["cloudflare"])
    prepare_time = moment(
        dict(line.split("=", 1) for line in args.prepare_receipt.read_text().splitlines())["prepared_at"],
        "open prepare time",
    )
    if detached < prepare_time or patched < detached:
        fail("edge cutover was not the last step after route/runtime preparation")
    validate_probes(value["public_probes"], max(purged, converged))
    issued = moment(value["issued_at"], "issued_at")
    if any(moment(item["observed_at"], "probe") > issued for item in value["public_probes"]):
        fail("edge evidence predates its public probes")


def validate_rollback(value: dict[str, Any], args: argparse.Namespace) -> None:
    fields = {
        "schema_version",
        "ceremony",
        "issued_at",
        "signature_key_sha256",
        "open_edge_evidence_sha256",
        "route_close_receipt_sha256",
        "revocation_evidence_sha256",
        "github_pages_restore",
        "cloudflare_restore",
        "public_probes",
    }
    if set(value) != fields or value.get("schema_version") != 1 or value.get("ceremony") != "holdfast-rikune-edge-rollback-v1":
        fail("edge rollback field set or ceremony is invalid")
    if args.open_edge_evidence is None or args.route_close_receipt is None or args.revocation_evidence is None:
        fail("edge rollback requires open edge, route-close, and revocation evidence")
    expected = {
        "signature_key_sha256": sha256(args.public_key),
        "open_edge_evidence_sha256": sha256(args.open_edge_evidence),
        "route_close_receipt_sha256": sha256(args.route_close_receipt),
        "revocation_evidence_sha256": sha256(args.revocation_evidence),
    }
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            fail(f"edge rollback binding differs: {name}")
    pages = exact(
        value["github_pages_restore"],
        {"method", "path", "api_version", "request_body_sha256", "response_status", "completed_at", "post_get_sha256", "post_cname", "source_branch", "source_path"},
        "GitHub Pages restore",
    )
    if (
        pages["method"] != "PUT"
        or pages["path"] != "/repos/Last-emo-boy/rikune/pages"
        or pages["api_version"] != "2026-03-10"
        or pages["response_status"] != 204
        or pages["post_cname"] != "rikune.w33d.xyz"
        or pages["source_branch"] != "main"
        or pages["source_path"] != "/docs"
    ):
        fail("original GitHub Pages ownership was not exactly restored")
    for name in ("request_body_sha256", "post_get_sha256"):
        hex64(pages[name], f"GitHub Pages restore {name}")
    cloudflare = exact(
        value["cloudflare_restore"],
        {
            "token_secret_path", "token_scopes", "zone_id_sha256", "record_id_sha256",
            "pre_record_sha256", "post_record_sha256", "patch_method", "patch_path_sha256",
            "patch_request_sha256", "patch_response_sha256", "patched_at", "origin",
            "pre_ttl_seconds", "post_ttl_seconds", "ttl_wait_seconds", "ttl_converged_at",
            "purge_method", "purge_request_sha256", "purge_response_id",
            "purge_response_sha256", "purged_at",
        },
        "Cloudflare restore",
    )
    if (
        not isinstance(cloudflare["token_secret_path"], str)
        or not cloudflare["token_secret_path"].startswith("/")
        or cloudflare["token_secret_path"].startswith("/root/w33d_infra/")
        or cloudflare["token_scopes"] != ["Cache Purge", "DNS Write"]
        or cloudflare["patch_method"] != "PATCH"
        or cloudflare["purge_method"] != "POST"
        or cloudflare["origin"] != "github-pages-original"
    ):
        fail("Cloudflare rollback authority or target is invalid")
    for name in (
        "zone_id_sha256", "record_id_sha256", "pre_record_sha256", "post_record_sha256",
        "patch_path_sha256", "patch_request_sha256", "patch_response_sha256",
        "purge_request_sha256", "purge_response_sha256",
    ):
        hex64(cloudflare[name], f"Cloudflare rollback {name}")
    if not isinstance(cloudflare["purge_response_id"], str) or not SAFE_ID.fullmatch(cloudflare["purge_response_id"]):
        fail("Cloudflare rollback purge response id is absent")
    restored = moment(pages["completed_at"], "Pages restored_at")
    patched = moment(cloudflare["patched_at"], "Cloudflare rollback patched_at")
    converged = moment(cloudflare["ttl_converged_at"], "Cloudflare rollback ttl_converged_at")
    purged = moment(cloudflare["purged_at"], "Cloudflare rollback purged_at")
    revocation_issued = moment(load(args.revocation_evidence)["issued_at"], "revocation issued_at")
    if restored < revocation_issued or patched < restored or purged < patched:
        fail("edge rollback must follow route close, grant revoke, and tombstone acknowledgements")
    pre_ttl = cloudflare["pre_ttl_seconds"]
    post_ttl = cloudflare["post_ttl_seconds"]
    ttl_wait = cloudflare["ttl_wait_seconds"]
    if (
        not isinstance(pre_ttl, int)
        or isinstance(pre_ttl, bool)
        or not 1 <= pre_ttl <= 86400
        or not isinstance(post_ttl, int)
        or isinstance(post_ttl, bool)
        or not 1 <= post_ttl <= 86400
        or not isinstance(ttl_wait, int)
        or isinstance(ttl_wait, bool)
        or ttl_wait < max(pre_ttl, post_ttl)
        or ttl_wait > 86400
        or converged < patched + timedelta(seconds=ttl_wait)
    ):
        fail("Cloudflare rollback TTL convergence evidence is invalid")
    open_edge = load(args.open_edge_evidence)
    open_cloudflare = exact(open_edge.get("cloudflare"), {
        "token_secret_path", "token_scopes", "zone_id_sha256", "record_id_sha256",
        "pre_record_sha256", "post_record_sha256", "patch_method", "patch_path_sha256",
        "patch_request_sha256", "patch_response_sha256", "patched_at", "origin",
        "pre_ttl_seconds", "post_ttl_seconds", "ttl_wait_seconds", "ttl_converged_at",
        "purge_method", "purge_request_sha256", "purge_response_id",
        "purge_response_sha256", "purged_at",
    }, "open Cloudflare evidence")
    for field in ("zone_id_sha256", "record_id_sha256", "patch_path_sha256"):
        if cloudflare[field] != open_cloudflare[field]:
            fail(f"Cloudflare rollback targets another record: {field}")
    if (
        cloudflare["pre_record_sha256"] != open_cloudflare["post_record_sha256"]
        or cloudflare["post_record_sha256"] != open_cloudflare["pre_record_sha256"]
    ):
        fail("Cloudflare rollback does not restore the exact pre-cutover record")
    probes = value["public_probes"]
    if not isinstance(probes, list) or {item.get("family") for item in probes if isinstance(item, dict)} != {"ipv4", "ipv6"}:
        fail("edge rollback requires IPv4/IPv6 Pages probes")
    for probe in probes:
        item = exact(probe, {"family", "observed_at", "origin", "cname", "response_headers_sha256"}, "Pages rollback probe")
        if item["origin"] != "github-pages" or item["cname"] != "rikune.w33d.xyz" or moment(item["observed_at"], "Pages probe") < max(purged, converged):
            fail("rollback probe does not prove restored Pages ownership after purge")
        hex64(item["response_headers_sha256"], "Pages rollback headers")
    if moment(value["issued_at"], "issued_at") < max(moment(item["observed_at"], "probe") for item in probes):
        fail("edge rollback evidence predates its probes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("cutover", "rollback"))
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--release-env", required=True, type=Path)
    parser.add_argument("--release-evidence", required=True, type=Path)
    parser.add_argument("--open-evidence", type=Path)
    parser.add_argument("--prepare-receipt", type=Path)
    parser.add_argument("--open-edge-evidence", type=Path)
    parser.add_argument("--route-close-receipt", type=Path)
    parser.add_argument("--revocation-evidence", type=Path)
    args = parser.parse_args()
    try:
        values = release(args.release_env)
        verify_signature(args.evidence, args.signature, args.public_key, values)
        if args.mode == "cutover":
            validate_cutover(load(args.evidence), args)
        else:
            validate_rollback(load(args.evidence), args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"edge evidence: {error}", file=sys.stderr)
        return 1
    print("signed Pages/Cloudflare cutover evidence is exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
