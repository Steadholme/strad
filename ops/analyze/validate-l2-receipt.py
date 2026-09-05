#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
INFRA_ROOT = ROOT.parents[2]
ACCESS_ROOT = INFRA_ROOT / "access-governance"
SLUICE_ROOT = INFRA_ROOT / ".worktrees" / "analyze-gen7" / "sluice"
VERDICT_ROOT = INFRA_ROOT / ".worktrees" / "analyze-gen7" / "verdict"
MANIFEST = INFRA_ROOT / ".worktrees" / "analyze-gen7" / "task-003-commit-manifest.json"

SCENARIOS = [
    "closed_topology",
    "application_approval",
    "oidc_browser",
    "mcp_four_tools",
    "authorization_negatives",
    "credential_rotation",
    "online_revocation",
    "final_fence_barrier",
    "fault_recovery",
]
FAULTS = ["dispatch_timeout", "response_before_crash", "cleanup_crash"]
MISSING = [
    "postgresql",
    "analyzer_ghidra",
    "ed25519_keyring",
    "application_credential_pepper",
    "approval_worker_signing_key",
    "strad_facade_token",
    "strad_governance_reporting_token",
]
NATIVE_CHECKS = [
    "access_real_pg",
    "sluice_manifest",
    "verdict_manifest",
    "facade_contract",
    "strad_real_pg",
    "analyzer_real_ghidra",
    "newapi_single_conversation",
]
REQUEST_V2_FIELDS = [
    "v",
    "application_sub",
    "client_id",
    "credential_id",
    "credential_version",
    "grant_id",
    "package_id",
    "package_revision_digest",
    "scopes",
    "canonical_tool",
    "resource",
    "session_id",
    "request_sha256",
    "policy_epoch",
    "revocation_epoch",
    "correlation_id",
]
EXECUTION_FIELDS = [
    "version",
    "decision_id",
    "decision_digest",
    "subject_version",
    "application_sub",
    "credential_id",
    "credential_version",
    "policy_epoch",
    "revocation_epoch",
    "request_sha256",
    "mcp_session_digest",
    "issued_at",
    "expires_at",
]


class DuplicateKeyError(ValueError):
    pass


def object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_no_duplicates)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} fields differ: missing={missing}, extra={extra}")


def validate(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("receipt must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise ValueError(f"receipt mode must be 0600, got {mode:04o}")
    receipt = read_json(path)
    if not isinstance(receipt, dict):
        raise ValueError("receipt root must be an object")

    exact_keys(
        receipt,
        {
            "schema_version", "layer", "status", "ingress_closed", "run_id",
            "started_at", "completed_at", "duration_seconds", "sources", "topology",
            "approval", "browser", "mcp", "authorization", "credential", "revocation",
            "final_fence", "faults", "missing_dependencies", "native_checks", "scenarios",
            "evidence_digests",
        },
        "receipt",
    )
    if receipt["schema_version"] != 1 or receipt["layer"] != "L2":
        raise ValueError("receipt must be schema v1 at layer L2")
    if receipt["status"] != "pass" or receipt["ingress_closed"] is not True:
        raise ValueError("receipt must be a closed passing run")
    started = receipt["started_at"]
    completed = receipt["completed_at"]
    if completed < started or receipt["duration_seconds"] != completed - started:
        raise ValueError("run chronology is inconsistent")

    topology = receipt["topology"]
    if topology["published_ports"] != [] or topology["network_internal"] is not True:
        raise ValueError("closed topology may not publish a host port")
    if topology["postgres"] != "real" or topology["service_readyz"] is not True:
        raise ValueError("real PostgreSQL and service readiness are mandatory")
    if topology["composite_real_ghidra"] is not True:
        raise ValueError("real Ghidra composite evidence is mandatory")
    if set(topology["services"]) != {
        "access", "sluice", "verdict", "facade", "strad", "analyzer", "postgres", "acceptance"
    }:
        raise ValueError("topology service set differs from the frozen composed topology")

    sources = receipt["sources"]
    manifest = read_json(MANIFEST)
    if sources["access_revision"] != git_revision(ACCESS_ROOT):
        raise ValueError("Access revision does not match the tested checkout")
    if sources["strad_revision"] != git_revision(INFRA_ROOT / "strad"):
        raise ValueError("Strad revision does not match the tested checkout")
    if sources["facade_revision"] != sources["strad_revision"]:
        raise ValueError("Facade must be bound to the same Strad revision")
    if sources["sluice_revision"] != git_revision(SLUICE_ROOT):
        raise ValueError("Sluice revision does not match its isolated checkout")
    if sources["verdict_revision"] != git_revision(VERDICT_ROOT):
        raise ValueError("Verdict revision does not match its isolated checkout")
    if sources["sluice_revision"] != manifest["repositories"]["sluice"]["final_commit_sha"]:
        raise ValueError("Sluice is not pinned by the TASK-003 manifest")
    if sources["verdict_revision"] != manifest["repositories"]["verdict"]["final_commit_sha"]:
        raise ValueError("Verdict is not pinned by the TASK-003 manifest")
    if sources["task003_manifest_sha256"] != sha256_file(MANIFEST):
        raise ValueError("TASK-003 manifest digest differs")

    approval = receipt["approval"]
    if approval["sponsor"]["consumed_count"] != 1:
        raise ValueError("Sponsor assertion was not consumed exactly once")
    if approval["system_decision"]["consumed_count"] != 1:
        raise ValueError("system decision was not consumed exactly once")
    if approval["system_decision"]["ttl_seconds"] != 300:
        raise ValueError("system decision is not the frozen 300-second decision")
    if approval["filesystem_assertion"] or approval["direct_decision_injection"]:
        raise ValueError("approval evidence used a forbidden injection seam")

    browser = receipt["browser"]
    oidc_fixture = ROOT / "fixtures" / "oidc-browser-v1.json"
    if browser["fixture_sha256"] != sha256_file(oidc_fixture):
        raise ValueError("OIDC browser fixture digest differs")
    if browser["sensitive_values_recorded"] is not False:
        raise ValueError("browser evidence recorded a sensitive value")

    mcp = receipt["mcp"]
    if mcp["newapi_conversation_calls"] != 1:
        raise ValueError("NewAPI must be called exactly once")
    if mcp["rest_cancel_status"] not in (404, 405) or mcp["rest_cancel_compensation_count"] != 0:
        raise ValueError("public REST cancel did not fail closed")

    authorization = receipt["authorization"]
    if authorization["request_v2_fields"] != REQUEST_V2_FIELDS:
        raise ValueError("Verdict RequestV2 field order/set differs")
    if authorization["all_negative_dispatch_count"] != 0:
        raise ValueError("a negative authorization path dispatched work")
    if authorization["non_allow_audit_count_each"] != 1:
        raise ValueError("a non-allow path lacks exactly one durable audit")

    revoked = receipt["revocation"]
    delta = revoked["enforced_at"] - revoked["durable_revoked_at"]
    if delta < 0 or delta != revoked["enforced_within_seconds"] or delta > 30:
        raise ValueError("revocation did not converge within 30 seconds")
    if revoked["cache_used"] is not False:
        raise ValueError("revocation polling may not use cached authentication")

    fence = receipt["final_fence"]
    if fence["execution_envelope_fields"] != EXECUTION_FIELDS:
        raise ValueError("ExecutionEnvelopeV1 field order/set differs")
    if fence["dispatch_count"] != 0 or fence["fence_result"] != "inactive":
        raise ValueError("final execution fence did not prevent dispatch")

    if [item["name"] for item in receipt["faults"]] != FAULTS:
        raise ValueError("fault scenario set/order differs")
    if any(
        item["state"] != "downstream_uncertain"
        or item["automatic_resend_count"] != 0
        or item["reservation_retained"] is not True
        or item["audited_reconciliation"] is not True
        for item in receipt["faults"]
    ):
        raise ValueError("fault recovery evidence is incomplete")
    if [item["name"] for item in receipt["missing_dependencies"]] != MISSING:
        raise ValueError("missing-dependency matrix differs")
    if any(
        item["result"] != "fail_closed" or item["pass_receipt_written"] is not False
        for item in receipt["missing_dependencies"]
    ):
        raise ValueError("a missing dependency did not fail closed")
    if [item["name"] for item in receipt["native_checks"]] != NATIVE_CHECKS:
        raise ValueError("native check set/order differs")
    if [item["name"] for item in receipt["scenarios"]] != SCENARIOS:
        raise ValueError("scenario set/order differs")
    if any(item["status"] != "pass" for item in receipt["native_checks"] + receipt["scenarios"]):
        raise ValueError("receipt contains a non-pass result")
    correlations = [item.get("correlation_id") for item in receipt["scenarios"]]
    if any(not isinstance(value, str) for value in correlations) or len(set(correlations)) != len(correlations):
        raise ValueError("every scenario must have one distinct correlation id")

    digests = receipt["evidence_digests"]
    expected_files = {
        "public_contract_sha256": ROOT / "analyze-public-v1.json",
        "oidc_fixture_sha256": oidc_fixture,
        "compose_sha256": ROOT / "compose.closed.yml",
        "analyzer_baseline_sha256": ROOT / "evidence" / "analyzer-baseline-v1.json",
    }
    for name, evidence_path in expected_files.items():
        if digests[name] != sha256_file(evidence_path):
            raise ValueError(f"{name} does not match {evidence_path}")

    serialized = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    forbidden_words = re.compile(r"(?i)(placeholder|degraded|sk[i]p(?:ped)?)")
    actual_token = re.compile(r"app_v1_[A-Za-z0-9_-]{43}")
    cookie_value = re.compile(r"__Secure-gw=")
    if forbidden_words.search(serialized):
        raise ValueError("receipt contains forbidden non-converged language")
    if actual_token.search(serialized) or cookie_value.search(serialized):
        raise ValueError("receipt contains credential or cookie material")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Analyze L2 receipt semantics")
    parser.add_argument("--input", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        validate(arguments.input.resolve())
    except (OSError, ValueError, DuplicateKeyError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"invalid L2 receipt: {error}", file=sys.stderr)
        return 1
    print("L2 receipt semantic validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
