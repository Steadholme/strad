#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --phase prepare|finalize --estate-root PATH --dry-run-dir PATH --release-env FILE --authority-evidence FILE --authority-signature FILE --authority-public-key FILE [--edge-evidence FILE --edge-signature FILE] [--state-dir PATH]" >&2
  echo "       $0 --execute --abandon-prepare --reason-file ROOT_OWNED_0600_FILE [--state-dir PATH]" >&2
  exit 2
}

execute="false"
phase=""
phase_supplied="false"
abandon_prepare="false"
reason_file=""
reason_file_supplied="false"
normal_input_supplied="false"
estate_root=""
dry_run_dir=""
release_env=""
authority_evidence=""
authority_signature=""
authority_public_key=""
edge_evidence=""
edge_signature=""
state_dir="/var/lib/holdfast-rikune"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --phase) [[ $# -ge 2 ]] || usage; phase=$2; phase_supplied="true"; shift 2 ;;
    --abandon-prepare) abandon_prepare="true"; shift ;;
    --reason-file) [[ $# -ge 2 ]] || usage; reason_file=$2; reason_file_supplied="true"; shift 2 ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; normal_input_supplied="true"; shift 2 ;;
    --dry-run-dir) [[ $# -ge 2 ]] || usage; dry_run_dir=$2; normal_input_supplied="true"; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; normal_input_supplied="true"; shift 2 ;;
    --authority-evidence) [[ $# -ge 2 ]] || usage; authority_evidence=$2; normal_input_supplied="true"; shift 2 ;;
    --authority-signature) [[ $# -ge 2 ]] || usage; authority_signature=$2; normal_input_supplied="true"; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; normal_input_supplied="true"; shift 2 ;;
    --edge-evidence) [[ $# -ge 2 ]] || usage; edge_evidence=$2; normal_input_supplied="true"; shift 2 ;;
    --edge-signature) [[ $# -ge 2 ]] || usage; edge_signature=$2; normal_input_supplied="true"; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" ]] || usage
if [[ "$abandon_prepare" == "true" ]]; then
  [[ "$phase_supplied" == "false" && "$reason_file_supplied" == "true" && \
    "$normal_input_supplied" == "false" && -n "$reason_file" ]] || usage
else
  [[ "$phase_supplied" == "true" && \
    ( "$phase" == "prepare" || "$phase" == "finalize" ) ]] || usage
  [[ "$reason_file_supplied" == "false" ]] || usage
  [[ -n "$estate_root" && -n "$dry_run_dir" && -n "$release_env" && -n "$authority_evidence" && -n "$authority_signature" && -n "$authority_public_key" ]] || usage
fi
[[ $EUID -eq 0 ]] || { echo "opening ingress requires root" >&2; exit 1; }
if [[ "$abandon_prepare" != "true" ]]; then
  [[ -n "${ROUTES_DATABASE_URL:-}" ]] || { echo "ROUTES_DATABASE_URL must be supplied by the secret authority" >&2; exit 1; }
fi
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
paths=("$state_dir")
if [[ "$abandon_prepare" == "true" ]]; then
  paths+=("$reason_file")
else
  paths+=("$estate_root" "$dry_run_dir" "$release_env" "$authority_evidence" "$authority_signature" "$authority_public_key")
fi
for path in "${paths[@]}"; do
  holdfast_require_absolute "$path"
done
holdfast_acquire_lock

state_file="$state_dir/CURRENT.json"
prepare_receipt="$state_dir/OPEN-PREPARE.receipt"
open_receipt="$state_dir/OPEN.receipt"
[[ -f "$state_file" && ! -L "$state_file" ]] || holdfast_die "active apply state is absent"

require_private_root_file() {
  local path=$1 label=$2
  [[ -f "$path" && ! -L "$path" ]] || holdfast_die "$label is unsafe or absent: $path"
  [[ "$(stat -c '%u:%h:%a' -- "$path")" == "0:1:600" ]] || \
    holdfast_die "$label must be root-owned, single-link, and mode 0600: $path"
}

require_private_root_directory() {
  local path=$1 label=$2
  [[ -d "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" ]] || \
    holdfast_die "$label must be a canonical non-symlink directory: $path"
  [[ "$(stat -c '%u:%a' -- "$path")" == "0:700" ]] || \
    holdfast_die "$label must be root-owned and mode 0700: $path"
}

receipt_key_set() {
  local path=$1
  awk -F= '
    !index($0, "=") || $1 == "" || seen[$1]++ { exit 3 }
    { print $1 }
  ' "$path" | LC_ALL=C sort
}

validate_schema4_successor_policy() {
  local policy=$1
  PYTHONPATH="$script_dir" python3 - "$policy" <<'PY'
import sys
from pathlib import Path

from successor_binding import validate_policy

policy = validate_policy(Path(sys.argv[1]))
if policy["schema_version"] != 4:
    raise ValueError("prepare abandonment requires schema-v4 successor policy authority")
PY
}

validate_schema4_gen5_namespaces() {
  local current=$1 apply_receipt=$2 predecessor_current=$3
  local estate=$4 backup=$5 predecessor_backup=$6
  PYTHONPATH="$script_dir" python3 - \
    "$current" "$apply_receipt" "$predecessor_current" \
    "$estate" "$backup" "$predecessor_backup" <<'PY'
import re
import sys
from pathlib import Path

from successor_binding import (
    GEN4_APPLY_RECEIPT_FIELDS,
    GEN4_CURRENT_FIELDS,
    exact_object,
    load_json,
    parse_receipt_bytes,
    read_safe_regular,
    require_hex,
    validate_gen4_current,
)

current_path = Path(sys.argv[1])
apply_path = Path(sys.argv[2])
predecessor_current_path = Path(sys.argv[3])
estate = Path(sys.argv[4])
backup = Path(sys.argv[5])
predecessor_backup = Path(sys.argv[6])
completion_fields = {
    field
    for field in GEN4_CURRENT_FIELDS | GEN4_APPLY_RECEIPT_FIELDS
    if field.startswith("predecessor_completion_")
}

current_fields = (GEN4_CURRENT_FIELDS - completion_fields) | {
    "predecessor_apply_receipt_sha256"
}
current = exact_object(load_json(current_path), current_fields, "Gen5 CURRENT")
current_expected = {
    "schema_version": 2,
    "state": "applied_ingress_closed",
    "estate_root": str(estate),
    "backup_dir": str(backup),
    "route_database_state": "absent",
    "public_ipv4_ipv6_closed_status": 404,
    "ingress_opened": False,
    "successor": True,
    "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
    "predecessor_backup_dir": str(predecessor_backup),
    "predecessor_release_generation": 4,
    "release_generation": 5,
}
for field, expected in current_expected.items():
    if current[field] != expected:
        raise ValueError(f"Gen5 CURRENT differs: {field}")
if not isinstance(current["services_activated"], bool):
    raise ValueError("Gen5 CURRENT services_activated is not boolean")
if current["runtime_verified"] is not current["services_activated"]:
    raise ValueError("Gen5 CURRENT runtime verification differs from activation")
if not re.fullmatch(
    r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    str(current["closed_verified_at"]),
):
    raise ValueError("Gen5 CURRENT closed_verified_at differs")
for field in current_fields:
    if field.endswith("_sha256"):
        require_hex(current[field], f"Gen5 CURRENT {field}")

apply_fields = (GEN4_APPLY_RECEIPT_FIELDS - completion_fields) | {
    "predecessor_apply_receipt_sha256"
}
apply = parse_receipt_bytes(
    read_safe_regular(apply_path, "Gen5 APPLY completion"),
    "Gen5 APPLY completion",
)
if set(apply) != apply_fields:
    raise ValueError("Gen5 APPLY completion field set is not exact")
apply_expected = {
    "schema_version": "2",
    "completion_state": "applied_ingress_closed",
    "estate_root": str(estate),
    "backup_dir": str(backup),
    "cargo_gate": "passed",
    "runtime_backup": "passed",
    "closed_bracket": "passed",
    "route_database_state": "absent",
    "public_ipv4_ipv6_closed_status": "404",
    "ingress_opened": "false",
    "successor": "true",
    "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
    "predecessor_backup_dir": str(predecessor_backup),
    "predecessor_release_generation": "4",
    "release_generation": "5",
}
for field, expected in apply_expected.items():
    if apply[field] != expected:
        raise ValueError(f"Gen5 APPLY completion differs: {field}")
for field in apply_fields:
    if field.endswith("_sha256"):
        require_hex(apply[field], f"Gen5 APPLY completion {field}")
for field in ("applied_at", "closed_verified_at"):
    if not re.fullmatch(
        r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        apply[field],
    ):
        raise ValueError(f"Gen5 APPLY completion {field} differs")

for field in current_fields & apply_fields:
    current_value = current[field]
    if isinstance(current_value, bool):
        current_value = "true" if current_value else "false"
    elif isinstance(current_value, int):
        current_value = str(current_value)
    if str(current_value) != apply[field]:
        raise ValueError(f"Gen5 CURRENT/APPLY alignment differs: {field}")

validate_gen4_current(
    load_json(predecessor_current_path),
    estate=estate,
    backup=predecessor_backup,
)
PY
}

validate_schema4_gen5_recovery_abandon_authority() {
  local current=$1 archive=$2 completion=$3 recovery_arm=$4 failure=$5
  local estate=$6 backup=$7 predecessor_backup=$8
  python3 - \
    "$current" "$archive" "$completion" "$recovery_arm" "$failure" \
    "$estate" "$backup" "$predecessor_backup" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


CURRENT_FIELDS = {
    "schema_version", "state", "apply_armed_at", "estate_root", "backup_dir",
    "apply_armed_receipt_sha256", "release_evidence_sha256",
    "dry_run_receipt_sha256", "control_sha256",
    "runtime_backup_caller_armed_sha256", "runtime_backup_stop_authority_sha256",
    "ingress_opened", "successor", "successor_armed_receipt",
    "successor_armed_receipt_sha256", "predecessor_current_file",
    "predecessor_current_sha256", "predecessor_backup_dir",
    "predecessor_control_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256", "predecessor_release_generation",
    "release_generation", "apply_failure_receipt", "apply_failure_receipt_sha256",
    "recovery_prior_state", "recovery_mode", "recovery_attempt_id",
    "recovery_armed_receipt", "recovery_armed_receipt_sha256",
    "restore_running_writers_manifest", "restore_running_writers_sha256",
    "legacy_empty_strad", "pre_restored_retry", "pre_restored_source_attempt",
    "pre_restored_runtime_snapshot_sha256", "pre_restored_estate_snapshot_sha256",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256", "pre_restored_runtime_disposition",
    "writer_set_reconciled", "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256", "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256", "writer_set_preimage_compose_sha256",
    "writer_set_quarantined", "transaction_sha256", "applied_targets_sha256",
    "recovery_receipt", "recovery_receipt_sha256", "services_activated",
    "runtime_verified",
}
ARCHIVE_FIELDS = CURRENT_FIELDS - {"services_activated", "runtime_verified"}
COMPLETION_FIELDS = (
    "schema_version", "completed_at", "attempt_id", "mode", "estate_root",
    "backup_dir", "control_sha256", "original_estate_transaction_state",
    "original_estate_transaction_sha256", "applied_targets_sha256",
    "legacy_empty_strad", "recovery_armed_receipt_sha256",
    "release_evidence_sha256", "dry_run_receipt_sha256",
    "runtime_restore_receipt_sha256", "estate_restore_state_sha256",
    "pre_restored_retry", "pre_restored_source_attempt",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256", "pre_restored_runtime_disposition",
    "restore_running_writers_manifest", "restore_running_writers_sha256",
    "writer_set_reconciled", "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256", "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256", "writer_set_preimage_compose_sha256",
    "writer_set_quarantined", "writers_reactivated", "uncaptured_writers_inactive",
    "quarantined_writers_inactive", "runtime_verified", "live_estate_disposition",
    "route_state", "route_conflict_cleanup", "public_host",
    "public_ipv4_ipv6_closed_status", "legacy_public_host", "legacy_route_state",
    "legacy_public_ipv4_ipv6_closed_status", "db_public_db_bracket",
    "apply_receipt_created", "successor", "successor_armed_receipt_sha256",
    "predecessor_current_sha256", "predecessor_backup_dir",
    "predecessor_control_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256", "predecessor_release_generation",
    "release_generation",
)
ARM_FIELDS = (
    "schema_version", "armed_at", "attempt_id", "mode", "prior_state",
    "legacy_orphan_adopted", "legacy_empty_strad", "runtime_backup_schema",
    "estate_transaction_state", "estate_root", "backup_dir", "control_sha256",
    "transaction_sha256", "applied_targets_sha256", "apply_armed_receipt_sha256",
    "release_evidence_sha256", "dry_run_receipt_sha256", "live_disposition",
    "restore_running_writers_manifest", "restore_running_writers_sha256",
    "writer_set_reconciled", "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256", "writer_set_source_state_sha256",
    "writer_set_source_manifest_sha256", "writer_set_preimage_compose_sha256",
    "writer_set_quarantined", "pre_restored_retry", "pre_restored_source_attempt",
    "pre_restored_runtime_snapshot_sha256", "pre_restored_estate_snapshot_sha256",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256", "pre_restored_runtime_disposition",
    "route_state", "route_conflict_cleanup", "public_host",
    "public_ipv4_ipv6_closed_status", "legacy_public_host", "legacy_route_state",
    "legacy_public_ipv4_ipv6_closed_status", "db_public_db_bracket", "successor",
    "successor_armed_receipt_sha256", "predecessor_current_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256", "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256", "predecessor_release_generation",
    "release_generation",
)
FAILURE_FIELDS = (
    "failed_at", "phase", "activation_step", "status", "estate_root", "backup_dir",
    "apply_armed_receipt_sha256", "control_sha256", "transaction_sha256",
    "ingress_opened",
)
HEX = re.compile(r"[0-9a-f]{64}")
ATTEMPT = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9]+")
UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def fail(message: str) -> None:
    raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(path: Path, label: str) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        fail(f"{label} is not a root-owned regular file")
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        fail(f"{label} is not single-link mode 0600")


def load_json(path: Path, label: str) -> dict[str, object]:
    safe_file(path, label)

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                fail(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        fail(f"{label} is not a JSON object")
    return value


def exact_json(path: Path, fields: set[str], label: str) -> dict[str, object]:
    value = load_json(path, label)
    if set(value) != fields:
        fail(f"{label} field set is not exact")
    return value


def receipt(path: Path, fields: tuple[str, ...], label: str) -> dict[str, str]:
    safe_file(path, label)
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        fail(f"{label} structure is invalid")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    result: dict[str, str] = {}
    observed: list[str] = []
    for line in lines:
        if line.count("=") != 1:
            fail(f"{label} structure is invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in result:
            fail(f"{label} structure is invalid")
        observed.append(key)
        result[key] = value
    if tuple(observed) != fields:
        fail(f"{label} field set is not exact")
    return result


def expect(values: dict[str, object] | dict[str, str], expected: dict[str, object], label: str) -> None:
    for key, value in expected.items():
        if values.get(key) != value:
            fail(f"{label} differs: {key}")


def require_hex(values: dict[str, object] | dict[str, str], fields: tuple[str, ...], label: str) -> None:
    for field in fields:
        if not isinstance(values.get(field), str) or not HEX.fullmatch(str(values[field])):
            fail(f"{label} contains an invalid hash: {field}")


def timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        fail(f"{label} is not canonical UTC")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail(f"{label} is not canonical UTC")
    return parsed


current_path, archive_path, completion_path, arm_path, failure_path = map(
    Path, sys.argv[1:6]
)
estate, backup, predecessor_backup = map(Path, sys.argv[6:9])
current = exact_json(current_path, CURRENT_FIELDS, "Gen5 recovered CURRENT")
archive = exact_json(archive_path, ARCHIVE_FIELDS, "Gen5 recovery completion archive")

attempt = current["recovery_attempt_id"]
if not isinstance(attempt, str) or not ATTEMPT.fullmatch(attempt):
    fail("Gen5 recovery attempt identity is unsafe")
receipt_name = f"APPLY-RECOVERY-COMPLETE-{attempt}.receipt"
archive_name = f"APPLY-RECOVERY-COMPLETE-{attempt}.json"
arm_name = f"APPLY-RECOVERY-ARMED-{attempt}.receipt"
failure_name = current["apply_failure_receipt"]
if not isinstance(failure_name, str) or not re.fullmatch(
    r"APPLY-ACTIVATION-FAILED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt", failure_name
):
    fail("Gen5 original activation failure identity is unsafe")
if (
    current["recovery_receipt"] != receipt_name
    or current["recovery_armed_receipt"] != arm_name
    or completion_path.name != receipt_name
    or archive_path.name != archive_name
    or arm_path.name != arm_name
    or failure_path.name != failure_name
):
    fail("Gen5 recovery attempt filename linkage differs")

common_current = {
    "schema_version": 2,
    "estate_root": str(estate),
    "backup_dir": str(backup),
    "ingress_opened": False,
    "successor": True,
    "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
    "predecessor_backup_dir": str(predecessor_backup),
    "predecessor_release_generation": 4,
    "release_generation": 5,
    "recovery_prior_state": "apply_activation_failed",
    "recovery_mode": "resume",
    "recovery_attempt_id": attempt,
    "recovery_armed_receipt": arm_name,
    "recovery_receipt": receipt_name,
    "restore_running_writers_manifest": "not-applicable",
    "restore_running_writers_sha256": "none",
    "legacy_empty_strad": False,
    "pre_restored_retry": False,
    "pre_restored_source_attempt": "none",
    "pre_restored_runtime_snapshot_sha256": "none",
    "pre_restored_estate_snapshot_sha256": "none",
    "pre_restored_superseded_attempt": "none",
    "pre_restored_superseded_failure_receipt_sha256": "none",
    "pre_restored_superseded_state_sha256": "none",
    "pre_restored_runtime_disposition": "not-applicable",
    "writer_set_reconciled": False,
    "writer_set_source_attempt": "none",
    "writer_set_source_failure_receipt_sha256": "none",
    "writer_set_source_state_sha256": "none",
    "writer_set_source_manifest_sha256": "none",
    "writer_set_preimage_compose_sha256": "none",
    "writer_set_quarantined": "none",
}
expect(current, {**common_current, "state": "applied_ingress_closed", "services_activated": True, "runtime_verified": True}, "Gen5 recovered CURRENT")
expect(archive, {**common_current, "state": "apply_recovered_resumed"}, "Gen5 recovery completion archive")
current_projection = {key: value for key, value in current.items() if key not in {"state", "services_activated", "runtime_verified"}}
archive_projection = {key: value for key, value in archive.items() if key != "state"}
if current_projection != archive_projection:
    fail("Gen5 recovery CURRENT/archive projection differs")

hash_fields = (
    "apply_armed_receipt_sha256", "release_evidence_sha256", "dry_run_receipt_sha256",
    "control_sha256", "runtime_backup_caller_armed_sha256",
    "runtime_backup_stop_authority_sha256", "successor_armed_receipt_sha256",
    "predecessor_current_sha256", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256", "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256", "apply_failure_receipt_sha256",
    "recovery_armed_receipt_sha256", "transaction_sha256",
    "applied_targets_sha256", "recovery_receipt_sha256",
)
require_hex(current, hash_fields, "Gen5 recovered CURRENT")
if current["recovery_receipt_sha256"] != digest(completion_path):
    fail("Gen5 recovery completion receipt hash differs")
if current["recovery_armed_receipt_sha256"] != digest(arm_path):
    fail("Gen5 recovery arm hash differs")
if current["apply_failure_receipt_sha256"] != digest(failure_path):
    fail("Gen5 original activation failure hash differs")

completion = receipt(completion_path, COMPLETION_FIELDS, "Gen5 recovery completion receipt")
recovery_arm = receipt(arm_path, ARM_FIELDS, "Gen5 recovery arm receipt")
failure = receipt(failure_path, FAILURE_FIELDS, "Gen5 original activation failure receipt")
route = {
    "route_state": "absent",
    "route_conflict_cleanup": "same-name-or-rikune-root-or-analyze-host",
    "public_host": "rikune.w33d.xyz",
    "public_ipv4_ipv6_closed_status": "404",
    "legacy_public_host": "analyze.w33d.xyz",
    "legacy_route_state": "absent",
    "legacy_public_ipv4_ipv6_closed_status": "404",
    "db_public_db_bracket": "absent-404-absent",
}
lineage = {
    "successor": "true",
    "successor_armed_receipt_sha256": str(current["successor_armed_receipt_sha256"]),
    "predecessor_current_sha256": str(current["predecessor_current_sha256"]),
    "predecessor_backup_dir": str(predecessor_backup),
    "predecessor_control_sha256": str(current["predecessor_control_sha256"]),
    "predecessor_apply_receipt_sha256": str(current["predecessor_apply_receipt_sha256"]),
    "predecessor_release_evidence_sha256": str(current["predecessor_release_evidence_sha256"]),
    "predecessor_runtime_backup_receipt_sha256": str(current["predecessor_runtime_backup_receipt_sha256"]),
    "predecessor_runtime_backup_manifest_sha256": str(current["predecessor_runtime_backup_manifest_sha256"]),
    "predecessor_release_generation": "4",
    "release_generation": "5",
}
expect(
    completion,
    {
        "schema_version": "3", "attempt_id": attempt, "mode": "resume",
        "estate_root": str(estate), "backup_dir": str(backup),
        "control_sha256": str(current["control_sha256"]),
        "original_estate_transaction_state": "applied",
        "original_estate_transaction_sha256": str(current["transaction_sha256"]),
        "applied_targets_sha256": str(current["applied_targets_sha256"]),
        "legacy_empty_strad": "false",
        "recovery_armed_receipt_sha256": str(current["recovery_armed_receipt_sha256"]),
        "release_evidence_sha256": str(current["release_evidence_sha256"]),
        "dry_run_receipt_sha256": str(current["dry_run_receipt_sha256"]),
        "runtime_restore_receipt_sha256": "none", "estate_restore_state_sha256": "none",
        "pre_restored_retry": "false", "pre_restored_source_attempt": "none",
        "pre_restored_superseded_attempt": "none",
        "pre_restored_superseded_failure_receipt_sha256": "none",
        "pre_restored_superseded_state_sha256": "none",
        "pre_restored_runtime_disposition": "not-applicable",
        "restore_running_writers_manifest": "not-applicable",
        "restore_running_writers_sha256": "none", "writer_set_reconciled": "false",
        "writer_set_source_attempt": "none",
        "writer_set_source_failure_receipt_sha256": "none",
        "writer_set_source_state_sha256": "none",
        "writer_set_source_manifest_sha256": "none",
        "writer_set_preimage_compose_sha256": "none", "writer_set_quarantined": "none",
        "writers_reactivated": "not-applicable",
        "uncaptured_writers_inactive": "not-applicable",
        "quarantined_writers_inactive": "not-applicable", "runtime_verified": "passed",
        "live_estate_disposition": "applied", "apply_receipt_created": "false",
        **route, **lineage,
    },
    "Gen5 recovery completion receipt",
)
expect(
    recovery_arm,
    {
        "schema_version": "3", "attempt_id": attempt, "mode": "resume",
        "prior_state": "apply_activation_failed", "legacy_orphan_adopted": "false",
        "legacy_empty_strad": "false", "runtime_backup_schema": "2",
        "estate_transaction_state": "applied", "estate_root": str(estate),
        "backup_dir": str(backup), "control_sha256": str(current["control_sha256"]),
        "transaction_sha256": str(current["transaction_sha256"]),
        "applied_targets_sha256": str(current["applied_targets_sha256"]),
        "apply_armed_receipt_sha256": str(current["apply_armed_receipt_sha256"]),
        "release_evidence_sha256": str(current["release_evidence_sha256"]),
        "dry_run_receipt_sha256": str(current["dry_run_receipt_sha256"]),
        "live_disposition": "applied", "restore_running_writers_manifest": "not-applicable",
        "restore_running_writers_sha256": "none", "writer_set_reconciled": "false",
        "writer_set_source_attempt": "none",
        "writer_set_source_failure_receipt_sha256": "none",
        "writer_set_source_state_sha256": "none",
        "writer_set_source_manifest_sha256": "none",
        "writer_set_preimage_compose_sha256": "none", "writer_set_quarantined": "none",
        "pre_restored_retry": "false", "pre_restored_source_attempt": "none",
        "pre_restored_runtime_snapshot_sha256": "none",
        "pre_restored_estate_snapshot_sha256": "none",
        "pre_restored_superseded_attempt": "none",
        "pre_restored_superseded_failure_receipt_sha256": "none",
        "pre_restored_superseded_state_sha256": "none",
        "pre_restored_runtime_disposition": "not-applicable", **route, **lineage,
    },
    "Gen5 recovery arm receipt",
)
expect(
    failure,
    {
        "phase": "activation", "estate_root": str(estate), "backup_dir": str(backup),
        "apply_armed_receipt_sha256": str(current["apply_armed_receipt_sha256"]),
        "control_sha256": str(current["control_sha256"]),
        "transaction_sha256": str(current["transaction_sha256"]),
        "ingress_opened": "false",
    },
    "Gen5 original activation failure receipt",
)
if failure["activation_step"] not in {"compose_up", "runtime_verify"}:
    fail("Gen5 original activation failure step differs")
if not re.fullmatch(r"[1-9][0-9]{0,2}", failure["status"]) or int(failure["status"]) > 255:
    fail("Gen5 original activation failure status differs")

apply_armed_at = timestamp(current["apply_armed_at"], "Gen5 apply armed time")
failed_at = timestamp(failure["failed_at"], "Gen5 activation failure time")
recovery_armed_at = timestamp(recovery_arm["armed_at"], "Gen5 recovery armed time")
completed_at = timestamp(completion["completed_at"], "Gen5 recovery completed time")
if not apply_armed_at <= failed_at <= recovery_armed_at <= completed_at:
    fail("Gen5 recovery producer timestamps are out of order")

matches: list[str] = []
for entry in current_path.parent.iterdir():
    if not entry.name.startswith("APPLY-RECOVERY-COMPLETE-") or not entry.name.endswith(".json"):
        continue
    if not re.fullmatch(r"APPLY-RECOVERY-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.json", entry.name):
        fail("Gen5 recovery completion candidate name is unsafe")
    candidate = load_json(entry, "Gen5 recovery completion candidate")
    if candidate.get("backup_dir") == str(backup) and candidate.get("state") == "apply_recovered_resumed":
        matches.append(entry.name)
if matches != [archive_name]:
    fail("Gen5 recovery completion archive match is not unique")
PY
}

snapshot_recovery_abandon_namespace() {
  python3 - "$state_dir" <<'PY'
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
patterns = (
    re.compile(r"CURRENT\.json"),
    re.compile(r"APPLY-RECOVERY-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.(?:json|receipt)"),
    re.compile(r"APPLY-RECOVERY-ARMED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt"),
    re.compile(r"APPLY-ACTIVATION-FAILED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt"),
)
snapshot = hashlib.sha256()
for entry in sorted(root.iterdir(), key=lambda item: item.name):
    if not any(pattern.fullmatch(entry.name) for pattern in patterns):
        continue
    metadata = entry.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise ValueError(f"unsafe recovery abandonment namespace entry: {entry}")
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError(f"unsafe recovery abandonment namespace entry: {entry}")
    digest = hashlib.sha256(entry.read_bytes()).hexdigest()
    snapshot.update(
        f"{entry.name}\0{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:{metadata.st_mtime_ns}\0{digest}\n".encode()
    )
print(snapshot.hexdigest())
PY
}

validate_historical_rollback_abandon_authority() {
  local source_prepare=$1 release_validator=$2
  python3 - \
    "$state_dir" "$source_prepare" "$successor_abandon_estate_root" \
    "$successor_abandon_predecessor_backup" "$release_validator" "$script_dir" <<'PY'
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


STATE_DIR, PREPARE, ESTATE, ACTIVE_GEN4, RELEASE_VALIDATOR, SCRIPT_DIR = map(
    Path, sys.argv[1:7]
)
HEX = re.compile(r"[0-9a-f]{64}")
ATTEMPT = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9]+")
UTC = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
RELEASE_SERVICES = (
    "access-governance", "verdict", "newapi", "rikune-analyzer", "strad",
    "sluice", "sluice-internal",
)
WRITER_SERVICES = ("strad", "rikune-analyzer")
GEN1_CONTROL_NAMES = {
    "APPLY-ABSENT.paths", "APPLY-ARMED.receipt", "APPLY-PREIMAGES.sha256",
    "DRY-RUN.receipt", "RELEASE-EVIDENCE.json", "RENDER-INPUTS.sha256",
    "RUNTIME-BACKUP-CALLER-ARMED.receipt", "SUPPLY-CHAIN.json",
    "SUPPLY-CHAIN.pub", "SUPPLY-CHAIN.sig", "TARGETS.sha256", "release.env",
    "rollback.override.yml", "runtime/BACKUP.receipt",
    "runtime/RUNNING-SERVICES.before", "runtime/RUNTIME-BACKUP-ARMED.receipt",
    "runtime/SHA256SUMS",
}
GEN2_CONTROL_NAMES = GEN1_CONTROL_NAMES | {
    "PREDECESSOR-CURRENT.json", "SUCCESSOR-ARMED.receipt", "SUCCESSOR-DELTA.sha256",
    "successor-authority/Dockerfile.analyzer",
    "successor-authority/bridge-package-lock.json",
    "successor-authority/assets/20260823_rikune_root_up.sql",
    "successor-authority/assets/20260823_rikune_root_down.sql",
    "successor-authority/successor-absent.paths",
    "successor-authority/successor-frozen-targets.json",
    "successor-authority/successor-policy.json",
    "successor-authority/successor-preimages.sha256",
    "successor-authority/successor-static-targets.sha256",
    "successor-authority/successor-supporting-targets.sha256",
}
GEN1_RUNTIME_NAMES = {
    "RUNNING-SERVICES.before", "RUNTIME-BACKUP-ARMED.receipt", "VOLUMES.tsv",
    "compose-config.json", "strad.dump",
}
GEN2_RUNTIME_NAMES = GEN1_RUNTIME_NAMES | {
    "rikune_audit.tar", "rikune_cache.tar", "rikune_state.tar",
    "rikune_storage.tar", "rikune_workspaces.tar", "strad_uploads.tar",
}
GEN1_CURRENT_FIELDS = {
    "schema_version", "state", "estate_root", "backup_dir",
    "apply_receipt_sha256", "apply_armed_receipt_sha256", "control_sha256",
    "release_evidence_sha256", "transaction_sha256", "applied_targets_sha256",
    "closed_verified_at", "route_database_state",
    "public_ipv4_ipv6_closed_status", "services_activated", "runtime_verified",
    "ingress_opened",
}
SUCCESSOR_FIELDS = {
    "successor", "successor_armed_receipt", "successor_armed_receipt_sha256",
    "predecessor_current_file", "predecessor_current_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
}
LEGACY_POLICY_PREDECESSOR_FIELDS = {
    "current_state_sha256", "control_sha256", "apply_receipt_sha256",
    "release_evidence_sha256", "runtime_manifest_sha256",
    "candidate_evidence_sha256", "candidate_targets_sha256", "access_image",
    "access_build_input_schema", "access_build_input_sha256",
    "permission_catalog_sha256", "package_catalog_sha256",
}
GEN2_CURRENT_FIELDS = GEN1_CURRENT_FIELDS | SUCCESSOR_FIELDS | {
    "runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256",
}
ACTIVE_GEN3_CURRENT_FIELDS = {
    "applied_targets_sha256", "apply_armed_at", "apply_armed_receipt_sha256",
    "apply_failure_receipt", "apply_failure_receipt_sha256", "backup_dir",
    "control_sha256", "dry_run_receipt_sha256", "estate_root", "ingress_opened",
    "legacy_empty_strad", "pre_restored_estate_snapshot_sha256",
    "pre_restored_retry", "pre_restored_runtime_disposition",
    "pre_restored_runtime_snapshot_sha256", "pre_restored_source_attempt",
    "pre_restored_superseded_attempt",
    "pre_restored_superseded_failure_receipt_sha256",
    "pre_restored_superseded_state_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_current_file", "predecessor_current_sha256",
    "predecessor_release_evidence_sha256", "predecessor_release_generation",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_runtime_backup_receipt_sha256", "recovery_armed_receipt",
    "recovery_armed_receipt_sha256", "recovery_attempt_id", "recovery_mode",
    "recovery_prior_state", "recovery_receipt", "recovery_receipt_sha256",
    "release_evidence_sha256", "release_generation",
    "restore_running_writers_manifest", "restore_running_writers_sha256",
    "runtime_backup_caller_armed_sha256", "runtime_backup_stop_authority_sha256",
    "runtime_verified", "schema_version", "services_activated", "state",
    "successor", "successor_armed_receipt", "successor_armed_receipt_sha256",
    "transaction_sha256", "writer_set_preimage_compose_sha256",
    "writer_set_quarantined", "writer_set_reconciled", "writer_set_source_attempt",
    "writer_set_source_failure_receipt_sha256", "writer_set_source_manifest_sha256",
    "writer_set_source_state_sha256",
}
BASE_APPLY_FIELDS = (
    "schema_version", "completion_state", "applied_at", "closed_verified_at",
    "estate_root", "backup_dir", "release_env_sha256",
    "release_evidence_sha256", "render_inputs_sha256",
    "apply_armed_receipt_sha256", "control_sha256", "transaction_sha256",
    "applied_targets_sha256", "cargo_gate", "runtime_backup", "closed_bracket",
    "route_database_state", "public_ipv4_ipv6_closed_status", "ingress_opened",
    "services_activated", "runtime_verified",
)
GEN2_APPLY_FIELDS = BASE_APPLY_FIELDS + (
    "successor", "successor_armed_receipt", "successor_armed_receipt_sha256",
    "predecessor_current_file", "predecessor_current_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
    "runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256",
)
SUCCESSOR_ARM_FIELDS = (
    "schema_version", "armed_at", "estate_root", "successor_backup_dir",
    "candidate_dry_run_receipt_sha256", "candidate_release_evidence_sha256",
    "predecessor_current_file", "predecessor_current_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
    "route_database_state", "public_ipv4_ipv6_closed_status",
    "predecessor_runtime_verified", "ingress_opened",
)
ROLLBACK_COMPLETION_FIELDS = {
    "schema_version", "state", "estate_root", "backup_dir",
    "apply_receipt_sha256", "apply_armed_receipt_sha256", "control_sha256",
    "release_evidence_sha256", "transaction_sha256", "applied_targets_sha256",
    "closed_verified_at", "route_database_state",
    "public_ipv4_ipv6_closed_status", "services_activated", "runtime_verified",
    "ingress_opened", "successor", "successor_armed_receipt",
    "successor_armed_receipt_sha256", "predecessor_current_file",
    "predecessor_current_sha256", "predecessor_backup_dir",
    "predecessor_control_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
    "runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256",
    "open_prepare_receipt_sha256", "last_open_interrupted_receipt_sha256",
    "route_close_receipt", "route_close_receipt_sha256",
    "route_close_preimage", "route_close_preimage_sha256",
    "rollback_attempt_id", "rollback_running_services_manifest",
    "rollback_running_services_sha256", "rollback_armed_receipt",
    "rollback_armed_receipt_sha256", "rollback_runtime_restore_phase_receipt",
    "rollback_runtime_restore_phase_receipt_sha256",
    "rollback_estate_restore_phase_receipt",
    "rollback_estate_restore_phase_receipt_sha256",
    "rollback_estate_transaction_sha256",
    "rollback_services_reactivated_phase_receipt",
    "rollback_services_reactivated_phase_receipt_sha256",
    "rollback_receipt_sha256",
}
ROLLBACK_RECEIPT_FIELDS = (
    "schema_version", "rolled_back_at", "rollback_armed_receipt_sha256",
    "running_services_sha256", "runtime_prior_services_sha256",
    "runtime_restore_phase_receipt_sha256",
    "estate_restore_phase_receipt_sha256",
    "services_reactivated_phase_receipt_sha256", "route_close_receipt",
    "route_close_receipt_sha256", "route_close_preimage",
    "route_close_preimage_sha256", "revocation_evidence_sha256",
    "open_evidence_sha256", "runtime_restore_receipt_sha256",
    "estate_transaction_sha256", "runtime_restore", "mixed_estate_restore",
    "orphan_cleanup", "service_reactivation", "reactivated_services",
    "excluded_services_inactive", "activation_policy",
    "activate_services_requested", "public_route_state", "ingress_opened",
    "successor", "successor_armed_receipt_sha256",
    "predecessor_current_sha256", "predecessor_backup_dir",
    "predecessor_control_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
)
ROLLBACK_ARM_FIELDS = (
    "schema_version", "armed_at", "attempt_id", "estate_root", "backup_dir",
    "control_sha256", "transaction_sha256", "applied_targets_sha256",
    "targets_sha256", "apply_preimages_sha256", "apply_absent_sha256",
    "route_close_receipt", "route_close_receipt_sha256",
    "route_close_preimage", "route_close_preimage_sha256",
    "open_evidence_file", "open_evidence_sha256", "open_signature_file",
    "open_signature_sha256", "authority_public_key_file",
    "authority_public_key_sha256", "revocation_evidence_file",
    "revocation_evidence_sha256", "revocation_signature_file",
    "revocation_signature_sha256", "edge_rollback_evidence_file",
    "edge_rollback_evidence_sha256", "edge_rollback_signature_file",
    "edge_rollback_signature_sha256", "open_edge_evidence_file",
    "open_edge_evidence_sha256", "compose_project", "release_service_count",
    "release_services", "running_services_manifest", "running_services_sha256",
    "runtime_prior_services_sha256", "activate_services_requested",
    "activation_policy", "ingress_opened", "successor",
    "successor_armed_receipt_sha256", "predecessor_current_sha256",
    "predecessor_backup_dir", "predecessor_control_sha256",
    "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256",
    "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
    "predecessor_release_generation", "release_generation",
)
INTERRUPTED_FIELDS = (
    "interrupted_at", "reason", "prior_state", "open_prepare_receipt_sha256",
    "preopen_edge_evidence_sha256", "route_down_sha256",
    "route_down_execution_evidence_sha256", "route_state", "public_host",
    "edge_owner", "db_public_db_bracket", "external_edge_mutation",
)
LEGACY_ANALYZE_PREPARE_FIELDS = {
    "db_public_db_bracket", "edge_owner", "external_edge_mutation",
    "open_evidence_sha256", "prepared_at", "public_host",
    "public_ipv4_ipv6_closed_status", "release_evidence_sha256", "route_state",
    "source_grant_id",
}
HISTORICAL_PUBLIC_HOST = "analyze.w33d.xyz"
RUNTIME_PHASE_FIELDS = (
    "schema_version", "phase", "completed_at", "attempt_id",
    "rollback_armed_receipt_sha256", "runtime_restore_receipt_sha256",
    "runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256",
    "transaction_before_sha256", "applied_targets_sha256", "ingress_opened",
)
ESTATE_PHASE_FIELDS = (
    "schema_version", "phase", "completed_at", "attempt_id",
    "rollback_armed_receipt_sha256", "runtime_restore_phase_receipt_sha256",
    "estate_transaction_sha256", "applied_targets_sha256", "preimages_sha256",
    "absent_sha256", "live_estate_disposition", "ingress_opened",
)
SERVICES_PHASE_FIELDS = (
    "schema_version", "phase", "completed_at", "attempt_id",
    "rollback_armed_receipt_sha256", "estate_restore_phase_receipt_sha256",
    "reactivated_services", "excluded_services_inactive", "ingress_opened",
)


def fail(message: str) -> None:
    raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


tracked: dict[str, tuple[str, str]] = {}
trees: dict[str, tuple[str, ...]] = {}


def metadata(path: Path) -> tuple[os.stat_result, str]:
    value = path.lstat()
    return value, (
        f"{value.st_dev}:{value.st_ino}:{value.st_mode}:{value.st_uid}:"
        f"{value.st_gid}:{value.st_nlink}:{value.st_size}:{value.st_mtime_ns}"
    )


def safe_file(path: Path, label: str, *, private: bool = True, track: bool = True) -> bytes:
    try:
        value, identity = metadata(path)
    except FileNotFoundError:
        fail(f"{label} is absent")
    if not stat.S_ISREG(value.st_mode) or path.is_symlink() or value.st_uid != 0:
        fail(f"{label} is not a root-owned regular file")
    if value.st_nlink != 1 or value.st_mode & 0o022:
        fail(f"{label} has unsafe links or write permissions")
    if private and stat.S_IMODE(value.st_mode) != 0o600:
        fail(f"{label} is not mode 0600")
    raw = path.read_bytes()
    if track:
        tracked[str(path)] = (identity, sha(raw))
    return raw


def safe_dir(path: Path, label: str, *, exact_mode: int | None = 0o700) -> Path:
    if not path.is_absolute() or path == Path("/"):
        fail(f"{label} path is unsafe")
    value, _ = metadata(path)
    if (
        not stat.S_ISDIR(value.st_mode) or path.is_symlink()
        or path.resolve() != path or value.st_uid != 0
        or value.st_mode & 0o022
        or (exact_mode is not None and stat.S_IMODE(value.st_mode) != exact_mode)
    ):
        mode_contract = "mode-0700" if exact_mode == 0o700 else "non-writable"
        fail(f"{label} is not a canonical root-owned {mode_contract} directory")
    return path


def tree_snapshot(root: Path, label: str) -> None:
    safe_dir(root, label)
    root_device = root.stat().st_dev
    rows: list[str] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in directories + files:
            path = current_path / name
            value, identity = metadata(path)
            if value.st_dev != root_device or value.st_uid != 0 or path.is_symlink():
                fail(f"{label} contains an unsafe entry: {path}")
            if stat.S_ISDIR(value.st_mode):
                if value.st_mode & 0o022:
                    fail(f"{label} contains a writable directory: {path}")
            elif not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_mode & 0o022:
                fail(f"{label} contains an unsafe file: {path}")
            rows.append(f"{path.relative_to(root)}\0{identity}")
    trees[str(root)] = tuple(rows)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_object(path: Path, label: str, *, private: bool = True, track: bool = True) -> dict[str, object]:
    raw = safe_file(path, label, private=private, track=track)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not exact JSON: {error}") from error
    if not isinstance(value, dict):
        fail(f"{label} is not a JSON object")
    return value


def exact_json(path: Path, fields: set[str], label: str) -> dict[str, object]:
    value = json_object(path, label)
    if set(value) != fields:
        fail(f"{label} field set is not exact")
    return value


def parse_receipt_raw(raw: bytes, label: str) -> tuple[dict[str, str], tuple[str, ...]]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        fail(f"{label} structure is invalid")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    result: dict[str, str] = {}
    keys: list[str] = []
    for line in lines:
        if line.count("=") != 1:
            fail(f"{label} structure is invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in result:
            fail(f"{label} structure is invalid")
        keys.append(key)
        result[key] = value
    return result, tuple(keys)


def receipt(path: Path, fields: tuple[str, ...], label: str) -> dict[str, str]:
    result, keys = parse_receipt_raw(safe_file(path, label), label)
    if keys != fields:
        fail(f"{label} field set or order is not exact")
    return result


def expect(values: dict[str, object] | dict[str, str], expected: dict[str, object], label: str) -> None:
    for key, value in expected.items():
        if values.get(key) != value:
            fail(f"{label} differs: {key}")


def require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        fail(f"{label} is not lowercase SHA-256")
    return value


def utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        fail(f"{label} is not canonical UTC")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail(f"{label} is not canonical UTC")
    return parsed


def safe_relative(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} contains an unsafe path")
    return path


def verify_manifest(root: Path, path: Path, label: str) -> set[str]:
    raw = safe_file(path, label)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    names: set[str] = set()
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if match is None:
            fail(f"{label} contains a malformed checksum line")
        expected, name = match.groups()
        if name in names:
            fail(f"{label} repeats a path")
        relative = safe_relative(name, label)
        artifact = root / relative
        if sha(safe_file(artifact, f"{label} artifact", private=False)) != expected:
            fail(f"{label} artifact hash differs: {name}")
        names.add(name)
    if not names:
        fail(f"{label} is empty")
    return names


def require_manifest_paths(observed: set[str], required: set[str], label: str) -> None:
    missing = sorted(required - observed)
    if missing:
        fail(f"{label} omits required authority: {missing[0]}")


def services_manifest(
    path: Path, label: str, allowed_order: tuple[str, ...]
) -> tuple[str, ...]:
    raw = safe_file(path, label)
    try:
        lines = tuple(raw.decode("utf-8").splitlines())
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    indexes: list[int] = []
    for name in lines:
        if name not in allowed_order:
            fail(f"{label} contains an unknown service")
        indexes.append(allowed_order.index(name))
    if indexes != sorted(set(indexes)):
        fail(f"{label} is duplicated or out of order")
    return lines


def run_validator(arguments: list[str], label: str) -> None:
    completed = subprocess.run(
        [sys.executable, *arguments], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    if completed.returncode != 0:
        fail(f"{label} rejected the frozen authority")


def validate_apply(
    backup: Path, current: dict[str, object], generation: int, *, successor: bool
) -> dict[str, str]:
    fields = GEN2_APPLY_FIELDS if successor else BASE_APPLY_FIELDS
    values = receipt(backup / "APPLY.receipt", fields, f"Gen{generation} APPLY")
    expected: dict[str, object] = {
        "schema_version": "2", "completion_state": "applied_ingress_closed",
        "estate_root": str(ESTATE), "backup_dir": str(backup),
        "cargo_gate": "passed", "runtime_backup": "passed",
        "closed_bracket": "passed", "route_database_state": "absent",
        "public_ipv4_ipv6_closed_status": "404", "ingress_opened": "false",
        "services_activated": "true", "runtime_verified": "true",
    }
    if successor:
        expected.update({
            "successor": "true", "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
            "predecessor_current_file": "PREDECESSOR-CURRENT.json",
            "predecessor_release_generation": str(generation - 1),
            "release_generation": str(generation),
        })
    expect(values, expected, f"Gen{generation} APPLY")
    for field in fields:
        if field.endswith("_sha256"):
            require_hash(values[field], f"Gen{generation} APPLY {field}")
    for field in GEN1_CURRENT_FIELDS & set(values):
        observed: object = values[field]
        expected_value: object = current[field]
        if isinstance(expected_value, bool):
            observed = observed == "true" if observed in {"true", "false"} else observed
        elif isinstance(expected_value, int):
            observed = int(observed) if observed.isdigit() else observed
        if observed != expected_value:
            fail(f"Gen{generation} CURRENT/APPLY projection differs: {field}")
    return values


def validate_gen1(current_path: Path, expected_backup: Path | None = None) -> tuple[dict[str, object], Path]:
    current = exact_json(current_path, GEN1_CURRENT_FIELDS, "Gen1 CURRENT")
    backup = safe_dir(Path(str(current["backup_dir"])), "Gen1 backup")
    if expected_backup is not None and backup != expected_backup:
        fail("Gen1 CURRENT backup linkage differs")
    expect(current, {
        "schema_version": 2, "state": "applied_ingress_closed",
        "estate_root": str(ESTATE), "backup_dir": str(backup),
        "route_database_state": "absent", "public_ipv4_ipv6_closed_status": 404,
        "services_activated": True, "runtime_verified": True, "ingress_opened": False,
    }, "Gen1 CURRENT")
    for field in GEN1_CURRENT_FIELDS:
        if field.endswith("_sha256"):
            require_hash(current[field], f"Gen1 CURRENT {field}")
    tree_snapshot(backup, "Gen1 backup")
    control_names = verify_manifest(backup, backup / "CONTROL.sha256", "Gen1 CONTROL")
    if control_names != GEN1_CONTROL_NAMES:
        fail("Gen1 CONTROL pathname set is not exact")
    runtime_names = verify_manifest(backup / "runtime", backup / "runtime/SHA256SUMS", "Gen1 runtime manifest")
    if runtime_names != GEN1_RUNTIME_NAMES:
        fail("Gen1 runtime manifest pathname set is not exact")
    if sha(safe_file(backup / "CONTROL.sha256", "Gen1 CONTROL")) != current["control_sha256"]:
        fail("Gen1 CURRENT CONTROL differs")
    if sha(safe_file(backup / "RELEASE-EVIDENCE.json", "Gen1 release")) != current["release_evidence_sha256"]:
        fail("Gen1 CURRENT release evidence differs")
    if sha(safe_file(backup / "APPLY.receipt", "Gen1 APPLY")) != current["apply_receipt_sha256"]:
        fail("Gen1 CURRENT APPLY differs")
    apply = validate_apply(backup, current, 1, successor=False)
    for field, relative in {
        "apply_armed_receipt_sha256": "APPLY-ARMED.receipt",
        "transaction_sha256": "estate/TRANSACTION.json",
        "applied_targets_sha256": "estate/APPLIED-TARGETS.sha256",
    }.items():
        if sha(safe_file(backup / relative, f"Gen1 {relative}")) != current[field]:
            fail(f"Gen1 CURRENT artifact differs: {field}")
    if apply["control_sha256"] != current["control_sha256"]:
        fail("Gen1 APPLY CONTROL differs")
    return current, backup


def validate_gen2_current(current_path: Path, label: str) -> tuple[dict[str, object], Path, dict[str, str]]:
    current = exact_json(current_path, GEN2_CURRENT_FIELDS, label)
    backup = safe_dir(Path(str(current["backup_dir"])), f"{label} backup")
    predecessor_backup = safe_dir(Path(str(current["predecessor_backup_dir"])), f"{label} predecessor")
    expect(current, {
        "schema_version": 2, "state": "applied_ingress_closed",
        "estate_root": str(ESTATE), "backup_dir": str(backup),
        "route_database_state": "absent", "public_ipv4_ipv6_closed_status": 404,
        "services_activated": True, "runtime_verified": True, "ingress_opened": False,
        "successor": True, "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
        "predecessor_current_file": "PREDECESSOR-CURRENT.json",
        "predecessor_release_generation": 1, "release_generation": 2,
    }, label)
    for field in GEN2_CURRENT_FIELDS:
        if field.endswith("_sha256"):
            require_hash(current[field], f"{label} {field}")
    tree_snapshot(backup, f"{label} backup")
    control_names = verify_manifest(backup, backup / "CONTROL.sha256", f"{label} CONTROL")
    if control_names != GEN2_CONTROL_NAMES:
        fail(f"{label} CONTROL pathname set is not exact")
    runtime_names = verify_manifest(backup / "runtime", backup / "runtime/SHA256SUMS", f"{label} runtime manifest")
    if runtime_names != GEN2_RUNTIME_NAMES:
        fail(f"{label} runtime manifest pathname set is not exact")
    bindings = {
        "control_sha256": backup / "CONTROL.sha256",
        "release_evidence_sha256": backup / "RELEASE-EVIDENCE.json",
        "apply_receipt_sha256": backup / "APPLY.receipt",
        "apply_armed_receipt_sha256": backup / "APPLY-ARMED.receipt",
        "transaction_sha256": backup / "estate/TRANSACTION.json",
        "applied_targets_sha256": backup / "estate/APPLIED-TARGETS.sha256",
        "successor_armed_receipt_sha256": backup / "SUCCESSOR-ARMED.receipt",
        "predecessor_current_sha256": backup / "PREDECESSOR-CURRENT.json",
        "predecessor_control_sha256": predecessor_backup / "CONTROL.sha256",
        "predecessor_apply_receipt_sha256": predecessor_backup / "APPLY.receipt",
        "predecessor_release_evidence_sha256": predecessor_backup / "RELEASE-EVIDENCE.json",
        "predecessor_runtime_backup_receipt_sha256": predecessor_backup / "runtime/BACKUP.receipt",
        "predecessor_runtime_backup_manifest_sha256": predecessor_backup / "runtime/SHA256SUMS",
        "runtime_backup_receipt_sha256": backup / "runtime/BACKUP.receipt",
        "runtime_backup_manifest_sha256": backup / "runtime/SHA256SUMS",
    }
    for field, path in bindings.items():
        if sha(safe_file(path, f"{label} artifact {field}")) != current[field]:
            fail(f"{label} artifact differs: {field}")
    apply = validate_apply(backup, current, 2, successor=True)
    for field in (SUCCESSOR_FIELDS | {"runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256"}) & set(apply):
        expected_value = current[field]
        observed: object = apply[field]
        if isinstance(expected_value, bool):
            observed = observed == "true"
        elif isinstance(expected_value, int):
            observed = int(observed)
        if observed != expected_value:
            fail(f"{label} APPLY lineage differs: {field}")
    arm = receipt(backup / "SUCCESSOR-ARMED.receipt", SUCCESSOR_ARM_FIELDS, f"{label} successor arm")
    expect(arm, {
        "schema_version": "1", "estate_root": str(ESTATE),
        "successor_backup_dir": str(backup),
        "candidate_dry_run_receipt_sha256": sha(safe_file(backup / "DRY-RUN.receipt", f"{label} dry run")),
        "candidate_release_evidence_sha256": str(current["release_evidence_sha256"]),
        "predecessor_current_file": "PREDECESSOR-CURRENT.json",
        "predecessor_current_sha256": str(current["predecessor_current_sha256"]),
        "predecessor_backup_dir": str(predecessor_backup),
        "predecessor_control_sha256": str(current["predecessor_control_sha256"]),
        "predecessor_apply_receipt_sha256": str(current["predecessor_apply_receipt_sha256"]),
        "predecessor_release_evidence_sha256": str(current["predecessor_release_evidence_sha256"]),
        "predecessor_runtime_backup_receipt_sha256": str(current["predecessor_runtime_backup_receipt_sha256"]),
        "predecessor_runtime_backup_manifest_sha256": str(current["predecessor_runtime_backup_manifest_sha256"]),
        "predecessor_release_generation": "1", "release_generation": "2",
        "route_database_state": "absent", "public_ipv4_ipv6_closed_status": "404",
        "predecessor_runtime_verified": "true", "ingress_opened": "false",
    }, f"{label} successor arm")
    policy = json_object(backup / "successor-authority/successor-policy.json", f"{label} policy")
    if set(policy) != {"schema_version", "ceremony", "predecessor", "successor", "overlay"}:
        fail(f"{label} policy field set is not exact")
    if policy["schema_version"] != 1 or policy["ceremony"] != "holdfast-rikune-successor-v1":
        fail(f"{label} policy namespace differs")
    predecessor = policy.get("predecessor")
    if not isinstance(predecessor, dict) or set(predecessor) != LEGACY_POLICY_PREDECESSOR_FIELDS:
        fail(f"{label} policy predecessor field set is not exact")
    for field, expected in {
        "current_state_sha256": current["predecessor_current_sha256"],
        "control_sha256": current["predecessor_control_sha256"],
        "apply_receipt_sha256": current["predecessor_apply_receipt_sha256"],
        "release_evidence_sha256": current["predecessor_release_evidence_sha256"],
        "runtime_manifest_sha256": current["predecessor_runtime_backup_manifest_sha256"],
    }.items():
        if predecessor.get(field) != expected:
            fail(f"{label} policy predecessor differs: {field}")
    return current, backup, apply


safe_dir(STATE_DIR, "state directory")
safe_dir(ESTATE, "estate root", exact_mode=None)
safe_dir(ACTIVE_GEN4, "active Gen4 backup")
tree_snapshot(ACTIVE_GEN4, "active Gen4 backup")
safe_file(RELEASE_VALIDATOR, "release validator", private=False)
safe_file(SCRIPT_DIR / "authority_evidence.py", "authority validator", private=False)
prepare_raw = safe_file(PREPARE, "stale OPEN-PREPARE", track=False)
prepare_values, prepare_keys = parse_receipt_raw(prepare_raw, "stale OPEN-PREPARE")
prepare_sha = sha(prepare_raw)
if set(prepare_keys) != LEGACY_ANALYZE_PREPARE_FIELDS:
    fail("historical stale prepare is not the legacy analyze contract")
expect(prepare_values, {
    "route_state": "absent", "public_host": HISTORICAL_PUBLIC_HOST,
    "edge_owner": "existing-w33d-sluice", "public_ipv4_ipv6_closed_status": "404",
    "db_public_db_bracket": "absent-404-absent", "external_edge_mutation": "none",
}, "historical stale prepare")
source_release = require_hash(prepare_values.get("release_evidence_sha256"), "source release evidence")
source_open = require_hash(prepare_values.get("open_evidence_sha256"), "source open evidence")

namespace_rows: list[str] = []
completion_candidates: list[tuple[Path, dict[str, object]]] = []
interrupted_candidates: list[Path] = []
for entry in sorted(STATE_DIR.iterdir(), key=lambda item: item.name):
    if re.fullmatch(r"ROLLBACK-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.json", entry.name):
        raw = safe_file(entry, "rollback completion namespace")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            fail("rollback completion namespace contains a non-object")
        namespace_rows.append(f"{entry.name}\0{tracked[str(entry)][0]}\0{sha(raw)}")
        if value.get("open_prepare_receipt_sha256") == prepare_sha or value.get("release_evidence_sha256") == source_release:
            completion_candidates.append((entry, value))
    elif re.fullmatch(r"OPEN-INTERRUPTED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt", entry.name):
        raw = safe_file(entry, "open interrupted namespace")
        namespace_rows.append(f"{entry.name}\0{tracked[str(entry)][0]}\0{sha(raw)}")
        interrupted_candidates.append(entry)
if len(completion_candidates) != 1:
    fail("historical rollback authority match is not unique")
completion_path, candidate_value = completion_candidates[0]
completion = exact_json(completion_path, ROLLBACK_COMPLETION_FIELDS, "historical rollback completion")
attempt = completion["rollback_attempt_id"]
if not isinstance(attempt, str) or not ATTEMPT.fullmatch(attempt) or completion_path.name != f"ROLLBACK-COMPLETE-{attempt}.json":
    fail("historical rollback completion identity is unsafe")
backup = safe_dir(Path(str(completion["backup_dir"])), "historical rollback backup")
tree_snapshot(backup, "historical rollback backup")
expect(completion, {
    "schema_version": 2, "state": "rolled_back", "estate_root": str(ESTATE),
    "backup_dir": str(backup), "route_database_state": "absent",
    "public_ipv4_ipv6_closed_status": 404, "services_activated": True,
    "runtime_verified": True, "ingress_opened": False, "successor": True,
    "successor_armed_receipt": "SUCCESSOR-ARMED.receipt",
    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
    "predecessor_release_generation": 1, "release_generation": 2,
    "open_prepare_receipt_sha256": prepare_sha,
    "release_evidence_sha256": source_release,
    "rollback_running_services_manifest": f"ROLLBACK-RUNNING-SERVICES-{attempt}.before",
    "rollback_armed_receipt": f"ROLLBACK-EXECUTE-ARMED-{attempt}.receipt",
    "rollback_runtime_restore_phase_receipt": f"ROLLBACK-RUNTIME-RESTORE-DONE-{attempt}.receipt",
    "rollback_estate_restore_phase_receipt": f"ROLLBACK-ESTATE-RESTORE-DONE-{attempt}.receipt",
    "rollback_services_reactivated_phase_receipt": f"ROLLBACK-SERVICES-REACTIVATED-DONE-{attempt}.receipt",
}, "historical rollback completion")
for field in ROLLBACK_COMPLETION_FIELDS:
    if field.endswith("_sha256"):
        require_hash(completion[field], f"historical rollback completion {field}")

interrupted_matches = [
    path for path in interrupted_candidates
    if sha(safe_file(path, "open interrupted candidate")) == completion["last_open_interrupted_receipt_sha256"]
]
if len(interrupted_matches) != 1:
    fail("historical interrupted authority match is not unique")
interrupted_path = interrupted_matches[0]
interrupted = receipt(interrupted_path, INTERRUPTED_FIELDS, "historical open interrupted receipt")
expect(interrupted, {
    "reason": "finalize-error-compensated", "prior_state": "finalizing_route_armed",
    "open_prepare_receipt_sha256": prepare_sha, "route_state": "absent",
    "public_host": prepare_values["public_host"], "edge_owner": "existing-w33d-sluice",
    "db_public_db_bracket": "absent-404-absent", "external_edge_mutation": "none",
}, "historical open interrupted receipt")
for field in ("preopen_edge_evidence_sha256", "route_down_sha256", "route_down_execution_evidence_sha256"):
    require_hash(interrupted[field], f"historical interrupted {field}")
interrupted_identity = re.fullmatch(
    r"OPEN-INTERRUPTED-[0-9]{8}T[0-9]{6}Z-([0-9]+)\.receipt",
    interrupted_path.name,
)
if interrupted_identity is None:
    fail("historical interrupted receipt identity is unsafe")
interrupted_execution_candidates = []
interrupted_execution_pattern = re.compile(
    rf"OPEN-ROUTE-DOWN-[0-9]{{8}}T[0-9]{{6}}Z-{re.escape(interrupted_identity.group(1))}\.log"
)
for entry in sorted(STATE_DIR.iterdir(), key=lambda item: item.name):
    if interrupted_execution_pattern.fullmatch(entry.name):
        safe_file(entry, "historical interrupted route execution candidate")
        interrupted_execution_candidates.append(entry)
if len(interrupted_execution_candidates) != 1:
    fail("historical interrupted route execution match is not unique")
interrupted_execution_path = interrupted_execution_candidates[0]
if sha(safe_file(interrupted_execution_path, "historical interrupted route execution")) != interrupted["route_down_execution_evidence_sha256"]:
    fail("historical interrupted route execution differs")

control = backup / "CONTROL.sha256"
release = backup / "RELEASE-EVIDENCE.json"
rollback_receipt_path = backup / "ROLLBACK.receipt"
rollback_arm_path = STATE_DIR / str(completion["rollback_armed_receipt"])
running_path = STATE_DIR / str(completion["rollback_running_services_manifest"])
runtime_phase_path = STATE_DIR / str(completion["rollback_runtime_restore_phase_receipt"])
estate_phase_path = STATE_DIR / str(completion["rollback_estate_restore_phase_receipt"])
services_phase_path = STATE_DIR / str(completion["rollback_services_reactivated_phase_receipt"])
route_identity = sha(safe_file(control, "historical CONTROL"))
route_receipt_name = f"ROUTE-CLOSE-{route_identity}.receipt"
route_preimage_name = f"ROUTE-CLOSE-PREIMAGE-{route_identity}.jsonl"
if completion["route_close_receipt"] != route_receipt_name or completion["route_close_preimage"] != route_preimage_name:
    fail("historical route-close namespace differs")
route_receipt_path = STATE_DIR / route_receipt_name
route_preimage_path = STATE_DIR / route_preimage_name
artifact_bindings = {
    "apply_receipt_sha256": backup / "APPLY.receipt",
    "apply_armed_receipt_sha256": backup / "APPLY-ARMED.receipt",
    "control_sha256": control,
    "release_evidence_sha256": release,
    "applied_targets_sha256": backup / "estate/APPLIED-TARGETS.sha256",
    "runtime_backup_receipt_sha256": backup / "runtime/BACKUP.receipt",
    "runtime_backup_manifest_sha256": backup / "runtime/SHA256SUMS",
    "predecessor_current_sha256": backup / "PREDECESSOR-CURRENT.json",
    "predecessor_control_sha256": Path(str(completion["predecessor_backup_dir"])) / "CONTROL.sha256",
    "predecessor_apply_receipt_sha256": Path(str(completion["predecessor_backup_dir"])) / "APPLY.receipt",
    "predecessor_release_evidence_sha256": Path(str(completion["predecessor_backup_dir"])) / "RELEASE-EVIDENCE.json",
    "predecessor_runtime_backup_receipt_sha256": Path(str(completion["predecessor_backup_dir"])) / "runtime/BACKUP.receipt",
    "predecessor_runtime_backup_manifest_sha256": Path(str(completion["predecessor_backup_dir"])) / "runtime/SHA256SUMS",
    "route_close_receipt_sha256": route_receipt_path,
    "route_close_preimage_sha256": route_preimage_path,
    "rollback_running_services_sha256": running_path,
    "rollback_armed_receipt_sha256": rollback_arm_path,
    "rollback_runtime_restore_phase_receipt_sha256": runtime_phase_path,
    "rollback_estate_restore_phase_receipt_sha256": estate_phase_path,
    "rollback_services_reactivated_phase_receipt_sha256": services_phase_path,
    "rollback_receipt_sha256": rollback_receipt_path,
    "rollback_estate_transaction_sha256": backup / "estate/TRANSACTION.json",
}
for field, path in artifact_bindings.items():
    if sha(safe_file(path, f"historical rollback artifact {field}")) != completion[field]:
        fail(f"historical rollback artifact differs: {field}")

control_names = verify_manifest(backup, control, "historical rollback CONTROL")
if control_names != GEN2_CONTROL_NAMES:
    fail("historical rollback CONTROL pathname set is not exact")
runtime_names = verify_manifest(backup / "runtime", backup / "runtime/SHA256SUMS", "historical rollback runtime manifest")
if runtime_names != GEN2_RUNTIME_NAMES:
    fail("historical rollback runtime manifest pathname set is not exact")

projected = {field: completion[field] for field in GEN2_CURRENT_FIELDS}
temporary_current = projected
apply = validate_apply(backup, temporary_current, 2, successor=True)
for field in (SUCCESSOR_FIELDS | {"runtime_backup_receipt_sha256", "runtime_backup_manifest_sha256"}) & set(apply):
    expected_value = projected[field]
    observed: object = apply[field]
    if isinstance(expected_value, bool):
        observed = observed == "true"
    elif isinstance(expected_value, int):
        observed = int(observed)
    if observed != expected_value:
        fail(f"historical rollback completion/APPLY projection differs: {field}")

anchor_current, anchor_backup = validate_gen1(backup / "PREDECESSOR-CURRENT.json")
if anchor_backup != Path(str(completion["predecessor_backup_dir"])):
    fail("historical rollback anchor backup differs")
candidate_arm = receipt(backup / "SUCCESSOR-ARMED.receipt", SUCCESSOR_ARM_FIELDS, "historical successor arm")
for field, expected in {
    "predecessor_current_sha256": completion["predecessor_current_sha256"],
    "predecessor_backup_dir": completion["predecessor_backup_dir"],
    "predecessor_control_sha256": completion["predecessor_control_sha256"],
    "predecessor_apply_receipt_sha256": completion["predecessor_apply_receipt_sha256"],
    "predecessor_release_evidence_sha256": completion["predecessor_release_evidence_sha256"],
    "predecessor_runtime_backup_receipt_sha256": completion["predecessor_runtime_backup_receipt_sha256"],
    "predecessor_runtime_backup_manifest_sha256": completion["predecessor_runtime_backup_manifest_sha256"],
    "predecessor_release_generation": "1", "release_generation": "2",
}.items():
    if candidate_arm[field] != str(expected):
        fail(f"historical successor arm lineage differs: {field}")

rollback_arm = receipt(rollback_arm_path, ROLLBACK_ARM_FIELDS, "historical rollback arm")
running = services_manifest(
    running_path, "historical rollback running manifest", RELEASE_SERVICES
)
runtime_prior = services_manifest(
    backup / "runtime/RUNNING-SERVICES.before", "historical runtime prior manifest",
    WRITER_SERVICES,
)
compose_config = json_object(backup / "runtime/compose-config.json", "historical Compose config")
compose_project = compose_config.get("name")
if not isinstance(compose_project, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", compose_project):
    fail("historical Compose project is unsafe")
expect(rollback_arm, {
    "schema_version": "2", "attempt_id": attempt, "estate_root": str(ESTATE),
    "backup_dir": str(backup), "control_sha256": str(completion["control_sha256"]),
    "transaction_sha256": str(completion["transaction_sha256"]),
    "applied_targets_sha256": str(completion["applied_targets_sha256"]),
    "targets_sha256": sha(safe_file(backup / "TARGETS.sha256", "historical targets")),
    "apply_preimages_sha256": sha(safe_file(backup / "APPLY-PREIMAGES.sha256", "historical apply preimages")),
    "apply_absent_sha256": sha(safe_file(backup / "APPLY-ABSENT.paths", "historical apply absent")),
    "route_close_receipt": route_receipt_path.name,
    "route_close_receipt_sha256": str(completion["route_close_receipt_sha256"]),
    "route_close_preimage": route_preimage_path.name,
    "route_close_preimage_sha256": str(completion["route_close_preimage_sha256"]),
    "compose_project": compose_project, "release_service_count": "7",
    "release_services": ",".join(RELEASE_SERVICES), "running_services_manifest": running_path.name,
    "running_services_sha256": str(completion["rollback_running_services_sha256"]),
    "runtime_prior_services_sha256": sha(safe_file(backup / "runtime/RUNNING-SERVICES.before", "historical runtime prior")),
    "activate_services_requested": "false", "activation_policy": "restore-exact-prior-running",
    "ingress_opened": "false", "successor": "true",
    "successor_armed_receipt_sha256": str(completion["successor_armed_receipt_sha256"]),
    "predecessor_current_sha256": str(completion["predecessor_current_sha256"]),
    "predecessor_backup_dir": str(completion["predecessor_backup_dir"]),
    "predecessor_control_sha256": str(completion["predecessor_control_sha256"]),
    "predecessor_apply_receipt_sha256": str(completion["predecessor_apply_receipt_sha256"]),
    "predecessor_release_evidence_sha256": str(completion["predecessor_release_evidence_sha256"]),
    "predecessor_runtime_backup_receipt_sha256": str(completion["predecessor_runtime_backup_receipt_sha256"]),
    "predecessor_runtime_backup_manifest_sha256": str(completion["predecessor_runtime_backup_manifest_sha256"]),
    "predecessor_release_generation": "1", "release_generation": "2",
}, "historical rollback arm")
for field, expected_name in {
    "open_evidence_file": f"ROLLBACK-OPEN-EVIDENCE-{attempt}.json",
    "open_signature_file": f"ROLLBACK-OPEN-SIGNATURE-{attempt}.sig",
    "authority_public_key_file": f"ROLLBACK-AUTHORITY-PUBLIC-KEY-{attempt}.pub",
    "revocation_evidence_file": f"ROLLBACK-REVOCATION-EVIDENCE-{attempt}.json",
    "revocation_signature_file": f"ROLLBACK-REVOCATION-SIGNATURE-{attempt}.sig",
}.items():
    if rollback_arm[field] != expected_name:
        fail(f"historical rollback frozen filename differs: {field}")
for field in ("edge_rollback_evidence_file", "edge_rollback_evidence_sha256", "edge_rollback_signature_file", "edge_rollback_signature_sha256", "open_edge_evidence_file", "open_edge_evidence_sha256"):
    if rollback_arm[field] != "none":
        fail(f"historical prepared-closed rollback contains edge authority: {field}")
frozen_paths = {
    "open_evidence_sha256": STATE_DIR / rollback_arm["open_evidence_file"],
    "open_signature_sha256": STATE_DIR / rollback_arm["open_signature_file"],
    "authority_public_key_sha256": STATE_DIR / rollback_arm["authority_public_key_file"],
    "revocation_evidence_sha256": STATE_DIR / rollback_arm["revocation_evidence_file"],
    "revocation_signature_sha256": STATE_DIR / rollback_arm["revocation_signature_file"],
}
for field, path in frozen_paths.items():
    if sha(safe_file(path, f"historical frozen rollback {field}")) != rollback_arm[field]:
        fail(f"historical frozen rollback authority differs: {field}")
if rollback_arm["open_evidence_sha256"] != source_open:
    fail("historical rollback open authority differs from stale prepare")

runtime_phase = receipt(runtime_phase_path, RUNTIME_PHASE_FIELDS, "historical runtime phase")
estate_phase = receipt(estate_phase_path, ESTATE_PHASE_FIELDS, "historical estate phase")
services_phase = receipt(services_phase_path, SERVICES_PHASE_FIELDS, "historical services phase")
expect(runtime_phase, {
    "schema_version": "2", "phase": "runtime_restore_done", "attempt_id": attempt,
    "rollback_armed_receipt_sha256": str(completion["rollback_armed_receipt_sha256"]),
    "runtime_restore_receipt_sha256": sha(safe_file(backup / "runtime/RESTORE.receipt", "historical runtime restore")),
    "runtime_backup_receipt_sha256": str(completion["runtime_backup_receipt_sha256"]),
    "runtime_backup_manifest_sha256": str(completion["runtime_backup_manifest_sha256"]),
    "transaction_before_sha256": str(completion["transaction_sha256"]),
    "applied_targets_sha256": str(completion["applied_targets_sha256"]),
    "ingress_opened": "false",
}, "historical runtime phase")
expect(estate_phase, {
    "schema_version": "2", "phase": "estate_restore_done", "attempt_id": attempt,
    "rollback_armed_receipt_sha256": str(completion["rollback_armed_receipt_sha256"]),
    "runtime_restore_phase_receipt_sha256": str(completion["rollback_runtime_restore_phase_receipt_sha256"]),
    "estate_transaction_sha256": str(completion["rollback_estate_transaction_sha256"]),
    "applied_targets_sha256": str(completion["applied_targets_sha256"]),
    "preimages_sha256": sha(safe_file(backup / "estate/PREIMAGES.sha256", "historical estate preimages")),
    "absent_sha256": sha(safe_file(backup / "estate/ABSENT.before", "historical estate absent")),
    "live_estate_disposition": "preimage", "ingress_opened": "false",
}, "historical estate phase")
restart_services = tuple(
    service for service in RELEASE_SERVICES
    if (
        service in runtime_prior
        if service in {"strad", "rikune-analyzer"}
        else service in running
    )
)
reactivated = "none" if not restart_services else ",".join(restart_services)
expect(services_phase, {
    "schema_version": "2", "phase": "services_reactivated_done", "attempt_id": attempt,
    "rollback_armed_receipt_sha256": str(completion["rollback_armed_receipt_sha256"]),
    "estate_restore_phase_receipt_sha256": str(completion["rollback_estate_restore_phase_receipt_sha256"]),
    "reactivated_services": reactivated, "excluded_services_inactive": "passed",
    "ingress_opened": "false",
}, "historical services phase")

rollback_receipt = receipt(rollback_receipt_path, ROLLBACK_RECEIPT_FIELDS, "historical rollback receipt")
expect(rollback_receipt, {
    "schema_version": "2", "rollback_armed_receipt_sha256": str(completion["rollback_armed_receipt_sha256"]),
    "running_services_sha256": str(completion["rollback_running_services_sha256"]),
    "runtime_prior_services_sha256": rollback_arm["runtime_prior_services_sha256"],
    "runtime_restore_phase_receipt_sha256": str(completion["rollback_runtime_restore_phase_receipt_sha256"]),
    "estate_restore_phase_receipt_sha256": str(completion["rollback_estate_restore_phase_receipt_sha256"]),
    "services_reactivated_phase_receipt_sha256": str(completion["rollback_services_reactivated_phase_receipt_sha256"]),
    "route_close_receipt": route_receipt_path.name,
    "route_close_receipt_sha256": str(completion["route_close_receipt_sha256"]),
    "route_close_preimage": route_preimage_path.name,
    "route_close_preimage_sha256": str(completion["route_close_preimage_sha256"]),
    "revocation_evidence_sha256": rollback_arm["revocation_evidence_sha256"],
    "open_evidence_sha256": source_open,
    "runtime_restore_receipt_sha256": runtime_phase["runtime_restore_receipt_sha256"],
    "estate_transaction_sha256": str(completion["rollback_estate_transaction_sha256"]),
    "runtime_restore": "passed", "mixed_estate_restore": "passed",
    "orphan_cleanup": "passed", "service_reactivation": "passed",
    "reactivated_services": reactivated, "excluded_services_inactive": "passed",
    "activation_policy": "restore-exact-prior-running",
    "activate_services_requested": "false", "public_route_state": "dual-stack-404",
    "ingress_opened": "false", "successor": "true",
    "successor_armed_receipt_sha256": str(completion["successor_armed_receipt_sha256"]),
    "predecessor_current_sha256": str(completion["predecessor_current_sha256"]),
    "predecessor_backup_dir": str(completion["predecessor_backup_dir"]),
    "predecessor_control_sha256": str(completion["predecessor_control_sha256"]),
    "predecessor_apply_receipt_sha256": str(completion["predecessor_apply_receipt_sha256"]),
    "predecessor_release_evidence_sha256": str(completion["predecessor_release_evidence_sha256"]),
    "predecessor_runtime_backup_receipt_sha256": str(completion["predecessor_runtime_backup_receipt_sha256"]),
    "predecessor_runtime_backup_manifest_sha256": str(completion["predecessor_runtime_backup_manifest_sha256"]),
    "predecessor_release_generation": "1", "release_generation": "2",
}, "historical rollback receipt")

route, route_keys = parse_receipt_raw(safe_file(route_receipt_path, "historical route-close receipt"), "historical route-close receipt")
expected_route_keys = (
    "schema_version", "route_closed_at", "source_state", "estate_root", "backup_dir",
    "control_sha256", "state_before_sha256", "route_down_sha256",
    "route_down_execution_evidence_sha256", "route_preimage_sha256",
    "route_conflict_cleanup", "open_evidence_sha256", "source_grant_id",
    "was_public_open", "preopen_edge_evidence_sha256", "route_state", "public_host",
    "edge_owner", "public_ipv4_ipv6_closed_status", "db_public_db_bracket",
    "external_edge_mutation",
)
if route_keys != expected_route_keys:
    fail("historical route-close receipt field set or order is not exact")
expect(route, {
    "schema_version": "2", "source_state": "edge_prepared_route_closed",
    "estate_root": str(ESTATE), "backup_dir": str(backup), "control_sha256": route_identity,
    "route_down_sha256": interrupted["route_down_sha256"],
    "route_down_execution_evidence_sha256": str(completion["route_close_preimage_sha256"]),
    "route_preimage_sha256": str(completion["route_close_preimage_sha256"]),
    "route_conflict_cleanup": "same-name-or-analyze-root", "open_evidence_sha256": source_open,
    "source_grant_id": str(prepare_values.get("source_grant_id")), "was_public_open": "false",
    "preopen_edge_evidence_sha256": "none", "route_state": "absent",
    "public_host": prepare_values["public_host"], "edge_owner": "existing-w33d-sluice",
    "public_ipv4_ipv6_closed_status": "404", "db_public_db_bracket": "absent-404-absent",
    "external_edge_mutation": "none",
}, "historical route-close receipt")
if route["route_down_execution_evidence_sha256"] != route["route_preimage_sha256"]:
    fail("historical route-close preimage projection differs")

run_validator([
    str(SCRIPT_DIR / "authority_evidence.py"), "--mode", "open",
    "--evidence", str(frozen_paths["open_evidence_sha256"]),
    "--signature", str(frozen_paths["open_signature_sha256"]),
    "--public-key", str(frozen_paths["authority_public_key_sha256"]),
    "--release-env", str(backup / "release.env"),
    "--release-evidence", str(release), "--dry-run-receipt", str(backup / "DRY-RUN.receipt"),
], "historical signed open validator")
run_validator([
    str(SCRIPT_DIR / "authority_evidence.py"), "--mode", "rollback",
    "--evidence", str(frozen_paths["revocation_evidence_sha256"]),
    "--signature", str(frozen_paths["revocation_signature_sha256"]),
    "--public-key", str(frozen_paths["authority_public_key_sha256"]),
    "--release-env", str(backup / "release.env"),
    "--release-evidence", str(release), "--open-evidence", str(frozen_paths["open_evidence_sha256"]),
    "--route-close-receipt", str(route_receipt_path),
], "historical signed rollback validator")
run_validator([
    str(RELEASE_VALIDATOR), "--evidence", str(release), "--successor-policy",
    str(backup / "successor-authority/successor-policy.json"),
], "historical candidate release validator")
run_validator([
    str(RELEASE_VALIDATOR), "--evidence", str(anchor_backup / "RELEASE-EVIDENCE.json"),
], "historical anchor release validator")

active_gen3_path = ACTIVE_GEN4 / "PREDECESSOR-CURRENT.json"
active_gen3 = exact_json(
    active_gen3_path, ACTIVE_GEN3_CURRENT_FIELDS, "active Gen3 CURRENT"
)
active_gen3_backup = safe_dir(Path(str(active_gen3.get("backup_dir"))), "active Gen3 backup")
expect(active_gen3, {
    "schema_version": 2, "state": "applied_ingress_closed", "estate_root": str(ESTATE),
    "backup_dir": str(active_gen3_backup), "services_activated": True,
    "runtime_verified": True, "ingress_opened": False, "successor": True,
    "predecessor_current_file": "PREDECESSOR-CURRENT.json",
    "recovery_mode": "resume", "recovery_prior_state": "apply_activation_failed",
    "predecessor_release_generation": 2, "release_generation": 3,
}, "active Gen3 CURRENT")
if "apply_receipt_sha256" in active_gen3 or any(key.startswith("predecessor_completion_") for key in active_gen3):
    fail("active Gen3 CURRENT is a hybrid lineage")
for field in (
    "control_sha256", "release_evidence_sha256", "predecessor_current_sha256",
    "predecessor_control_sha256", "predecessor_apply_receipt_sha256",
    "predecessor_release_evidence_sha256", "predecessor_runtime_backup_receipt_sha256",
    "predecessor_runtime_backup_manifest_sha256",
):
    require_hash(active_gen3.get(field), f"active Gen3 CURRENT {field}")
tree_snapshot(active_gen3_backup, "active Gen3 backup")
gen3_control_names = verify_manifest(active_gen3_backup, active_gen3_backup / "CONTROL.sha256", "active Gen3 CONTROL")
require_manifest_paths(gen3_control_names, {
    "RELEASE-EVIDENCE.json", "PREDECESSOR-CURRENT.json",
    "runtime/BACKUP.receipt", "runtime/SHA256SUMS",
}, "active Gen3 CONTROL")
gen3_runtime_names = verify_manifest(
    active_gen3_backup / "runtime",
    active_gen3_backup / "runtime/SHA256SUMS",
    "active Gen3 runtime manifest",
)
if not gen3_runtime_names:
    fail("active Gen3 runtime manifest is empty")
if sha(safe_file(active_gen3_backup / "CONTROL.sha256", "active Gen3 CONTROL")) != active_gen3["control_sha256"]:
    fail("active Gen3 CONTROL differs")
if sha(safe_file(active_gen3_backup / "RELEASE-EVIDENCE.json", "active Gen3 release")) != active_gen3["release_evidence_sha256"]:
    fail("active Gen3 release evidence differs")
if (active_gen3_backup / "APPLY.receipt").exists() or (active_gen3_backup / "APPLY.receipt").is_symlink():
    fail("active Gen3 recovered backup contains APPLY.receipt")
for field, relative in (
    ("runtime_backup_receipt_sha256", "runtime/BACKUP.receipt"),
    ("runtime_backup_manifest_sha256", "runtime/SHA256SUMS"),
):
    if field in active_gen3 and sha(safe_file(active_gen3_backup / relative, f"active Gen3 {relative}")) != active_gen3[field]:
        fail(f"active Gen3 runtime authority differs: {field}")
active_gen2_path = active_gen3_backup / "PREDECESSOR-CURRENT.json"
if sha(safe_file(active_gen2_path, "active Gen2 CURRENT")) != active_gen3["predecessor_current_sha256"]:
    fail("active Gen3 predecessor CURRENT differs")
active_gen2, active_gen2_backup, _ = validate_gen2_current(active_gen2_path, "active Gen2 CURRENT")
if active_gen2_backup == backup or active_gen2["release_evidence_sha256"] == source_release:
    fail("historical rollback source is not distinct from the active Gen2 lineage")
for field, path in {
    "predecessor_control_sha256": active_gen2_backup / "CONTROL.sha256",
    "predecessor_apply_receipt_sha256": active_gen2_backup / "APPLY.receipt",
    "predecessor_release_evidence_sha256": active_gen2_backup / "RELEASE-EVIDENCE.json",
    "predecessor_runtime_backup_receipt_sha256": active_gen2_backup / "runtime/BACKUP.receipt",
    "predecessor_runtime_backup_manifest_sha256": active_gen2_backup / "runtime/SHA256SUMS",
}.items():
    if sha(safe_file(path, f"active Gen3 predecessor {field}")) != active_gen3[field]:
        fail(f"active Gen3 predecessor differs: {field}")
active_gen1_path = active_gen2_backup / "PREDECESSOR-CURRENT.json"
active_anchor, active_anchor_backup = validate_gen1(active_gen1_path)
if sha(safe_file(active_gen1_path, "active Gen1 CURRENT")) != active_gen2["predecessor_current_sha256"]:
    fail("active Gen2 predecessor CURRENT differs")
if (
    safe_file(active_gen1_path, "active Gen1 CURRENT") != safe_file(backup / "PREDECESSOR-CURRENT.json", "historical Gen1 CURRENT")
    or active_anchor_backup != anchor_backup
    or active_anchor["control_sha256"] != anchor_current["control_sha256"]
    or active_anchor["apply_receipt_sha256"] != anchor_current["apply_receipt_sha256"]
    or active_anchor["release_evidence_sha256"] != anchor_current["release_evidence_sha256"]
):
    fail("historical rollback does not anchor to the active Gen1 lineage")

prepared = utc(prepare_values.get("prepared_at"), "stale prepare time")
interrupted_at = utc(interrupted["interrupted_at"], "interrupted time")
route_closed = utc(route["route_closed_at"], "route close time")
revocation = json_object(frozen_paths["revocation_evidence_sha256"], "historical revocation evidence")
revoked_at = utc(revocation.get("grant_revoked_at"), "grant revoked time")
rollback_armed_at = utc(rollback_arm["armed_at"], "rollback armed time")
runtime_at = utc(runtime_phase["completed_at"], "runtime phase time")
estate_at = utc(estate_phase["completed_at"], "estate phase time")
services_at = utc(services_phase["completed_at"], "services phase time")
rolled_back_at = utc(rollback_receipt["rolled_back_at"], "rolled back time")
if not (prepared <= interrupted_at <= route_closed < revoked_at <= rollback_armed_at <= runtime_at <= estate_at <= services_at <= rolled_back_at):
    fail("historical rollback lifecycle timestamps are out of order")

for path, (identity, digest_value) in tracked.items():
    current_raw = safe_file(Path(path), "tracked historical authority", private=False, track=False)
    _, current_identity = metadata(Path(path))
    if current_identity != identity or sha(current_raw) != digest_value:
        fail("historical rollback authority changed during validation")
for root, before in list(trees.items()):
    previous = trees[root]
    del trees[root]
    tree_snapshot(Path(root), "tracked historical tree")
    after = trees[root]
    trees[root] = previous
    if after != before:
        fail("historical rollback tree namespace changed during validation")
snapshot = hashlib.sha256()
for row in namespace_rows:
    snapshot.update((row + "\n").encode())
for path in sorted(tracked):
    identity, digest_value = tracked[path]
    snapshot.update(f"{path}\0{identity}\0{digest_value}\n".encode())
for root in sorted(trees):
    snapshot.update(f"tree={root}\n".encode())
    for row in trees[root]:
        snapshot.update((row + "\n").encode())
result = {
    "schema_version": 1,
    "authority_kind": "historical-rollback-v1",
    "source_release_generation": 2,
    "rollback_anchor_release_generation": 1,
    "rollback_attempt_id": attempt,
    "rollback_completion": completion_path.name,
    "rollback_completion_sha256": sha(safe_file(completion_path, "historical completion", track=False)),
    "rollback_interrupted_receipt": interrupted_path.name,
    "rollback_interrupted_receipt_sha256": str(completion["last_open_interrupted_receipt_sha256"]),
    "rollback_armed_receipt": rollback_arm_path.name,
    "rollback_armed_receipt_sha256": str(completion["rollback_armed_receipt_sha256"]),
    "rollback_receipt": "ROLLBACK.receipt",
    "rollback_receipt_sha256": str(completion["rollback_receipt_sha256"]),
    "rollback_route_close_receipt": route_receipt_path.name,
    "rollback_route_close_receipt_sha256": str(completion["route_close_receipt_sha256"]),
    "rollback_route_close_preimage": route_preimage_path.name,
    "rollback_route_close_preimage_sha256": str(completion["route_close_preimage_sha256"]),
    "rollback_open_evidence": rollback_arm["open_evidence_file"],
    "rollback_open_evidence_sha256": rollback_arm["open_evidence_sha256"],
    "rollback_revocation_evidence": rollback_arm["revocation_evidence_file"],
    "rollback_revocation_evidence_sha256": rollback_arm["revocation_evidence_sha256"],
    "historical_control_sha256": str(completion["control_sha256"]),
    "historical_release_evidence_sha256": source_release,
    "historical_predecessor_current_sha256": str(completion["predecessor_current_sha256"]),
    "active_anchor_current_sha256": sha(safe_file(active_gen1_path, "active anchor", track=False)),
    "authority_snapshot_sha256": snapshot.hexdigest(),
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
}

validate_stale_prepare_receipt() {
  local path=$1 keys receipt_generation prepared_at
  require_private_root_file "$path" "stale open prepare receipt"
  keys=$(receipt_key_set "$path") || holdfast_die "stale open prepare receipt is malformed"
  if [[ "$keys" == $'db_public_db_bracket\nedge_owner\nexternal_edge_mutation\nopen_evidence_sha256\nprepared_at\npublic_host\npublic_ipv4_ipv6_closed_status\nrelease_evidence_sha256\nroute_state\nsource_grant_id' ]]; then
    source_prepare_schema="legacy-analyze-v2"
    source_claimed_release_generation="none"
    [[ "$(holdfast_receipt_value "$path" public_host)" == "analyze.w33d.xyz" ]] || \
      holdfast_die "legacy stale prepare receipt does not bind analyze.w33d.xyz"
  elif [[ "$keys" == $'db_public_db_bracket\nedge_owner\nexternal_edge_mutation\nlegacy_public_host\nlegacy_public_ipv4_ipv6_closed_status\nlegacy_route_state\nopen_evidence_sha256\nprepared_at\npublic_host\npublic_ipv4_ipv6_closed_status\nrelease_evidence_sha256\nrelease_generation\nroute_state\nschema_version\nsource_grant_id' ]]; then
    source_prepare_schema="rikune-v3"
    [[ "$(holdfast_receipt_value "$path" schema_version)" == "3" && \
      "$(holdfast_receipt_value "$path" public_host)" == "rikune.w33d.xyz" && \
      "$(holdfast_receipt_value "$path" legacy_public_host)" == "analyze.w33d.xyz" && \
      "$(holdfast_receipt_value "$path" legacy_route_state)" == "absent" && \
      "$(holdfast_receipt_value "$path" legacy_public_ipv4_ipv6_closed_status)" == "404" ]] || \
      holdfast_die "stale rikune prepare receipt host/tombstone authority differs"
    receipt_generation=$(holdfast_receipt_value "$path" release_generation)
    [[ "$receipt_generation" =~ ^[1-9][0-9]*$ ]] || \
      holdfast_die "stale rikune prepare receipt generation is invalid"
    source_claimed_release_generation=$receipt_generation
  else
    holdfast_die "stale open prepare receipt is hybrid or has an unknown field set"
  fi

  source_release_evidence_sha=$(holdfast_receipt_value "$path" release_evidence_sha256)
  source_open_evidence_sha=$(holdfast_receipt_value "$path" open_evidence_sha256)
  source_grant_id=$(holdfast_receipt_value "$path" source_grant_id)
  source_public_host=$(holdfast_receipt_value "$path" public_host)
  prepared_at=$(holdfast_receipt_value "$path" prepared_at)
  [[ "$source_release_evidence_sha" =~ ^[0-9a-f]{64}$ && \
    "$source_open_evidence_sha" =~ ^[0-9a-f]{64}$ && -n "$source_grant_id" && \
    "$prepared_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "stale open prepare receipt evidence binding is invalid"
  [[ "$(holdfast_receipt_value "$path" route_state)" == "absent" && \
    "$(holdfast_receipt_value "$path" edge_owner)" == "existing-w33d-sluice" && \
    "$(holdfast_receipt_value "$path" public_ipv4_ipv6_closed_status)" == "404" && \
    "$(holdfast_receipt_value "$path" db_public_db_bracket)" == "absent-404-absent" && \
    "$(holdfast_receipt_value "$path" external_edge_mutation)" == "none" ]] || \
    holdfast_die "stale open prepare receipt does not prove a closed Sluice route"
}

bind_prepare_abandon_source_authority() {
  local source_path=$1 release_validator snapshot
  if [[ "$source_release_evidence_sha" == "$predecessor_release_evidence_sha" ]]; then
    [[ "$source_claimed_release_generation" == "none" || \
      "$source_claimed_release_generation" == "$predecessor_release_generation" ]] || \
      holdfast_die "stale rikune prepare receipt generation is not the immediate predecessor"
    [[ "$source_release_evidence_sha" != "$successor_release_evidence_sha" ]] || \
      holdfast_die "stale OPEN-PREPARE binds the active successor release"
    successor_abandon_source_kind="immediate"
    source_release_generation=$predecessor_release_generation
    source_archive_generation=$predecessor_release_generation
    return 0
  fi
  [[ "${successor_abandon_authority_kind:-apply}" == "recovery-resume" ]] || \
    holdfast_die "stale OPEN-PREPARE does not bind the immediate predecessor release"
  [[ "$source_prepare_schema" == "legacy-analyze-v2" && \
    "$source_public_host" == "analyze.w33d.xyz" && \
    "$source_claimed_release_generation" == "none" ]] || \
    holdfast_die "historical rollback abandonment only accepts legacy analyze OPEN-PREPARE authority"

  release_validator="$script_dir/validate_release_evidence.py"
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    -n "${HOLDFAST_HISTORICAL_RELEASE_VALIDATOR_BIN:-}" ]]; then
    release_validator=$HOLDFAST_HISTORICAL_RELEASE_VALIDATOR_BIN
  fi
  holdfast_require_absolute "$release_validator"
  snapshot=$(validate_historical_rollback_abandon_authority \
    "$source_path" "$release_validator") || \
    holdfast_die "historical rollback abandonment authority is not exact"
  jq -e '
    keys == [
      "active_anchor_current_sha256","authority_kind","authority_snapshot_sha256",
      "historical_control_sha256","historical_predecessor_current_sha256",
      "historical_release_evidence_sha256","rollback_anchor_release_generation",
      "rollback_armed_receipt","rollback_armed_receipt_sha256",
      "rollback_attempt_id","rollback_completion","rollback_completion_sha256",
      "rollback_interrupted_receipt","rollback_interrupted_receipt_sha256",
      "rollback_open_evidence","rollback_open_evidence_sha256",
      "rollback_receipt","rollback_receipt_sha256",
      "rollback_revocation_evidence","rollback_revocation_evidence_sha256",
      "rollback_route_close_preimage","rollback_route_close_preimage_sha256",
      "rollback_route_close_receipt","rollback_route_close_receipt_sha256",
      "schema_version","source_release_generation"
    ] and .schema_version == 1 and .authority_kind == "historical-rollback-v1" and
    .source_release_generation == 2 and .rollback_anchor_release_generation == 1
  ' <<<"$snapshot" >/dev/null || \
    holdfast_die "historical rollback abandonment result namespace is not exact"
  [[ "$(jq -er '.historical_release_evidence_sha256' <<<"$snapshot")" == \
      "$source_release_evidence_sha" ]] || \
    holdfast_die "historical rollback release evidence differs from stale prepare"
  if [[ "$source_claimed_release_generation" != "none" ]]; then
    [[ "$source_claimed_release_generation" == "2" ]] || \
      holdfast_die "historical rollback stale prepare generation differs"
  fi

  successor_abandon_source_kind="historical-rollback"
  source_release_generation=2
  source_archive_generation=2
  historical_authority_snapshot=$snapshot
  historical_release_validator=$release_validator
  historical_rollback_attempt_id=$(jq -er '.rollback_attempt_id' <<<"$snapshot")
  historical_rollback_completion_name=$(jq -er '.rollback_completion' <<<"$snapshot")
  historical_rollback_completion_sha=$(jq -er '.rollback_completion_sha256' <<<"$snapshot")
  historical_interrupted_name=$(jq -er '.rollback_interrupted_receipt' <<<"$snapshot")
  historical_interrupted_sha=$(jq -er '.rollback_interrupted_receipt_sha256' <<<"$snapshot")
  historical_rollback_arm_name=$(jq -er '.rollback_armed_receipt' <<<"$snapshot")
  historical_rollback_arm_sha=$(jq -er '.rollback_armed_receipt_sha256' <<<"$snapshot")
  historical_rollback_receipt_name=$(jq -er '.rollback_receipt' <<<"$snapshot")
  historical_rollback_receipt_sha=$(jq -er '.rollback_receipt_sha256' <<<"$snapshot")
  historical_route_receipt_name=$(jq -er '.rollback_route_close_receipt' <<<"$snapshot")
  historical_route_receipt_sha=$(jq -er '.rollback_route_close_receipt_sha256' <<<"$snapshot")
  historical_route_preimage_name=$(jq -er '.rollback_route_close_preimage' <<<"$snapshot")
  historical_route_preimage_sha=$(jq -er '.rollback_route_close_preimage_sha256' <<<"$snapshot")
  historical_open_evidence_name=$(jq -er '.rollback_open_evidence' <<<"$snapshot")
  historical_open_evidence_sha=$(jq -er '.rollback_open_evidence_sha256' <<<"$snapshot")
  historical_revocation_evidence_name=$(jq -er '.rollback_revocation_evidence' <<<"$snapshot")
  historical_revocation_evidence_sha=$(jq -er '.rollback_revocation_evidence_sha256' <<<"$snapshot")
  historical_control_sha=$(jq -er '.historical_control_sha256' <<<"$snapshot")
  historical_predecessor_current_sha=$(jq -er '.historical_predecessor_current_sha256' <<<"$snapshot")
  historical_active_anchor_current_sha=$(jq -er '.active_anchor_current_sha256' <<<"$snapshot")
  historical_authority_snapshot_sha=$(jq -er '.authority_snapshot_sha256' <<<"$snapshot")
}

render_prepare_supersede_receipt() {
  local abandoned_at=$1 output=$2
  if [[ "${successor_abandon_source_kind:-immediate}" == "historical-rollback" ]]; then
    [[ ! -e "$output" && ! -L "$output" ]] || \
      holdfast_die "prepare supersede render path already exists: $output"
    {
      printf 'schema_version=1\n'
      printf 'ceremony=holdfast-rikune-open-prepare-abandon-historical-rollback-v1\n'
      printf 'authority_binding=frozen-historical-rollback-and-successor-recovery-hash-chains\n'
      printf 'abandoned_at=%s\n' "$abandoned_at"
      printf 'reason_file_sha256=%s\n' "$reason_file_sha"
      printf 'source_prepare_receipt_sha256=%s\n' "$source_prepare_sha"
      printf 'source_prepare_schema=%s\n' "$source_prepare_schema"
      printf 'source_release_generation=%s\n' "$source_release_generation"
      printf 'source_release_evidence_sha256=%s\n' "$source_release_evidence_sha"
      printf 'source_open_evidence_sha256=%s\n' "$source_open_evidence_sha"
      printf 'source_grant_id=%s\n' "$source_grant_id"
      printf 'source_public_host=%s\n' "$source_public_host"
      printf 'archive_name=%s\n' "$archive_name"
      printf 'archive_sha256=%s\n' "$source_prepare_sha"
      printf 'rollback_anchor_release_generation=1\n'
      printf 'historical_control_sha256=%s\n' "$historical_control_sha"
      printf 'historical_predecessor_current_sha256=%s\n' "$historical_predecessor_current_sha"
      printf 'active_anchor_current_sha256=%s\n' "$historical_active_anchor_current_sha"
      printf 'rollback_attempt_id=%s\n' "$historical_rollback_attempt_id"
      printf 'rollback_completion=%s\n' "$historical_rollback_completion_name"
      printf 'rollback_completion_sha256=%s\n' "$historical_rollback_completion_sha"
      printf 'rollback_interrupted_receipt=%s\n' "$historical_interrupted_name"
      printf 'rollback_interrupted_receipt_sha256=%s\n' "$historical_interrupted_sha"
      printf 'rollback_armed_receipt=%s\n' "$historical_rollback_arm_name"
      printf 'rollback_armed_receipt_sha256=%s\n' "$historical_rollback_arm_sha"
      printf 'rollback_receipt=%s\n' "$historical_rollback_receipt_name"
      printf 'rollback_receipt_sha256=%s\n' "$historical_rollback_receipt_sha"
      printf 'rollback_route_close_receipt=%s\n' "$historical_route_receipt_name"
      printf 'rollback_route_close_receipt_sha256=%s\n' "$historical_route_receipt_sha"
      printf 'rollback_route_close_preimage=%s\n' "$historical_route_preimage_name"
      printf 'rollback_route_close_preimage_sha256=%s\n' "$historical_route_preimage_sha"
      printf 'rollback_open_evidence=%s\n' "$historical_open_evidence_name"
      printf 'rollback_open_evidence_sha256=%s\n' "$historical_open_evidence_sha"
      printf 'rollback_revocation_evidence=%s\n' "$historical_revocation_evidence_name"
      printf 'rollback_revocation_evidence_sha256=%s\n' "$historical_revocation_evidence_sha"
      printf 'historical_authority_snapshot_sha256=%s\n' "$historical_authority_snapshot_sha"
      printf 'active_predecessor_release_generation=%s\n' "$predecessor_release_generation"
      printf 'active_predecessor_current_sha256=%s\n' "$predecessor_current_sha"
      printf 'active_predecessor_control_sha256=%s\n' "$predecessor_control_sha"
      printf 'active_predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_receipt_sha"
      printf 'active_predecessor_release_evidence_sha256=%s\n' "$predecessor_release_evidence_sha"
      printf 'successor_release_generation=%s\n' "$successor_release_generation"
      printf 'successor_current_sha256=%s\n' "$successor_current_sha"
      printf 'successor_release_evidence_sha256=%s\n' "$successor_release_evidence_sha"
      printf 'successor_control_sha256=%s\n' "$successor_control_sha"
      printf 'successor_policy_sha256=%s\n' "$successor_policy_sha"
      printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_receipt_sha"
      printf 'successor_completion_authority=recovery-resume-completion-v1\n'
      printf 'successor_recovery_attempt_id=%s\n' "$successor_recovery_attempt_id"
      printf 'successor_recovery_completion_receipt=%s\n' "$successor_recovery_receipt_name"
      printf 'successor_recovery_completion_receipt_sha256=%s\n' "$successor_recovery_receipt_sha"
      printf 'successor_recovery_completion_archive=%s\n' "$successor_recovery_archive_name"
      printf 'successor_recovery_completion_archive_sha256=%s\n' "$successor_recovery_archive_sha"
      printf 'successor_recovery_armed_receipt=%s\n' "$successor_recovery_armed_name"
      printf 'successor_recovery_armed_receipt_sha256=%s\n' "$successor_recovery_armed_sha"
      printf 'successor_original_failure_receipt=%s\n' "$successor_recovery_failure_name"
      printf 'successor_original_failure_receipt_sha256=%s\n' "$successor_recovery_failure_sha"
      printf 'successor_apply_receipt_created=false\n'
    } >"$output"
    chmod 0600 -- "$output"
    return 0
  fi
  if [[ "${successor_abandon_authority_kind:-apply}" == "recovery-resume" ]]; then
    [[ ! -e "$output" && ! -L "$output" ]] || \
      holdfast_die "prepare supersede render path already exists: $output"
    {
      printf 'schema_version=1\n'
      printf 'ceremony=holdfast-rikune-open-prepare-abandon-recovery-v1\n'
      printf 'authority_binding=frozen-successor-recovery-completion-hash-chain\n'
      printf 'abandoned_at=%s\n' "$abandoned_at"
      printf 'reason_file_sha256=%s\n' "$reason_file_sha"
      printf 'source_prepare_receipt_sha256=%s\n' "$source_prepare_sha"
      printf 'source_prepare_schema=%s\n' "$source_prepare_schema"
      printf 'source_release_evidence_sha256=%s\n' "$source_release_evidence_sha"
      printf 'source_open_evidence_sha256=%s\n' "$source_open_evidence_sha"
      printf 'source_grant_id=%s\n' "$source_grant_id"
      printf 'source_public_host=%s\n' "$source_public_host"
      printf 'archive_name=%s\n' "$archive_name"
      printf 'archive_sha256=%s\n' "$source_prepare_sha"
      printf 'predecessor_release_generation=%s\n' "$predecessor_release_generation"
      printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
      printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_receipt_sha"
      printf 'successor_release_generation=%s\n' "$successor_release_generation"
      printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
      printf 'successor_current_sha256=%s\n' "$successor_current_sha"
      printf 'successor_release_evidence_sha256=%s\n' "$successor_release_evidence_sha"
      printf 'successor_control_sha256=%s\n' "$successor_control_sha"
      printf 'successor_policy_sha256=%s\n' "$successor_policy_sha"
      printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_receipt_sha"
      printf 'successor_completion_authority=recovery-resume-completion-v1\n'
      printf 'successor_recovery_attempt_id=%s\n' "$successor_recovery_attempt_id"
      printf 'successor_recovery_completion_receipt=%s\n' "$successor_recovery_receipt_name"
      printf 'successor_recovery_completion_receipt_sha256=%s\n' "$successor_recovery_receipt_sha"
      printf 'successor_recovery_completion_archive=%s\n' "$successor_recovery_archive_name"
      printf 'successor_recovery_completion_archive_sha256=%s\n' "$successor_recovery_archive_sha"
      printf 'successor_recovery_armed_receipt=%s\n' "$successor_recovery_armed_name"
      printf 'successor_recovery_armed_receipt_sha256=%s\n' "$successor_recovery_armed_sha"
      printf 'successor_original_failure_receipt=%s\n' "$successor_recovery_failure_name"
      printf 'successor_original_failure_receipt_sha256=%s\n' "$successor_recovery_failure_sha"
      printf 'successor_apply_receipt_created=false\n'
    } >"$output"
    chmod 0600 -- "$output"
    return 0
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || \
    holdfast_die "prepare supersede render path already exists: $output"
  # This verifier-only script never receives a signing key, so the receipt binds both
  # frozen release CONTROL chains and the exact active successor CURRENT instead.
  {
    printf 'schema_version=1\n'
    printf 'ceremony=holdfast-rikune-open-prepare-abandon-v1\n'
    printf 'authority_binding=frozen-successor-current-hash-chain\n'
    printf 'abandoned_at=%s\n' "$abandoned_at"
    printf 'reason_file_sha256=%s\n' "$reason_file_sha"
    printf 'source_prepare_receipt_sha256=%s\n' "$source_prepare_sha"
    printf 'source_prepare_schema=%s\n' "$source_prepare_schema"
    printf 'source_release_evidence_sha256=%s\n' "$source_release_evidence_sha"
    printf 'source_open_evidence_sha256=%s\n' "$source_open_evidence_sha"
    printf 'source_grant_id=%s\n' "$source_grant_id"
    printf 'source_public_host=%s\n' "$source_public_host"
    printf 'archive_name=%s\n' "$archive_name"
    printf 'archive_sha256=%s\n' "$source_prepare_sha"
    printf 'predecessor_release_generation=%s\n' "$predecessor_release_generation"
    printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
    printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_receipt_sha"
    printf 'successor_release_generation=%s\n' "$successor_release_generation"
    printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
    printf 'successor_current_sha256=%s\n' "$successor_current_sha"
    printf 'successor_release_evidence_sha256=%s\n' "$successor_release_evidence_sha"
    printf 'successor_control_sha256=%s\n' "$successor_control_sha"
    printf 'successor_policy_sha256=%s\n' "$successor_policy_sha"
    printf 'successor_apply_receipt_sha256=%s\n' "$successor_apply_receipt_sha"
    printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_receipt_sha"
  } >"$output"
  chmod 0600 -- "$output"
}

validate_prepare_supersede_receipt() {
  local path=$1 expected=$2 abandoned_at keys
  require_private_root_file "$path" "open prepare supersede receipt"
  keys=$(receipt_key_set "$path") || holdfast_die "open prepare supersede receipt is malformed"
  if [[ "${successor_abandon_source_kind:-immediate}" == "historical-rollback" ]]; then
    [[ "$keys" == $'abandoned_at\nactive_anchor_current_sha256\nactive_predecessor_apply_receipt_sha256\nactive_predecessor_control_sha256\nactive_predecessor_current_sha256\nactive_predecessor_release_evidence_sha256\nactive_predecessor_release_generation\narchive_name\narchive_sha256\nauthority_binding\nceremony\nhistorical_authority_snapshot_sha256\nhistorical_control_sha256\nhistorical_predecessor_current_sha256\nreason_file_sha256\nrollback_anchor_release_generation\nrollback_armed_receipt\nrollback_armed_receipt_sha256\nrollback_attempt_id\nrollback_completion\nrollback_completion_sha256\nrollback_interrupted_receipt\nrollback_interrupted_receipt_sha256\nrollback_open_evidence\nrollback_open_evidence_sha256\nrollback_receipt\nrollback_receipt_sha256\nrollback_revocation_evidence\nrollback_revocation_evidence_sha256\nrollback_route_close_preimage\nrollback_route_close_preimage_sha256\nrollback_route_close_receipt\nrollback_route_close_receipt_sha256\nschema_version\nsource_grant_id\nsource_open_evidence_sha256\nsource_prepare_receipt_sha256\nsource_prepare_schema\nsource_public_host\nsource_release_evidence_sha256\nsource_release_generation\nsuccessor_apply_receipt_created\nsuccessor_armed_receipt_sha256\nsuccessor_completion_authority\nsuccessor_control_sha256\nsuccessor_current_sha256\nsuccessor_original_failure_receipt\nsuccessor_original_failure_receipt_sha256\nsuccessor_policy_sha256\nsuccessor_recovery_armed_receipt\nsuccessor_recovery_armed_receipt_sha256\nsuccessor_recovery_attempt_id\nsuccessor_recovery_completion_archive\nsuccessor_recovery_completion_archive_sha256\nsuccessor_recovery_completion_receipt\nsuccessor_recovery_completion_receipt_sha256\nsuccessor_release_evidence_sha256\nsuccessor_release_generation' ]] || \
      holdfast_die "historical rollback prepare supersede receipt field set is not exact"
  elif [[ "${successor_abandon_authority_kind:-apply}" == "recovery-resume" ]]; then
    [[ "$keys" == $'abandoned_at\narchive_name\narchive_sha256\nauthority_binding\nceremony\npredecessor_apply_receipt_sha256\npredecessor_control_sha256\npredecessor_current_sha256\npredecessor_release_generation\nreason_file_sha256\nschema_version\nsource_grant_id\nsource_open_evidence_sha256\nsource_prepare_receipt_sha256\nsource_prepare_schema\nsource_public_host\nsource_release_evidence_sha256\nsuccessor_apply_receipt_created\nsuccessor_armed_receipt_sha256\nsuccessor_completion_authority\nsuccessor_control_sha256\nsuccessor_current_sha256\nsuccessor_original_failure_receipt\nsuccessor_original_failure_receipt_sha256\nsuccessor_policy_sha256\nsuccessor_recovery_armed_receipt\nsuccessor_recovery_armed_receipt_sha256\nsuccessor_recovery_attempt_id\nsuccessor_recovery_completion_archive\nsuccessor_recovery_completion_archive_sha256\nsuccessor_recovery_completion_receipt\nsuccessor_recovery_completion_receipt_sha256\nsuccessor_release_evidence_sha256\nsuccessor_release_generation' ]] || \
      holdfast_die "recovery prepare supersede receipt field set is not exact"
  else
  [[ "$keys" == $'abandoned_at\narchive_name\narchive_sha256\nauthority_binding\nceremony\npredecessor_apply_receipt_sha256\npredecessor_control_sha256\npredecessor_current_sha256\npredecessor_release_generation\nreason_file_sha256\nschema_version\nsource_grant_id\nsource_open_evidence_sha256\nsource_prepare_receipt_sha256\nsource_prepare_schema\nsource_public_host\nsource_release_evidence_sha256\nsuccessor_apply_receipt_sha256\nsuccessor_armed_receipt_sha256\nsuccessor_control_sha256\nsuccessor_current_sha256\nsuccessor_policy_sha256\nsuccessor_release_evidence_sha256\nsuccessor_release_generation' ]] || \
    holdfast_die "open prepare supersede receipt field set is not exact"
  fi
  abandoned_at=$(holdfast_receipt_value "$path" abandoned_at)
  [[ "$abandoned_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "open prepare supersede receipt timestamp is invalid"
  render_prepare_supersede_receipt "$abandoned_at" "$expected"
  cmp -s -- "$path" "$expected" || \
    holdfast_die "open prepare supersede receipt differs from the exact successor authority"
  rm -f -- "$expected"
}

load_successor_recovery_abandon_authority() {
  local backup predecessor_backup current_release predecessor_release expected key value
  local policy arm_keys armed_at namespace_before namespace_after
  successor_abandon_authority_kind="recovery-resume"
  require_private_root_file "$state_file" "active recovered apply state"
  successor_current_sha=$(holdfast_sha256 "$state_file")
  namespace_before=$(snapshot_recovery_abandon_namespace) || \
    holdfast_die "recovery abandonment namespace is unsafe"

  predecessor_release_generation=$(jq -er '.predecessor_release_generation' "$state_file")
  successor_release_generation=$(jq -er '.release_generation' "$state_file")
  successor_release_evidence_sha=$(jq -er '.release_evidence_sha256' "$state_file")
  successor_control_sha=$(jq -er '.control_sha256' "$state_file")
  successor_dry_receipt_sha=$(jq -er '.dry_run_receipt_sha256' "$state_file")
  successor_armed_receipt_sha=$(jq -er '.successor_armed_receipt_sha256' "$state_file")
  predecessor_current_sha=$(jq -er '.predecessor_current_sha256' "$state_file")
  predecessor_control_sha=$(jq -er '.predecessor_control_sha256' "$state_file")
  predecessor_apply_receipt_sha=$(jq -er '.predecessor_apply_receipt_sha256' "$state_file")
  current_predecessor_release_sha=$(jq -er '.predecessor_release_evidence_sha256' "$state_file")
  predecessor_runtime_backup_receipt_sha=$(jq -er \
    '.predecessor_runtime_backup_receipt_sha256' "$state_file")
  predecessor_runtime_backup_manifest_sha=$(jq -er \
    '.predecessor_runtime_backup_manifest_sha256' "$state_file")
  successor_apply_armed_sha=$(jq -er '.apply_armed_receipt_sha256' "$state_file")
  successor_transaction_sha=$(jq -er '.transaction_sha256' "$state_file")
  successor_applied_targets_sha=$(jq -er '.applied_targets_sha256' "$state_file")
  successor_runtime_caller_sha=$(jq -er \
    '.runtime_backup_caller_armed_sha256' "$state_file")
  successor_runtime_stop_sha=$(jq -er \
    '.runtime_backup_stop_authority_sha256' "$state_file")
  successor_recovery_attempt_id=$(jq -er '.recovery_attempt_id' "$state_file")
  successor_recovery_receipt_name=$(jq -er '.recovery_receipt' "$state_file")
  successor_recovery_armed_name=$(jq -er '.recovery_armed_receipt' "$state_file")
  successor_recovery_failure_name=$(jq -er '.apply_failure_receipt' "$state_file")
  successor_recovery_archive_name="APPLY-RECOVERY-COMPLETE-${successor_recovery_attempt_id}.json"
  successor_estate_root=$(jq -er '.estate_root' "$state_file")
  backup=$(jq -er '.backup_dir' "$state_file")
  predecessor_backup=$(jq -er '.predecessor_backup_dir' "$state_file")
  holdfast_require_absolute "$backup"
  holdfast_require_absolute "$predecessor_backup"
  holdfast_require_absolute "$successor_estate_root"
  require_private_root_directory "$backup" "successor release authority directory"
  require_private_root_directory "$predecessor_backup" "predecessor release authority directory"
  [[ "$successor_recovery_attempt_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
    "$successor_recovery_receipt_name" == \
      "APPLY-RECOVERY-COMPLETE-${successor_recovery_attempt_id}.receipt" && \
    "$successor_recovery_armed_name" == \
      "APPLY-RECOVERY-ARMED-${successor_recovery_attempt_id}.receipt" && \
    "$successor_recovery_failure_name" =~ \
      ^APPLY-ACTIVATION-FAILED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ ]] || \
    holdfast_die "recovery abandonment attempt namespace is unsafe"

  successor_recovery_receipt="$state_dir/$successor_recovery_receipt_name"
  successor_recovery_archive="$state_dir/$successor_recovery_archive_name"
  successor_recovery_armed="$state_dir/$successor_recovery_armed_name"
  successor_recovery_failure="$state_dir/$successor_recovery_failure_name"
  for value in "$successor_release_evidence_sha" "$successor_control_sha" \
    "$successor_dry_receipt_sha" "$successor_armed_receipt_sha" \
    "$predecessor_current_sha" "$predecessor_control_sha" \
    "$predecessor_apply_receipt_sha" "$current_predecessor_release_sha" \
    "$predecessor_runtime_backup_receipt_sha" \
    "$predecessor_runtime_backup_manifest_sha" "$successor_apply_armed_sha" \
    "$successor_transaction_sha" "$successor_applied_targets_sha" \
    "$successor_runtime_caller_sha" "$successor_runtime_stop_sha"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "recovered successor CURRENT contains an invalid authority hash"
  done

  [[ ! -e "$backup/APPLY.receipt" && ! -L "$backup/APPLY.receipt" && \
    ! -e "$backup/APPLY-PENDING.receipt" && ! -L "$backup/APPLY-PENDING.receipt" ]] || \
    holdfast_die "recovery abandonment refuses APPLY/recovery hybrid authority"
  for value in \
    "$backup/CONTROL.sha256" "$backup/RELEASE-EVIDENCE.json" \
    "$backup/DRY-RUN.receipt" "$backup/SUCCESSOR-ARMED.receipt" \
    "$backup/PREDECESSOR-CURRENT.json" "$backup/APPLY-ARMED.receipt" \
    "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt" \
    "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" \
    "$backup/estate/TRANSACTION.json" "$backup/estate/APPLIED-TARGETS.sha256" \
    "$successor_recovery_receipt" "$successor_recovery_archive" \
    "$successor_recovery_armed" "$successor_recovery_failure" \
    "$predecessor_backup/RELEASE-EVIDENCE.json" \
    "$predecessor_backup/CONTROL.sha256" "$predecessor_backup/APPLY.receipt" \
    "$predecessor_backup/runtime/BACKUP.receipt" \
    "$predecessor_backup/runtime/SHA256SUMS"; do
    require_private_root_file "$value" "recovery abandonment authority"
  done
  policy="$backup/successor-authority/successor-policy.json"
  require_private_root_file "$policy" "successor policy authority"
  validate_schema4_successor_policy "$policy" || \
    holdfast_die "successor policy is not exact schema-v4 authority"
  validate_schema4_gen5_recovery_abandon_authority \
    "$state_file" "$successor_recovery_archive" "$successor_recovery_receipt" \
    "$successor_recovery_armed" "$successor_recovery_failure" \
    "$successor_estate_root" "$backup" "$predecessor_backup" || \
    holdfast_die "schema-v4/Gen5 recovery completion authority is not exact"
  python3 "$script_dir/successor_binding.py" \
    --validate-gen4-lineage \
    --current-state "$backup/PREDECESSOR-CURRENT.json" \
    --estate-root "$successor_estate_root" >/dev/null || \
    holdfast_die "schema-v4 predecessor CURRENT/APPLY lineage differs"

  successor_policy_sha=$(holdfast_sha256 "$policy")
  successor_recovery_receipt_sha=$(holdfast_sha256 "$successor_recovery_receipt")
  successor_recovery_archive_sha=$(holdfast_sha256 "$successor_recovery_archive")
  successor_recovery_armed_sha=$(holdfast_sha256 "$successor_recovery_armed")
  successor_recovery_failure_sha=$(holdfast_sha256 "$successor_recovery_failure")
  [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$successor_control_sha" && \
    "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" == \
      "$successor_release_evidence_sha" && \
    "$(holdfast_sha256 "$backup/DRY-RUN.receipt")" == "$successor_dry_receipt_sha" && \
    "$(holdfast_sha256 "$backup/SUCCESSOR-ARMED.receipt")" == \
      "$successor_armed_receipt_sha" && \
    "$(holdfast_sha256 "$backup/PREDECESSOR-CURRENT.json")" == \
      "$predecessor_current_sha" && \
    "$(holdfast_sha256 "$backup/APPLY-ARMED.receipt")" == \
      "$successor_apply_armed_sha" && \
    "$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt")" == \
      "$successor_runtime_caller_sha" && \
    "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == \
      "$successor_runtime_stop_sha" && \
    "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == \
      "$successor_transaction_sha" && \
    "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" == \
      "$successor_applied_targets_sha" && \
    "$(jq -er '.recovery_receipt_sha256' "$state_file")" == \
      "$successor_recovery_receipt_sha" && \
    "$(jq -er '.recovery_armed_receipt_sha256' "$state_file")" == \
      "$successor_recovery_armed_sha" && \
    "$(jq -er '.apply_failure_receipt_sha256' "$state_file")" == \
      "$successor_recovery_failure_sha" ]] || \
    holdfast_die "recovered successor authority differs from CURRENT"
  (cd "$backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "successor frozen CONTROL authority does not verify"
  [[ "$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")" == \
      "$predecessor_control_sha" ]] || \
    holdfast_die "predecessor CONTROL authority differs from CURRENT"
  (cd "$predecessor_backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "predecessor frozen CONTROL authority does not verify"

  arm_keys=$(receipt_key_set "$backup/SUCCESSOR-ARMED.receipt") || \
    holdfast_die "successor armed authority is malformed"
  [[ "$arm_keys" == $'armed_at\ncandidate_dry_run_receipt_sha256\ncandidate_release_evidence_sha256\nestate_root\ningress_opened\npredecessor_apply_receipt_sha256\npredecessor_backup_dir\npredecessor_control_sha256\npredecessor_current_file\npredecessor_current_sha256\npredecessor_release_evidence_sha256\npredecessor_release_generation\npredecessor_runtime_backup_manifest_sha256\npredecessor_runtime_backup_receipt_sha256\npredecessor_runtime_verified\npublic_ipv4_ipv6_closed_status\nrelease_generation\nroute_database_state\nschema_version\nsuccessor_backup_dir\nsuccessor_policy_sha256' ]] || \
    holdfast_die "schema-v4 successor armed authority field set is not exact"
  armed_at=$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" armed_at)
  [[ "$armed_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "schema-v4 successor armed timestamp is invalid"
  for expected in \
    "schema_version=1" \
    "estate_root=$successor_estate_root" \
    "successor_backup_dir=$backup" \
    "candidate_dry_run_receipt_sha256=$successor_dry_receipt_sha" \
    "candidate_release_evidence_sha256=$successor_release_evidence_sha" \
    "successor_policy_sha256=$successor_policy_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_receipt_sha" \
    "predecessor_release_evidence_sha256=$current_predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_backup_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_backup_manifest_sha" \
    "predecessor_release_generation=$predecessor_release_generation" \
    "release_generation=$successor_release_generation" \
    "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" \
    "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" "$key")" == \
      "$value" ]] || holdfast_die "successor armed authority differs: $key"
  done
  [[ "$predecessor_current_sha" == \
      "$(jq -er '.predecessor.current_state_sha256' "$policy")" && \
    "$predecessor_control_sha" == \
      "$(jq -er '.predecessor.control_sha256' "$policy")" && \
    "$predecessor_apply_receipt_sha" == \
      "$(jq -er '.predecessor.apply_receipt_sha256' "$policy")" && \
    "$current_predecessor_release_sha" == \
      "$(jq -er '.predecessor.release_evidence_sha256' "$policy")" && \
    "$predecessor_runtime_backup_manifest_sha" == \
      "$(jq -er '.predecessor.runtime_manifest_sha256' "$policy")" && \
    "$predecessor_apply_receipt_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/APPLY.receipt")" && \
    "$predecessor_runtime_backup_receipt_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")" && \
    "$predecessor_runtime_backup_manifest_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")" ]] || \
    holdfast_die "schema-v4 predecessor APPLY/runtime authority differs"

  predecessor_release=$(jq -er '.release_evidence_sha256' \
    "$backup/PREDECESSOR-CURRENT.json")
  current_release=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  [[ "$predecessor_release" =~ ^[0-9a-f]{64}$ && \
    "$predecessor_release" == "$current_release" && \
    "$predecessor_release" == "$current_predecessor_release_sha" && \
    "$predecessor_release" != "$successor_release_evidence_sha" ]] || \
    holdfast_die "predecessor and successor release evidence lineage is not exact"
  [[ "$(jq -er '.release_generation // 1' \
      "$backup/PREDECESSOR-CURRENT.json")" == "$predecessor_release_generation" ]] || \
    holdfast_die "frozen predecessor CURRENT generation differs"
  predecessor_release_evidence_sha=$predecessor_release
  successor_abandon_estate_root=$successor_estate_root
  successor_abandon_backup=$backup
  successor_abandon_predecessor_backup=$predecessor_backup

  namespace_after=$(snapshot_recovery_abandon_namespace) || \
    holdfast_die "recovery abandonment namespace is unsafe"
  [[ "$namespace_after" == "$namespace_before" && \
    "$(holdfast_sha256 "$state_file")" == "$successor_current_sha" && \
    ! -e "$backup/APPLY.receipt" && ! -L "$backup/APPLY.receipt" && \
    ! -e "$backup/APPLY-PENDING.receipt" && ! -L "$backup/APPLY-PENDING.receipt" ]] || \
    holdfast_die "recovery abandonment authority changed during validation"
  successor_recovery_namespace_sha=$namespace_after
}

load_successor_abandon_authority() {
  local backup predecessor_backup current_release predecessor_release expected key value
  local policy arm_keys successor_estate_root armed_at
  require_private_root_file "$state_file" "active apply state"
  if jq -e '
    has("recovery_mode") or has("recovery_attempt_id") or
    has("recovery_receipt") or has("recovery_armed_receipt") or
    has("apply_failure_receipt")
  ' "$state_file" >/dev/null; then
    load_successor_recovery_abandon_authority
    return 0
  fi
  successor_abandon_authority_kind="apply"
  jq -e '
    .schema_version == 2 and .state == "applied_ingress_closed" and
    .successor == true and
    .ingress_opened == false and .route_database_state == "absent" and
    .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
    .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
    (.predecessor_release_generation | type) == "number" and
    (.release_generation | type) == "number" and
    (.predecessor_release_generation | floor) == .predecessor_release_generation and
    (.release_generation | floor) == .release_generation and
    .predecessor_release_generation == 4 and .release_generation == 5 and
    (.predecessor_apply_receipt_sha256 | type) == "string" and
    (.predecessor_apply_receipt_sha256 | test("^[0-9a-f]{64}$")) and
    ([keys[] | select(startswith("predecessor_completion_"))] | length) == 0
  ' "$state_file" >/dev/null || \
    holdfast_die "prepare abandonment requires an exact closed successor CURRENT"

  predecessor_release_generation=$(jq -er '.predecessor_release_generation' "$state_file")
  successor_release_generation=$(jq -er '.release_generation' "$state_file")
  successor_release_evidence_sha=$(jq -er '.release_evidence_sha256' "$state_file")
  successor_control_sha=$(jq -er '.control_sha256' "$state_file")
  successor_apply_receipt_sha=$(jq -er '.apply_receipt_sha256' "$state_file")
  successor_armed_receipt_sha=$(jq -er '.successor_armed_receipt_sha256' "$state_file")
  predecessor_current_sha=$(jq -er '.predecessor_current_sha256' "$state_file")
  predecessor_control_sha=$(jq -er '.predecessor_control_sha256' "$state_file")
  predecessor_apply_receipt_sha=$(jq -er '.predecessor_apply_receipt_sha256' "$state_file")
  current_predecessor_release_sha=$(jq -er '.predecessor_release_evidence_sha256' "$state_file")
  predecessor_runtime_backup_receipt_sha=$(jq -er \
    '.predecessor_runtime_backup_receipt_sha256' "$state_file")
  predecessor_runtime_backup_manifest_sha=$(jq -er \
    '.predecessor_runtime_backup_manifest_sha256' "$state_file")
  successor_estate_root=$(jq -er '.estate_root' "$state_file")
  backup=$(jq -er '.backup_dir' "$state_file")
  predecessor_backup=$(jq -er '.predecessor_backup_dir' "$state_file")
  holdfast_require_absolute "$backup"
  holdfast_require_absolute "$predecessor_backup"
  require_private_root_directory "$backup" "successor release authority directory"
  require_private_root_directory "$predecessor_backup" "predecessor release authority directory"
  for value in "$successor_release_evidence_sha" "$successor_control_sha" \
    "$successor_apply_receipt_sha" "$successor_armed_receipt_sha" \
    "$predecessor_current_sha" "$predecessor_control_sha" \
    "$predecessor_apply_receipt_sha" "$current_predecessor_release_sha" \
    "$predecessor_runtime_backup_receipt_sha" \
    "$predecessor_runtime_backup_manifest_sha"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "successor CURRENT contains an invalid release authority hash"
  done

  require_private_root_file "$backup/CONTROL.sha256" "successor CONTROL authority"
  require_private_root_file "$backup/RELEASE-EVIDENCE.json" "successor release evidence"
  require_private_root_file "$backup/APPLY.receipt" "successor apply receipt"
  require_private_root_file "$backup/DRY-RUN.receipt" "successor dry-run receipt"
  require_private_root_file "$backup/SUCCESSOR-ARMED.receipt" "successor armed receipt"
  require_private_root_file "$backup/PREDECESSOR-CURRENT.json" "frozen predecessor CURRENT"
  policy="$backup/successor-authority/successor-policy.json"
  require_private_root_file "$policy" "successor policy authority"
  validate_schema4_successor_policy "$policy" || \
    holdfast_die "successor policy is not exact schema-v4 authority"
  require_private_root_file "$predecessor_backup/RELEASE-EVIDENCE.json" "predecessor release evidence"
  require_private_root_file "$predecessor_backup/CONTROL.sha256" "predecessor CONTROL authority"
  require_private_root_file "$predecessor_backup/APPLY.receipt" "predecessor apply receipt"
  require_private_root_file "$predecessor_backup/runtime/BACKUP.receipt" \
    "predecessor runtime backup receipt"
  require_private_root_file "$predecessor_backup/runtime/SHA256SUMS" \
    "predecessor runtime backup manifest"
  validate_schema4_gen5_namespaces \
    "$state_file" "$backup/APPLY.receipt" "$backup/PREDECESSOR-CURRENT.json" \
    "$successor_estate_root" "$backup" "$predecessor_backup" || \
    holdfast_die "schema-v4/Gen5 authority namespace is not exact"
  python3 "$script_dir/successor_binding.py" \
    --validate-gen4-lineage \
    --current-state "$backup/PREDECESSOR-CURRENT.json" \
    --estate-root "$successor_estate_root" >/dev/null || \
    holdfast_die "schema-v4 predecessor CURRENT/APPLY lineage differs"
  successor_policy_sha=$(holdfast_sha256 "$policy")
  successor_dry_receipt_sha=$(holdfast_sha256 "$backup/DRY-RUN.receipt")
  [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$successor_control_sha" && \
    "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" == "$successor_release_evidence_sha" && \
    "$(holdfast_sha256 "$backup/APPLY.receipt")" == "$successor_apply_receipt_sha" && \
    "$(holdfast_sha256 "$backup/SUCCESSOR-ARMED.receipt")" == "$successor_armed_receipt_sha" && \
    "$(holdfast_sha256 "$backup/PREDECESSOR-CURRENT.json")" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor frozen release authority differs from CURRENT"
  (cd "$backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "successor frozen CONTROL authority does not verify"
  [[ "$predecessor_control_sha" =~ ^[0-9a-f]{64}$ && \
    "$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")" == "$predecessor_control_sha" ]] || \
    holdfast_die "predecessor CONTROL authority differs from CURRENT"
  (cd "$predecessor_backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "predecessor frozen CONTROL authority does not verify"

  arm_keys=$(receipt_key_set "$backup/SUCCESSOR-ARMED.receipt") || \
    holdfast_die "successor armed authority is malformed"
  [[ "$arm_keys" == $'armed_at\ncandidate_dry_run_receipt_sha256\ncandidate_release_evidence_sha256\nestate_root\ningress_opened\npredecessor_apply_receipt_sha256\npredecessor_backup_dir\npredecessor_control_sha256\npredecessor_current_file\npredecessor_current_sha256\npredecessor_release_evidence_sha256\npredecessor_release_generation\npredecessor_runtime_backup_manifest_sha256\npredecessor_runtime_backup_receipt_sha256\npredecessor_runtime_verified\npublic_ipv4_ipv6_closed_status\nrelease_generation\nroute_database_state\nschema_version\nsuccessor_backup_dir\nsuccessor_policy_sha256' ]] || \
    holdfast_die "schema-v4 successor armed authority field set is not exact"
  armed_at=$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" armed_at)
  [[ "$armed_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "schema-v4 successor armed timestamp is invalid"

  for expected in \
    "schema_version=1" \
    "estate_root=$successor_estate_root" \
    "successor_backup_dir=$backup" \
    "candidate_dry_run_receipt_sha256=$successor_dry_receipt_sha" \
    "candidate_release_evidence_sha256=$successor_release_evidence_sha" \
    "successor_policy_sha256=$successor_policy_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_receipt_sha" \
    "predecessor_release_evidence_sha256=$current_predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_backup_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_backup_manifest_sha" \
    "predecessor_release_generation=$predecessor_release_generation" \
    "release_generation=$successor_release_generation" \
    "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" \
    "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor armed authority differs: $key"
  done
  [[ "$predecessor_current_sha" == \
      "$(jq -er '.predecessor.current_state_sha256' "$policy")" && \
    "$predecessor_control_sha" == \
      "$(jq -er '.predecessor.control_sha256' "$policy")" && \
    "$predecessor_apply_receipt_sha" == \
      "$(jq -er '.predecessor.apply_receipt_sha256' "$policy")" && \
    "$current_predecessor_release_sha" == \
      "$(jq -er '.predecessor.release_evidence_sha256' "$policy")" && \
    "$predecessor_runtime_backup_manifest_sha" == \
      "$(jq -er '.predecessor.runtime_manifest_sha256' "$policy")" && \
    "$predecessor_apply_receipt_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/APPLY.receipt")" && \
    "$predecessor_runtime_backup_receipt_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")" && \
    "$predecessor_runtime_backup_manifest_sha" == \
      "$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")" ]] || \
    holdfast_die "schema-v4 predecessor APPLY/runtime authority differs"

  for expected in \
    "schema_version=2" \
    "completion_state=applied_ingress_closed" \
    "backup_dir=$backup" \
    "release_evidence_sha256=$successor_release_evidence_sha" \
    "control_sha256=$successor_control_sha" \
    "successor=true" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_receipt_sha" \
    "predecessor_release_evidence_sha256=$current_predecessor_release_sha" \
    "predecessor_release_generation=$predecessor_release_generation" \
    "release_generation=$successor_release_generation" \
    "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/APPLY.receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor apply authority differs: $key"
  done
  ! grep -q '^predecessor_completion_' "$state_file" || \
    holdfast_die "schema-v4 successor CURRENT contains recovery completion authority"
  ! grep -q '^predecessor_completion_' "$backup/SUCCESSOR-ARMED.receipt" || \
    holdfast_die "schema-v4 successor arm contains recovery completion authority"
  ! grep -q '^predecessor_completion_' "$backup/APPLY.receipt" || \
    holdfast_die "schema-v4 successor APPLY contains recovery completion authority"

  predecessor_release=$(jq -er '.release_evidence_sha256' "$backup/PREDECESSOR-CURRENT.json")
  current_release=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  [[ "$predecessor_release" =~ ^[0-9a-f]{64}$ && \
    "$predecessor_release" == "$current_release" && \
    "$predecessor_release" == "$current_predecessor_release_sha" && \
    "$predecessor_release" != "$successor_release_evidence_sha" ]] || \
    holdfast_die "predecessor and successor release evidence lineage is not exact"
  [[ "$(jq -er '.release_generation // 1' "$backup/PREDECESSOR-CURRENT.json")" == \
    "$predecessor_release_generation" ]] || \
    holdfast_die "frozen predecessor CURRENT generation differs"
  predecessor_release_evidence_sha=$predecessor_release
  successor_current_sha=$(holdfast_sha256 "$state_file")
  successor_abandon_backup=$backup
  successor_abandon_predecessor_backup=$predecessor_backup
}

recheck_successor_abandon_authority() {
  local source_path=${1:-}
  if [[ "${successor_abandon_authority_kind:-apply}" == "recovery-resume" ]]; then
    local current_namespace historical_snapshot
    for authority in \
      "$state_file" "$successor_recovery_receipt" "$successor_recovery_archive" \
      "$successor_recovery_armed" "$successor_recovery_failure" \
      "$successor_abandon_backup/CONTROL.sha256" \
      "$successor_abandon_backup/RELEASE-EVIDENCE.json" \
      "$successor_abandon_backup/DRY-RUN.receipt" \
      "$successor_abandon_backup/SUCCESSOR-ARMED.receipt" \
      "$successor_abandon_backup/PREDECESSOR-CURRENT.json" \
      "$successor_abandon_backup/APPLY-ARMED.receipt" \
      "$successor_abandon_backup/RUNTIME-BACKUP-CALLER-ARMED.receipt" \
      "$successor_abandon_backup/runtime/RUNTIME-BACKUP-ARMED.receipt" \
      "$successor_abandon_backup/estate/TRANSACTION.json" \
      "$successor_abandon_backup/estate/APPLIED-TARGETS.sha256" \
      "$successor_abandon_backup/successor-authority/successor-policy.json" \
      "$successor_abandon_predecessor_backup/CONTROL.sha256" \
      "$successor_abandon_predecessor_backup/RELEASE-EVIDENCE.json" \
      "$successor_abandon_predecessor_backup/APPLY.receipt" \
      "$successor_abandon_predecessor_backup/runtime/BACKUP.receipt" \
      "$successor_abandon_predecessor_backup/runtime/SHA256SUMS"; do
      require_private_root_file "$authority" "frozen recovery abandonment authority"
    done
    current_namespace=$(snapshot_recovery_abandon_namespace) || \
      holdfast_die "recovery abandonment namespace changed before commit"
    [[ "$current_namespace" == "$successor_recovery_namespace_sha" && \
      ! -e "$successor_abandon_backup/APPLY.receipt" && \
      ! -L "$successor_abandon_backup/APPLY.receipt" && \
      ! -e "$successor_abandon_backup/APPLY-PENDING.receipt" && \
      ! -L "$successor_abandon_backup/APPLY-PENDING.receipt" && \
      "$(holdfast_sha256 "$state_file")" == "$successor_current_sha" && \
      "$(holdfast_sha256 "$successor_recovery_receipt")" == \
        "$successor_recovery_receipt_sha" && \
      "$(holdfast_sha256 "$successor_recovery_archive")" == \
        "$successor_recovery_archive_sha" && \
      "$(holdfast_sha256 "$successor_recovery_armed")" == \
        "$successor_recovery_armed_sha" && \
      "$(holdfast_sha256 "$successor_recovery_failure")" == \
        "$successor_recovery_failure_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/CONTROL.sha256")" == \
        "$successor_control_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/RELEASE-EVIDENCE.json")" == \
        "$successor_release_evidence_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/DRY-RUN.receipt")" == \
        "$successor_dry_receipt_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/SUCCESSOR-ARMED.receipt")" == \
        "$successor_armed_receipt_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/PREDECESSOR-CURRENT.json")" == \
        "$predecessor_current_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/APPLY-ARMED.receipt")" == \
        "$successor_apply_armed_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/RUNTIME-BACKUP-CALLER-ARMED.receipt")" == \
        "$successor_runtime_caller_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == \
        "$successor_runtime_stop_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/estate/TRANSACTION.json")" == \
        "$successor_transaction_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/estate/APPLIED-TARGETS.sha256")" == \
        "$successor_applied_targets_sha" && \
      "$(holdfast_sha256 "$successor_abandon_backup/successor-authority/successor-policy.json")" == \
        "$successor_policy_sha" && \
      "$(holdfast_sha256 "$successor_abandon_predecessor_backup/CONTROL.sha256")" == \
        "$predecessor_control_sha" && \
      "$(holdfast_sha256 "$successor_abandon_predecessor_backup/RELEASE-EVIDENCE.json")" == \
        "$predecessor_release_evidence_sha" && \
      "$(holdfast_sha256 "$successor_abandon_predecessor_backup/APPLY.receipt")" == \
        "$predecessor_apply_receipt_sha" && \
      "$(holdfast_sha256 "$successor_abandon_predecessor_backup/runtime/BACKUP.receipt")" == \
        "$predecessor_runtime_backup_receipt_sha" && \
      "$(holdfast_sha256 "$successor_abandon_predecessor_backup/runtime/SHA256SUMS")" == \
        "$predecessor_runtime_backup_manifest_sha" ]] || \
      holdfast_die "frozen recovery abandonment authority changed before commit"
    validate_schema4_gen5_recovery_abandon_authority \
      "$state_file" "$successor_recovery_archive" "$successor_recovery_receipt" \
      "$successor_recovery_armed" "$successor_recovery_failure" \
      "$successor_abandon_estate_root" "$successor_abandon_backup" \
      "$successor_abandon_predecessor_backup" || \
      holdfast_die "schema-v4/Gen5 recovery completion authority changed before commit"
    (cd "$successor_abandon_backup" && \
      sha256sum --check CONTROL.sha256 >/dev/null) || \
      holdfast_die "successor frozen CONTROL authority changed before commit"
    (cd "$successor_abandon_predecessor_backup" && \
      sha256sum --check CONTROL.sha256 >/dev/null) || \
      holdfast_die "predecessor frozen CONTROL authority changed before commit"
    [[ ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
      holdfast_die "recovery abandonment OPEN authority changed before commit"
    if [[ "${successor_abandon_source_kind:-immediate}" == "historical-rollback" ]]; then
      [[ -n "$source_path" ]] || \
        holdfast_die "historical rollback source receipt is absent at commit boundary"
      historical_snapshot=$(validate_historical_rollback_abandon_authority \
        "$source_path" "$historical_release_validator") || \
        holdfast_die "historical rollback authority changed before commit"
      [[ "$historical_snapshot" == "$historical_authority_snapshot" ]] || \
        holdfast_die "historical rollback authority snapshot changed before commit"
    fi
    return 0
  fi
  [[ "$(holdfast_sha256 "$successor_abandon_backup/CONTROL.sha256")" == \
      "$successor_control_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/RELEASE-EVIDENCE.json")" == \
      "$successor_release_evidence_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/APPLY.receipt")" == \
      "$successor_apply_receipt_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/DRY-RUN.receipt")" == \
      "$successor_dry_receipt_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/SUCCESSOR-ARMED.receipt")" == \
      "$successor_armed_receipt_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/successor-authority/successor-policy.json")" == \
      "$successor_policy_sha" && \
    "$(holdfast_sha256 "$successor_abandon_backup/PREDECESSOR-CURRENT.json")" == \
      "$predecessor_current_sha" && \
    "$(holdfast_sha256 "$successor_abandon_predecessor_backup/CONTROL.sha256")" == \
      "$predecessor_control_sha" && \
    "$(holdfast_sha256 "$successor_abandon_predecessor_backup/RELEASE-EVIDENCE.json")" == \
      "$predecessor_release_evidence_sha" && \
    "$(holdfast_sha256 "$successor_abandon_predecessor_backup/APPLY.receipt")" == \
      "$predecessor_apply_receipt_sha" && \
    "$(holdfast_sha256 "$successor_abandon_predecessor_backup/runtime/BACKUP.receipt")" == \
      "$predecessor_runtime_backup_receipt_sha" && \
    "$(holdfast_sha256 "$successor_abandon_predecessor_backup/runtime/SHA256SUMS")" == \
      "$predecessor_runtime_backup_manifest_sha" ]] || \
    holdfast_die "frozen successor/predecessor abandonment authority changed before commit"
  (cd "$successor_abandon_backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "successor frozen CONTROL authority changed before commit"
  (cd "$successor_abandon_predecessor_backup" && \
    sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "predecessor frozen CONTROL authority changed before commit"
}

reject_conflicting_prepare_archives() {
  local expected_archive=$1 expected_pending=$2 candidate
  local -a completed_candidates pending_candidates
  shopt -s nullglob
  completed_candidates=(
    "$state_dir"/OPEN-PREPARE-ABANDONED-G"$source_archive_generation"-BY-G"$successor_release_generation"-*.receipt
  )
  pending_candidates=(
    "$state_dir"/.OPEN-PREPARE-ABANDONED-G"$source_archive_generation"-BY-G"$successor_release_generation"-*.pending
  )
  shopt -u nullglob
  for candidate in "${completed_candidates[@]}"; do
    [[ "$candidate" == "$expected_archive" ]] || \
      holdfast_die "conflicting completed prepare archive exists: $candidate"
  done
  for candidate in "${pending_candidates[@]}"; do
    [[ "$candidate" == "$expected_pending" ]] || \
      holdfast_die "conflicting pending prepare archive exists: $candidate"
  done
}

abandon_stale_prepare() {
  local supersede_name supersede_receipt pending_archive pending_receipt check_file abandoned_at
  local reason_size replay_archive archive_stage
  require_private_root_directory "$state_dir" "active state directory"
  load_successor_abandon_authority
  [[ ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
    holdfast_die "prepare abandonment refuses a hybrid final OPEN receipt"
  [[ "$(readlink -f -- "$reason_file")" == "$reason_file" ]] || \
    holdfast_die "prepare abandonment reason file path is not canonical"
  [[ "$reason_file" != "$state_file" && "$reason_file" != "$prepare_receipt" && \
    "$reason_file" != "$open_receipt" ]] || \
    holdfast_die "prepare abandonment reason must be separate from live ceremony authority"
  require_private_root_file "$reason_file" "prepare abandonment reason file"
  reason_size=$(stat -c '%s' -- "$reason_file")
  [[ "$reason_size" =~ ^[0-9]+$ && "$reason_size" -ge 1 && "$reason_size" -le 4096 ]] || \
    holdfast_die "prepare abandonment reason file must contain 1..4096 sealed bytes"
  reason_file_sha=$(holdfast_sha256 "$reason_file")
  [[ "$reason_file_sha" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "prepare abandonment reason hash is invalid"

  supersede_name="OPEN-PREPARE-SUPERSEDED-G${successor_release_generation}.receipt"
  supersede_receipt="$state_dir/$supersede_name"
  pending_receipt="$state_dir/.${supersede_name}.pending"
  check_file="$state_dir/.${supersede_name}.check.$$"

  if [[ ! -e "$prepare_receipt" && ! -L "$prepare_receipt" ]]; then
    if [[ -f "$supersede_receipt" && ! -L "$supersede_receipt" ]]; then
      source_prepare_sha=$(holdfast_receipt_value "$supersede_receipt" source_prepare_receipt_sha256)
      [[ "$source_prepare_sha" =~ ^[0-9a-f]{64}$ ]] || \
        holdfast_die "persisted prepare archive hash is invalid"
      archive_name=$(holdfast_receipt_value "$supersede_receipt" archive_name)
      [[ "$archive_name" =~ ^OPEN-PREPARE-ABANDONED-G[1-9][0-9]*-BY-G${successor_release_generation}-${source_prepare_sha}\.receipt$ ]] || \
        holdfast_die "persisted prepare archive name is unsafe"
      replay_archive="$state_dir/$archive_name"
      pending_archive="$state_dir/.${archive_name}.pending"
      validate_stale_prepare_receipt "$replay_archive"
      bind_prepare_abandon_source_authority "$replay_archive"
      [[ "$archive_name" == "OPEN-PREPARE-ABANDONED-G${source_archive_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt" ]] || \
        holdfast_die "persisted prepare archive name differs from successor lineage"
      reject_conflicting_prepare_archives "$replay_archive" "$pending_archive"
      [[ "$(holdfast_sha256 "$replay_archive")" == "$source_prepare_sha" ]] || \
        holdfast_die "persisted prepare archive differs from frozen source authority"
      validate_prepare_supersede_receipt "$supersede_receipt" "$check_file"
      [[ ! -e "$pending_receipt" && ! -L "$pending_receipt" ]] || \
        holdfast_die "completed prepare abandonment retains a hybrid pending receipt"
      [[ ! -e "$pending_archive" && ! -L "$pending_archive" ]] || \
        holdfast_die "completed prepare abandonment retains a hybrid pending archive"
      echo "stale OPEN-PREPARE abandonment replay verified for successor generation $successor_release_generation"
      return 0
    fi

    [[ -f "$pending_receipt" && ! -L "$pending_receipt" ]] || \
      holdfast_die "OPEN-PREPARE is absent without a complete or recoverable supersede receipt"
    source_prepare_sha=$(holdfast_receipt_value "$pending_receipt" source_prepare_receipt_sha256)
    [[ "$source_prepare_sha" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "pending prepare archive hash is invalid"
    archive_name=$(holdfast_receipt_value "$pending_receipt" archive_name)
    [[ "$archive_name" =~ ^OPEN-PREPARE-ABANDONED-G[1-9][0-9]*-BY-G${successor_release_generation}-${source_prepare_sha}\.receipt$ ]] || \
      holdfast_die "pending prepare archive name is unsafe"
    replay_archive="$state_dir/$archive_name"
    pending_archive="$state_dir/.${archive_name}.pending"
    validate_stale_prepare_receipt "$replay_archive"
    bind_prepare_abandon_source_authority "$replay_archive"
    [[ "$archive_name" == "OPEN-PREPARE-ABANDONED-G${source_archive_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt" ]] || \
      holdfast_die "pending prepare archive name differs from successor lineage"
    reject_conflicting_prepare_archives "$replay_archive" "$pending_archive"
    [[ "$(holdfast_sha256 "$replay_archive")" == "$source_prepare_sha" ]] || \
      holdfast_die "recoverable prepare archive differs from frozen source authority"
    validate_prepare_supersede_receipt "$pending_receipt" "$check_file"
    [[ ! -e "$pending_archive" && ! -L "$pending_archive" ]] || \
      holdfast_die "recoverable prepare abandonment retains a hybrid pending archive"
    [[ ! -e "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
      holdfast_die "prepare abandonment contains hybrid final and pending receipts"
    recheck_successor_abandon_authority "$replay_archive"
    [[ "$(holdfast_sha256 "$replay_archive")" == "$source_prepare_sha" && \
      "$(holdfast_sha256 "$state_file")" == "$successor_current_sha" && \
      "$(holdfast_sha256 "$reason_file")" == "$reason_file_sha" ]] || \
      holdfast_die "prepare abandonment recovery authority changed before commit"
    mv -nT -- "$pending_receipt" "$supersede_receipt"
    [[ ! -e "$pending_receipt" && ! -L "$pending_receipt" && \
      -f "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
      holdfast_die "prepare supersede receipt appeared at the recovery commit boundary"
    sync -f "$supersede_receipt"
    sync -f "$state_dir"
    validate_prepare_supersede_receipt "$supersede_receipt" "$check_file"
    echo "recovered stale OPEN-PREPARE abandonment for successor generation $successor_release_generation"
    return 0
  fi

  require_private_root_file "$prepare_receipt" "stale open prepare receipt"
  [[ ! -e "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
    holdfast_die "live OPEN-PREPARE cannot coexist with a supersede receipt"
  validate_stale_prepare_receipt "$prepare_receipt"
  bind_prepare_abandon_source_authority "$prepare_receipt"
  source_prepare_sha=$(holdfast_sha256 "$prepare_receipt")
  archive_name="OPEN-PREPARE-ABANDONED-G${source_archive_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt"
  archive="$state_dir/$archive_name"
  pending_archive="$state_dir/.${archive_name}.pending"
  reject_conflicting_prepare_archives "$archive" "$pending_archive"
  [[ ! -e "$archive" && ! -L "$archive" ]] || \
    holdfast_die "live OPEN-PREPARE cannot coexist with a completed archive"

  if [[ -e "$pending_archive" || -L "$pending_archive" ]]; then
    require_private_root_file "$pending_archive" "pending prepare archive"
    cmp -s -- "$prepare_receipt" "$pending_archive" || \
      holdfast_die "pending prepare archive conflicts with the live receipt"
  else
    archive_stage="$state_dir/.${archive_name}.stage.$$"
    [[ ! -e "$archive_stage" && ! -L "$archive_stage" ]] || \
      holdfast_die "prepare archive staging path already exists"
    install -o 0 -g 0 -m 0600 -- "$prepare_receipt" "$archive_stage"
    sync -f "$archive_stage"
    mv -nT -- "$archive_stage" "$pending_archive"
    [[ ! -e "$archive_stage" && ! -L "$archive_stage" && \
      -f "$pending_archive" && ! -L "$pending_archive" ]] || \
      holdfast_die "pending prepare archive appeared during staging"
  fi
  sync -f "$pending_archive"

  if [[ -e "$pending_receipt" || -L "$pending_receipt" ]]; then
    require_private_root_file "$pending_receipt" "pending prepare supersede receipt"
    abandoned_at=$(holdfast_receipt_value "$pending_receipt" abandoned_at)
  else
    abandoned_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  fi
  render_prepare_supersede_receipt "$abandoned_at" "$check_file"
  if [[ -e "$pending_receipt" || -L "$pending_receipt" ]]; then
    cmp -s -- "$pending_receipt" "$check_file" || \
      holdfast_die "pending prepare supersede receipt conflicts with this abandonment"
    rm -f -- "$check_file"
  else
    mv -nT -- "$check_file" "$pending_receipt"
    [[ ! -e "$check_file" && ! -L "$check_file" && \
      -f "$pending_receipt" && ! -L "$pending_receipt" ]] || \
      holdfast_die "pending prepare supersede receipt appeared during staging"
  fi
  sync -f "$pending_receipt"
  validate_prepare_supersede_receipt "$pending_receipt" "$check_file"
  sync -f "$state_dir"
  recheck_successor_abandon_authority "$prepare_receipt"
  [[ "$(holdfast_sha256 "$prepare_receipt")" == "$source_prepare_sha" && \
    "$(holdfast_sha256 "$pending_archive")" == "$source_prepare_sha" && \
    "$(holdfast_sha256 "$state_file")" == "$successor_current_sha" && \
    "$(holdfast_sha256 "$reason_file")" == "$reason_file_sha" ]] || \
    holdfast_die "prepare abandonment authority changed before commit"

  rm -f -- "$pending_archive"
  [[ ! -e "$archive" && ! -L "$archive" ]] || \
    holdfast_die "prepare archive appeared at the commit boundary"
  mv -nT -- "$prepare_receipt" "$archive"
  [[ ! -e "$prepare_receipt" && ! -L "$prepare_receipt" && \
    -f "$archive" && ! -L "$archive" ]] || \
    holdfast_die "prepare archive appeared at the live-pointer commit boundary"
  sync -f "$archive"
  sync -f "$state_dir"
  [[ "$(holdfast_sha256 "$archive")" == "$source_prepare_sha" ]] || \
    holdfast_die "atomically archived prepare receipt differs from its original hash"
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_STOP_AFTER_PREPARE_ARCHIVE_MOVE:-0}" == "1" ]]; then
    exit 75
  fi

  [[ ! -e "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
    holdfast_die "prepare supersede receipt appeared at the commit boundary"
  recheck_successor_abandon_authority "$archive"
  [[ "$(holdfast_sha256 "$archive")" == "$source_prepare_sha" && \
    "$(holdfast_sha256 "$state_file")" == "$successor_current_sha" && \
    "$(holdfast_sha256 "$reason_file")" == "$reason_file_sha" ]] || \
    holdfast_die "prepare abandonment authority changed before supersede commit"
  mv -nT -- "$pending_receipt" "$supersede_receipt"
  [[ ! -e "$pending_receipt" && ! -L "$pending_receipt" && \
    -f "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
    holdfast_die "prepare supersede receipt appeared at the commit boundary"
  sync -f "$supersede_receipt"
  sync -f "$state_dir"
  validate_prepare_supersede_receipt "$supersede_receipt" "$check_file"
  [[ ! -e "$prepare_receipt" && ! -L "$prepare_receipt" ]] || \
    holdfast_die "live OPEN-PREPARE pointer remains after audited abandonment"
  echo "stale OPEN-PREPARE archived and superseded for release generation $successor_release_generation; rerun prepare separately"
}

if [[ "$abandon_prepare" == "true" ]]; then
  abandon_stale_prepare
  exit 0
fi

stage="$dry_run_dir/stage"
release_evidence="$stage/RELEASE-EVIDENCE.json"
dry_receipt="$dry_run_dir/DRY-RUN.receipt"

archive_failed_open_receipt() {
  local failed_receipt
  if [[ -L "$open_receipt" || ( -e "$open_receipt" && ! -f "$open_receipt" ) ]]; then
    echo "holdfast: unsafe open receipt blocks recovery" >&2
    return 1
  fi
  if [[ -f "$open_receipt" ]]; then
    failed_receipt="$state_dir/FAILED-OPEN-$(date -u +%Y%m%dT%H%M%SZ)-$$.receipt"
    mv -- "$open_receipt" "$failed_receipt"
  fi
}

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-db-absent psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: route database does not prove rikune-root and analyze tombstone absence" >&2
    return 1
  }
}

verify_database_open() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-db-open psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: route database does not prove the exact rikune-root authority" >&2
    return 1
  }
}

verify_public_closed() {
  "$script_dir/public-origin-verify.sh" --mode closed --url https://rikune.w33d.xyz/
  "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/
}

verify_closed_bracket() {
  verify_database_absent
  verify_public_closed
  verify_database_absent
}

verify_open_bracket() {
  verify_database_open
  "$script_dir/public-origin-verify.sh" --mode open --url https://rikune.w33d.xyz/
  "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/
  verify_database_open
}

force_route_absent() {
  local target temporary status evidence_sha
  target="$state_dir/OPEN-ROUTE-DOWN-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
  temporary="$state_dir/.OPEN-ROUTE-DOWN.$$"
  if PGAPPNAME=holdfast-rikune-force-down psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/20260823_rikune_root_down.sql" >"$temporary" 2>&1; then
    status=0
  else
    status=$?
  fi
  if [[ ! -f "$temporary" || -L "$temporary" ]]; then
    echo "holdfast: frozen route-down output is not a regular non-symlink file" >&2
    return 1
  fi
  if ! chmod 0600 -- "$temporary"; then
    echo "holdfast: could not protect frozen route-down output" >&2
    return 1
  fi
  if ! mv -fT -- "$temporary" "$target"; then
    echo "holdfast: could not atomically persist frozen route-down output" >&2
    return 1
  fi
  if [[ ! -f "$target" || -L "$target" ]]; then
    echo "holdfast: persisted frozen route-down output is not a regular non-symlink file" >&2
    return 1
  fi
  if ! evidence_sha=$(holdfast_sha256 "$target"); then
    echo "holdfast: could not hash frozen route-down output" >&2
    return 1
  fi
  if [[ ! "$evidence_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: frozen route-down output hash is not lowercase SHA-256" >&2
    return 1
  fi
  route_down_execution_evidence_sha=$evidence_sha
  if [[ $status -ne 0 ]]; then
    echo "frozen route-down failed; exact output preserved at $target" >&2
    return "$status"
  fi
  return 0
}

write_interrupted_receipt() {
  local reason=$1
  local prior_state=$2
  local now stamp target temporary prepare_sha edge_sha route_down_sha receipt_sha
  if ! now=$(date -u +%Y-%m-%dT%H:%M:%SZ); then
    echo "holdfast: could not timestamp interrupted receipt" >&2
    return 1
  fi
  if ! stamp=$(date -u +%Y%m%dT%H%M%SZ); then
    echo "holdfast: could not name interrupted receipt" >&2
    return 1
  fi
  target="$state_dir/OPEN-INTERRUPTED-$stamp-$$.receipt"
  temporary="$state_dir/.OPEN-INTERRUPTED.$$"
  if ! prepare_sha=$(jq -er '.open_prepare_receipt_sha256 // "none"' "$state_file"); then
    echo "holdfast: could not bind prepare evidence into interrupted receipt" >&2
    return 1
  fi
  if ! edge_sha=$(jq -er '.open_armed_edge_evidence_sha256 // "none"' "$state_file"); then
    echo "holdfast: could not bind edge evidence into interrupted receipt" >&2
    return 1
  fi
  if ! route_down_sha=$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql"); then
    echo "holdfast: could not hash frozen route-down asset for interrupted receipt" >&2
    return 1
  fi
  if [[ ! "$route_down_sha" =~ ^[0-9a-f]{64}$ || ! "${route_down_execution_evidence_sha:-}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: interrupted receipt inputs are not lowercase SHA-256 values" >&2
    return 1
  fi
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    echo "holdfast: unsafe interrupted receipt temporary path" >&2
    return 1
  fi
  if ! {
    printf 'interrupted_at=%s\n' "$now"
    printf 'reason=%s\n' "$reason"
    printf 'prior_state=%s\n' "$prior_state"
    printf 'open_prepare_receipt_sha256=%s\n' "$prepare_sha"
    printf 'preopen_edge_evidence_sha256=%s\n' "$edge_sha"
    printf 'route_down_sha256=%s\n' "$route_down_sha"
    printf 'route_down_execution_evidence_sha256=%s\n' "$route_down_execution_evidence_sha"
    printf 'route_state=absent\n'
    printf 'public_host=rikune.w33d.xyz\n'
    printf 'legacy_public_host=analyze.w33d.xyz\n'
    printf 'legacy_route_state=absent\n'
    printf 'legacy_public_ipv4_ipv6_closed_status=404\n'
    printf 'edge_owner=existing-w33d-sluice\n'
    printf 'db_public_db_bracket=absent-404-absent\n'
    printf 'external_edge_mutation=none\n'
  } >"$temporary"; then
    echo "holdfast: could not write interrupted receipt" >&2
    return 1
  fi
  if [[ ! -f "$temporary" || -L "$temporary" ]]; then
    echo "holdfast: interrupted receipt temporary is not a regular non-symlink file" >&2
    return 1
  fi
  if ! chmod 0600 -- "$temporary"; then
    echo "holdfast: could not protect interrupted receipt" >&2
    return 1
  fi
  if ! mv -fT -- "$temporary" "$target"; then
    echo "holdfast: could not atomically persist interrupted receipt" >&2
    return 1
  fi
  if [[ ! -f "$target" || -L "$target" ]]; then
    echo "holdfast: interrupted receipt is not a regular non-symlink file" >&2
    return 1
  fi
  if ! receipt_sha=$(holdfast_sha256 "$target"); then
    echo "holdfast: could not hash interrupted receipt" >&2
    return 1
  fi
  if [[ ! "$receipt_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: interrupted receipt hash is not lowercase SHA-256" >&2
    return 1
  fi
  interrupted_receipt_sha=$receipt_sha
  return 0
}

record_interrupted_state() {
  local target_state=$1
  local receipt_sha=$2
  local interrupted_state_tmp="$state_dir/.CURRENT.interrupted.$$"
  local state_sha
  if [[ ! "$receipt_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: interrupted state receipt hash is not lowercase SHA-256" >&2
    return 1
  fi
  if [[ -e "$interrupted_state_tmp" || -L "$interrupted_state_tmp" ]]; then
    echo "holdfast: unsafe interrupted state temporary path" >&2
    return 1
  fi
  if ! jq --arg state "$target_state" --arg receipt_sha "$receipt_sha" '
    .state=$state
    | .last_open_interrupted_receipt_sha256=$receipt_sha
    | del(
        .open_receipt_sha256,
        .open_armed_at,
        .open_armed_prepare_receipt_sha256,
        .open_armed_edge_evidence_sha256,
        .open_armed_route_up_sha256,
        .open_armed_route_down_sha256,
        .open_armed_public_host,
        .open_armed_legacy_public_host,
        .open_armed_edge_owner
      )
  ' "$state_file" >"$interrupted_state_tmp"; then
    echo "holdfast: could not render interrupted state" >&2
    return 1
  fi
  if [[ ! -f "$interrupted_state_tmp" || -L "$interrupted_state_tmp" ]]; then
    echo "holdfast: interrupted state temporary is not a regular non-symlink file" >&2
    return 1
  fi
  if ! chmod 0600 -- "$interrupted_state_tmp"; then
    echo "holdfast: could not protect interrupted state" >&2
    return 1
  fi
  if ! state_sha=$(holdfast_sha256 "$interrupted_state_tmp"); then
    echo "holdfast: could not hash interrupted state" >&2
    return 1
  fi
  if [[ ! "$state_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: interrupted state hash is not lowercase SHA-256" >&2
    return 1
  fi
  if ! mv -fT -- "$interrupted_state_tmp" "$state_file"; then
    echo "holdfast: could not atomically persist interrupted state" >&2
    return 1
  fi
  return 0
}

mark_compensation_unverified() {
  local delete_status=$1
  local initial_db_status=$2
  local public_status=$3
  local final_db_status=$4
  local target temporary state_tmp receipt_sha state_sha current_state
  target="$state_dir/OPEN-COMPENSATION-UNVERIFIED-$(date -u +%Y%m%dT%H%M%SZ)-$$.receipt"
  temporary="$state_dir/.OPEN-COMPENSATION-UNVERIFIED.$$"
  if [[ -e "$temporary" || -L "$temporary" ]]; then
    echo "holdfast: unsafe compensation-unverified receipt temporary path" >&2
    return 1
  fi
  if ! {
    printf 'failed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'route_delete_status=%s\n' "$delete_status"
    printf 'route_down_execution_evidence_sha256=%s\n' "${route_down_execution_evidence_sha:-unavailable}"
    printf 'initial_database_absent_status=%s\n' "$initial_db_status"
    printf 'public_closed_status=%s\n' "$public_status"
    printf 'final_database_absent_status=%s\n' "$final_db_status"
    printf 'public_host=rikune.w33d.xyz\n'
    printf 'legacy_public_host=analyze.w33d.xyz\n'
    printf 'required_manual_state=route-absent-dual-stack-404\n'
  } >"$temporary"; then
    echo "holdfast: could not write compensation-unverified receipt" >&2
    return 1
  fi
  if [[ ! -f "$temporary" || -L "$temporary" ]]; then
    echo "holdfast: compensation-unverified receipt temporary is not a regular non-symlink file" >&2
    return 1
  fi
  if ! chmod 0600 -- "$temporary"; then
    echo "holdfast: could not protect compensation-unverified receipt" >&2
    return 1
  fi
  if ! mv -fT -- "$temporary" "$target"; then
    echo "holdfast: could not atomically persist compensation-unverified receipt" >&2
    return 1
  fi
  if [[ ! -f "$target" || -L "$target" ]]; then
    echo "holdfast: compensation-unverified receipt is not a regular non-symlink file" >&2
    return 1
  fi
  if ! receipt_sha=$(holdfast_sha256 "$target"); then
    echo "holdfast: could not hash compensation-unverified receipt" >&2
    return 1
  fi
  if [[ ! "$receipt_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: compensation-unverified receipt hash is not lowercase SHA-256" >&2
    return 1
  fi
  if ! current_state=$(jq -er '.state' "$state_file"); then
    echo "holdfast: could not read armed state before marking compensation unverified" >&2
    return 1
  fi
  if [[ "$current_state" != "finalizing_route_armed" ]]; then
    echo "holdfast: refusing to replace non-armed state while marking compensation unverified" >&2
    return 1
  fi
  state_tmp="$state_dir/.CURRENT.compensation-unverified.$$"
  if [[ -e "$state_tmp" || -L "$state_tmp" ]]; then
    echo "holdfast: unsafe compensation-unverified state temporary path" >&2
    return 1
  fi
  if ! jq --arg receipt_sha "$receipt_sha" '
    .state="ingress_compensation_unverified"
    | .compensation_unverified_receipt_sha256=$receipt_sha
  ' "$state_file" >"$state_tmp"; then
    echo "holdfast: could not render compensation-unverified state" >&2
    return 1
  fi
  if [[ ! -f "$state_tmp" || -L "$state_tmp" ]]; then
    echo "holdfast: compensation-unverified state temporary is not a regular non-symlink file" >&2
    return 1
  fi
  if ! chmod 0600 -- "$state_tmp"; then
    echo "holdfast: could not protect compensation-unverified state" >&2
    return 1
  fi
  if ! state_sha=$(holdfast_sha256 "$state_tmp"); then
    echo "holdfast: could not hash compensation-unverified state" >&2
    return 1
  fi
  if [[ ! "$state_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "holdfast: compensation-unverified state hash is not lowercase SHA-256" >&2
    return 1
  fi
  if ! mv -fT -- "$state_tmp" "$state_file"; then
    echo "holdfast: could not atomically persist compensation-unverified state" >&2
    return 1
  fi
  return 0
}

validate_armed_open_contract() {
  local backup frozen_release frozen_policy policy_schema expected_route_up
  local expected_route_down frozen_route_up frozen_route_down
  local -a validator_args
  backup=$(jq -er '.backup_dir' "$state_file")
  holdfast_require_absolute "$backup"
  require_private_root_directory "$backup" "armed open release authority directory"
  frozen_release="$backup/RELEASE-EVIDENCE.json"
  require_private_root_file "$frozen_release" "armed open frozen release evidence"
  require_private_root_file "$backup/CONTROL.sha256" "armed open frozen CONTROL"
  [[ "$(jq -er '.release_evidence_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$frozen_release")" && \
    "$(jq -er '.control_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$backup/CONTROL.sha256")" ]] || \
    holdfast_die "armed open state differs from its frozen release authority"
  (cd "$backup" && sha256sum --check CONTROL.sha256 >/dev/null) || \
    holdfast_die "armed open frozen CONTROL authority does not verify"

  validator_args=(--evidence "$frozen_release")
  policy_schema=0
  if jq -e '.schema_version == 2 and .release_mode == "successor"' \
    "$frozen_release" >/dev/null; then
    frozen_policy="$backup/successor-authority/successor-policy.json"
    require_private_root_file "$frozen_policy" "armed open frozen successor policy"
    validator_args+=(--successor-policy "$frozen_policy")
    policy_schema=$(jq -er '
      .schema_version |
      select(type == "number" and floor == . and . >= 1 and . <= 5)
    ' "$frozen_policy") || holdfast_die "armed open frozen policy schema is invalid"
  fi
  python3 "$script_dir/validate_release_evidence.py" "${validator_args[@]}" \
    >/dev/null || holdfast_die "armed open frozen release evidence is invalid"

  expected_route_up=$(jq -er '
    .route_up_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))
  ' "$frozen_release") || holdfast_die "armed open route-up authority is invalid"
  expected_route_down=$(jq -er '
    .route_down_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))
  ' "$frozen_release") || holdfast_die "armed open route-down authority is invalid"
  [[ "$(jq -er '.open_armed_route_up_sha256' "$state_file")" == \
      "$expected_route_up" && \
    "$(jq -er '.open_armed_route_down_sha256' "$state_file")" == \
      "$expected_route_down" ]] || \
    holdfast_die "armed open route authority differs from its frozen release"

  if [[ "$policy_schema" -ge 3 ]]; then
    frozen_route_up="$backup/successor-authority/assets/20260823_rikune_root_up.sql"
    frozen_route_down="$backup/successor-authority/assets/20260823_rikune_root_down.sql"
    require_private_root_file "$frozen_route_up" "armed open frozen route-up SQL"
    require_private_root_file "$frozen_route_down" "armed open frozen route-down SQL"
    [[ "$(holdfast_sha256 "$frozen_route_up")" == "$expected_route_up" && \
      "$(holdfast_sha256 "$frozen_route_down")" == "$expected_route_down" ]] || \
      holdfast_die "armed open frozen route assets differ from release evidence"
  fi

  if [[ "$policy_schema" -ge 4 ]]; then
    jq -e '
      .open_armed_public_host == "rikune.w33d.xyz" and
      .open_armed_legacy_public_host == "analyze.w33d.xyz"
    ' "$state_file" >/dev/null || \
      holdfast_die "dual-host armed open host namespace differs"
  else
    jq -e '
      .open_armed_public_host == "analyze.w33d.xyz" and
      (has("open_armed_legacy_public_host") | not)
    ' "$state_file" >/dev/null || \
      holdfast_die "legacy armed open host namespace differs"
  fi
}

recover_armed_open() {
  local armed_prepare_sha armed_edge_sha
  echo "armed open state detected; closing the route before reading armed metadata" >&2
  force_route_absent
  verify_closed_bracket
  armed_prepare_sha=$(jq -er '.open_armed_prepare_receipt_sha256' "$state_file")
  armed_edge_sha=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  [[ "$armed_prepare_sha" =~ ^[0-9a-f]{64}$ && "$armed_edge_sha" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "armed open state contains invalid evidence hashes"
  [[ -f "$prepare_receipt" && ! -L "$prepare_receipt" ]] || \
    holdfast_die "armed open recovery cannot find the prepare receipt"
  [[ "$armed_prepare_sha" == "$(holdfast_sha256 "$prepare_receipt")" ]] || \
    holdfast_die "armed open prepare receipt was replaced"
  [[ "$(jq -er '.open_prepare_receipt_sha256' "$state_file")" == "$armed_prepare_sha" ]] || \
    holdfast_die "armed open state points to another prepare receipt"
  validate_armed_open_contract
  [[ "$(jq -er '.open_armed_edge_owner' "$state_file")" == "existing-w33d-sluice" ]] || \
    holdfast_die "armed open state targets another edge"

  archive_failed_open_receipt
  write_interrupted_receipt "armed-open-recovery" "finalizing_route_armed"
  record_interrupted_state "edge_prepared_route_closed" "$interrupted_receipt_sha"
  holdfast_die "armed open was compensated to prepared dual-stack 404 state; invocation refused, rerun finalize"
}

current_state=$(jq -er '.state' "$state_file")
if [[ "$current_state" == "finalizing_route_armed" ]]; then
  recover_armed_open
fi
if [[ "$current_state" == "ingress_compensation_unverified" ]]; then
  holdfast_die "ingress compensation is unverified; finalize is prohibited pending manual route closure"
fi
if [[ "$current_state" == "applied_ingress_closed" || "$current_state" == "edge_prepared_route_closed" ]]; then
  if ! verify_database_absent; then
    prior_closed_state=$current_state
    force_route_absent
    verify_closed_bracket
    write_interrupted_receipt "closed-state-route-present" "$prior_closed_state"
    record_interrupted_state "$prior_closed_state" "$interrupted_receipt_sha"
    holdfast_die "unexpected route in closed state was removed and recorded; invocation refused"
  fi
fi

release_validator_args=(--evidence "$release_evidence")
edge_policy_args=()
open_edge_contract="legacy-analyze-v2"
if jq -e '.schema_version == 2 and .release_mode == "successor"' \
  "$release_evidence" >/dev/null; then
  active_backup=$(jq -er '.backup_dir' "$state_file")
  holdfast_require_absolute "$active_backup"
  frozen_successor_policy="$active_backup/successor-authority/successor-policy.json"
  require_private_root_file "$frozen_successor_policy" "frozen successor policy"
  require_private_root_file "$active_backup/RELEASE-EVIDENCE.json" \
    "frozen successor release evidence"
  [[ "$(holdfast_sha256 "$active_backup/RELEASE-EVIDENCE.json")" == \
      "$(holdfast_sha256 "$release_evidence")" ]] || \
    holdfast_die "open release evidence differs from the frozen successor release"
  frozen_policy_schema=$(jq -er \
    '.schema_version | select(type == "number" and floor == . and . >= 1 and . <= 5)' \
    "$frozen_successor_policy") || holdfast_die "frozen successor policy schema is invalid"
  if [[ "$frozen_policy_schema" -ge 4 ]]; then
    open_edge_contract="rikune-dual-v3"
  fi
  release_validator_args+=(--successor-policy "$frozen_successor_policy")
  edge_policy_args+=(--successor-policy "$frozen_successor_policy")
fi
python3 "$script_dir/validate_release_evidence.py" "${release_validator_args[@]}"
[[ "$(holdfast_sha256 "$release_env")" == "$(jq -er '.release_env_sha256' "$release_evidence")" ]] || \
  holdfast_die "release env identity differs"
python3 "$script_dir/authority_evidence.py" --mode open \
  --evidence "$authority_evidence" --signature "$authority_signature" \
  --public-key "$authority_public_key" --release-env "$release_env" \
  --release-evidence "$release_evidence" --dry-run-receipt "$dry_receipt"
"$script_dir/runtime-verify.sh" --estate-root "$estate_root" --release-env "$release_env" \
  --release-evidence "$release_evidence"
(cd "$estate_root" && sha256sum --check "$stage/TARGETS.sha256")

current_state=$(jq -er '.state' "$state_file")
if [[ "$phase" == "prepare" ]]; then
  [[ "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "open prepare refuses state $current_state (re-open/race blocked)"
  [[ ! -e "$prepare_receipt" && ! -L "$prepare_receipt" && ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
    holdfast_die "open ceremony receipt already exists"
  verify_closed_bracket
  receipt_tmp="$state_dir/.OPEN-PREPARE.receipt.$$"
  active_release_generation=$(jq -er '
    (.release_generation // 1) |
    select(type == "number" and floor == . and . >= 1)
  ' "$state_file") || holdfast_die "active release generation is invalid"
  if [[ "$open_edge_contract" == "rikune-dual-v3" ]]; then
    expected_release_generation=$((frozen_policy_schema + 1))
    [[ "$active_release_generation" == "$expected_release_generation" ]] || \
      holdfast_die "dual-host open release generation differs from frozen policy"
    {
      printf 'schema_version=3\n'
      printf 'prepared_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'release_generation=%s\n' "$active_release_generation"
      printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$release_evidence")"
      printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$authority_evidence")"
      printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$authority_evidence")"
      printf 'route_state=absent\n'
      printf 'public_host=rikune.w33d.xyz\n'
      printf 'legacy_public_host=analyze.w33d.xyz\n'
      printf 'legacy_route_state=absent\n'
      printf 'legacy_public_ipv4_ipv6_closed_status=404\n'
      printf 'edge_owner=existing-w33d-sluice\n'
      printf 'public_ipv4_ipv6_closed_status=404\n'
      printf 'db_public_db_bracket=absent-404-absent\n'
      printf 'external_edge_mutation=none\n'
    } >"$receipt_tmp"
  else
    {
      printf 'prepared_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$release_evidence")"
      printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$authority_evidence")"
      printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$authority_evidence")"
      printf 'route_state=absent\n'
      printf 'public_host=analyze.w33d.xyz\n'
      printf 'edge_owner=existing-w33d-sluice\n'
      printf 'public_ipv4_ipv6_closed_status=404\n'
      printf 'db_public_db_bracket=absent-404-absent\n'
      printf 'external_edge_mutation=none\n'
    } >"$receipt_tmp"
  fi
  chmod 0600 "$receipt_tmp"
  mv -fT -- "$receipt_tmp" "$prepare_receipt"
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg prepare_sha "$(holdfast_sha256 "$prepare_receipt")" \
    '.state="edge_prepared_route_closed" | .open_prepare_receipt_sha256=$prepare_sha' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  echo "runtime/authority prepared in $open_edge_contract closed state; collect and sign the matching edge evidence"
  exit 0
fi

[[ -n "$edge_evidence" && -n "$edge_signature" ]] || usage
[[ "$current_state" == "edge_prepared_route_closed" ]] || \
  holdfast_die "open finalize refuses state $current_state (re-open/race blocked)"
[[ -f "$prepare_receipt" && ! -L "$prepare_receipt" && ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
  holdfast_die "open prepare receipt is absent or final receipt already exists"
[[ "$(jq -er '.open_prepare_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$prepare_receipt")" ]] || \
  holdfast_die "open prepare receipt was replaced"
for path in "$edge_evidence" "$edge_signature"; do holdfast_require_absolute "$path"; done
python3 "$script_dir/edge_evidence.py" --mode preopen \
  --evidence "$edge_evidence" --signature "$edge_signature" --public-key "$authority_public_key" \
  --release-env "$release_env" --release-evidence "$release_evidence" \
  "${edge_policy_args[@]}" \
  --open-evidence "$authority_evidence" --prepare-receipt "$prepare_receipt"

"$script_dir/runtime-verify.sh" --estate-root "$estate_root" --release-env "$release_env" \
  --release-evidence "$release_evidence"
verify_closed_bracket
expected_route_up=$(jq -er '.route_up_sha256' "$release_evidence")
[[ "$expected_route_up" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_up.sql")" ]] || \
  holdfast_die "route-up SQL differs from release evidence"
expected_route_down=$(jq -er '.route_down_sha256' "$release_evidence")
[[ "$expected_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
  holdfast_die "route-down SQL differs from release evidence"

route_mutation_started="false"
receipt_tmp="$state_dir/.OPEN.receipt.$$"
state_tmp="$state_dir/.CURRENT.json.$$"

compensate_finalize() {
  local original_status=$1
  local state_now delete_status initial_db_status public_status final_db_status
  local archive_status interrupted_receipt_status state_restore_status unverified_status retained_state
  trap - EXIT INT TERM
  if [[ $original_status -eq 0 ]]; then original_status=1; fi
  state_now=$(jq -er '.state' "$state_file" 2>/dev/null || true)
  if [[ "$route_mutation_started" != "true" && "$state_now" != "finalizing_route_armed" ]]; then
    rm -f -- "$receipt_tmp" "$state_tmp"
    exit "$original_status"
  fi

  set +e
  echo "open finalize failed after the ceremony was armed; compensating to route-absent state" >&2
  if force_route_absent; then delete_status=0; else delete_status=$?; fi
  if verify_database_absent; then initial_db_status=0; else initial_db_status=$?; fi
  if verify_public_closed; then
    public_status=0
  else
    public_status=$?
  fi
  if verify_database_absent; then final_db_status=0; else final_db_status=$?; fi
  archive_status=1
  interrupted_receipt_status=1
  state_restore_status=1
  if [[ $delete_status -eq 0 && $initial_db_status -eq 0 && $public_status -eq 0 && $final_db_status -eq 0 ]]; then
    if archive_failed_open_receipt; then archive_status=0; else archive_status=$?; fi
    if [[ $archive_status -eq 0 ]]; then
      if write_interrupted_receipt "finalize-error-compensated" "$state_now"; then
        interrupted_receipt_status=0
      else
        interrupted_receipt_status=$?
      fi
      if [[ $interrupted_receipt_status -eq 0 ]]; then
        if record_interrupted_state "edge_prepared_route_closed" "$interrupted_receipt_sha"; then
          state_restore_status=0
        else
          state_restore_status=$?
        fi
      fi
    fi
  fi
  if [[ $delete_status -eq 0 && $initial_db_status -eq 0 && $public_status -eq 0 && $final_db_status -eq 0 && $archive_status -eq 0 && $interrupted_receipt_status -eq 0 && $state_restore_status -eq 0 ]]; then
    echo "open finalize compensation verified dual-stack 404 and restored prepared closed state" >&2
  else
    if mark_compensation_unverified "$delete_status" "$initial_db_status" "$public_status" "$final_db_status"; then
      unverified_status=0
      echo "CRITICAL: open finalize compensation was incomplete; ingress_compensation_unverified was persisted" >&2
    else
      unverified_status=$?
      retained_state=$(jq -er '.state' "$state_file" 2>/dev/null || true)
      if [[ "$retained_state" == "finalizing_route_armed" ]]; then
        echo "CRITICAL: compensation and unverified-state persistence failed with status $unverified_status; finalizing_route_armed was retained" >&2
      else
        echo "CRITICAL: compensation and unverified-state persistence failed with status $unverified_status; armed state cannot be proven retained" >&2
      fi
    fi
  fi
  rm -f -- "$receipt_tmp" "$state_tmp"
  exit "$original_status"
}
trap 'compensate_finalize "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Persist the recovery intent before the final route insertion. SIGKILL leaves this state durable.
armed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq \
  --arg armed_at "$armed_at" \
  --arg prepare_sha "$(holdfast_sha256 "$prepare_receipt")" \
  --arg edge_sha "$(holdfast_sha256 "$edge_evidence")" \
  --arg route_up_sha "$expected_route_up" \
  --arg route_down_sha "$expected_route_down" \
  '
    .state="finalizing_route_armed"
    | .open_armed_at=$armed_at
    | .open_armed_prepare_receipt_sha256=$prepare_sha
    | .open_armed_edge_evidence_sha256=$edge_sha
    | .open_armed_route_up_sha256=$route_up_sha
    | .open_armed_route_down_sha256=$route_down_sha
    | .open_armed_public_host="rikune.w33d.xyz"
    | .open_armed_legacy_public_host="analyze.w33d.xyz"
    | .open_armed_edge_owner="existing-w33d-sluice"
  ' "$state_file" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_file"
route_mutation_started="true"

# This is deliberately the last external exposure mutation. Every later failure compensates down.
PGAPPNAME=holdfast-rikune-open-finalize psql "$ROUTES_DATABASE_URL" -X \
  -f "$script_dir/assets/20260823_rikune_root_up.sql"
verify_open_bracket

{
  printf 'opened_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'armed_at=%s\n' "$armed_at"
  printf 'open_prepare_receipt_sha256=%s\n' "$(holdfast_sha256 "$prepare_receipt")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$authority_evidence")"
  printf 'edge_evidence_sha256=%s\n' "$(holdfast_sha256 "$edge_evidence")"
  printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$authority_evidence")"
  printf 'public_host=rikune.w33d.xyz\n'
  printf 'legacy_public_host=analyze.w33d.xyz\n'
  printf 'legacy_route_state=absent\n'
  printf 'legacy_public_ipv4_ipv6_closed_status=404\n'
  printf 'edge_owner=existing-w33d-sluice\n'
  printf 'route_state=present\n'
  printf 'public_ipv4_ipv6_origin=sluice-strad\n'
  printf 'cache_policy=private,no-store\n'
  printf 'external_edge_mutation=none\n'
} >"$receipt_tmp"
chmod 0600 "$receipt_tmp"
mv -fT -- "$receipt_tmp" "$open_receipt"
jq --arg open_sha "$(holdfast_sha256 "$open_receipt")" '
  .state="ingress_open"
  | .open_receipt_sha256=$open_sha
  | del(
      .open_armed_at,
      .open_armed_prepare_receipt_sha256,
      .open_armed_edge_evidence_sha256,
      .open_armed_route_up_sha256,
      .open_armed_route_down_sha256,
      .open_armed_public_host,
      .open_armed_legacy_public_host,
      .open_armed_edge_owner
    )
' "$state_file" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_file"
route_mutation_started="false"
trap - EXIT INT TERM
echo "rikune-root public ingress finalized on rikune.w33d.xyz while analyze.w33d.xyz remains an exact-404 tombstone; no Pages, Cloudflare, or DNS mutation was performed"
