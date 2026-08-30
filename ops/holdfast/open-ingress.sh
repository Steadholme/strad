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

validate_stale_prepare_receipt() {
  local path=$1 keys receipt_generation prepared_at
  require_private_root_file "$path" "stale open prepare receipt"
  keys=$(receipt_key_set "$path") || holdfast_die "stale open prepare receipt is malformed"
  if [[ "$keys" == $'db_public_db_bracket\nedge_owner\nexternal_edge_mutation\nopen_evidence_sha256\nprepared_at\npublic_host\npublic_ipv4_ipv6_closed_status\nrelease_evidence_sha256\nroute_state\nsource_grant_id' ]]; then
    source_prepare_schema="legacy-analyze-v2"
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
    [[ "$receipt_generation" == "$predecessor_release_generation" ]] || \
      holdfast_die "stale rikune prepare receipt generation is not the immediate predecessor"
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

render_prepare_supersede_receipt() {
  local abandoned_at=$1 output=$2
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
  [[ "$keys" == $'abandoned_at\narchive_name\narchive_sha256\nauthority_binding\nceremony\npredecessor_apply_receipt_sha256\npredecessor_control_sha256\npredecessor_current_sha256\npredecessor_release_generation\nreason_file_sha256\nschema_version\nsource_grant_id\nsource_open_evidence_sha256\nsource_prepare_receipt_sha256\nsource_prepare_schema\nsource_public_host\nsource_release_evidence_sha256\nsuccessor_apply_receipt_sha256\nsuccessor_armed_receipt_sha256\nsuccessor_control_sha256\nsuccessor_current_sha256\nsuccessor_policy_sha256\nsuccessor_release_evidence_sha256\nsuccessor_release_generation' ]] || \
    holdfast_die "open prepare supersede receipt field set is not exact"
  abandoned_at=$(holdfast_receipt_value "$path" abandoned_at)
  [[ "$abandoned_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "open prepare supersede receipt timestamp is invalid"
  render_prepare_supersede_receipt "$abandoned_at" "$expected"
  cmp -s -- "$path" "$expected" || \
    holdfast_die "open prepare supersede receipt differs from the exact successor authority"
  rm -f -- "$expected"
}

load_successor_abandon_authority() {
  local backup predecessor_backup current_release predecessor_release expected key value
  local policy arm_keys successor_estate_root armed_at
  require_private_root_file "$state_file" "active apply state"
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
    "$state_dir"/OPEN-PREPARE-ABANDONED-G"$predecessor_release_generation"-BY-G"$successor_release_generation"-*.receipt
  )
  pending_candidates=(
    "$state_dir"/.OPEN-PREPARE-ABANDONED-G"$predecessor_release_generation"-BY-G"$successor_release_generation"-*.pending
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
      replay_archive="$state_dir/$archive_name"
      pending_archive="$state_dir/.${archive_name}.pending"
      [[ "$archive_name" == "OPEN-PREPARE-ABANDONED-G${predecessor_release_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt" ]] || \
        holdfast_die "persisted prepare archive name differs from successor lineage"
      reject_conflicting_prepare_archives "$replay_archive" "$pending_archive"
      validate_stale_prepare_receipt "$replay_archive"
      [[ "$(holdfast_sha256 "$replay_archive")" == "$source_prepare_sha" && \
        "$source_release_evidence_sha" == "$predecessor_release_evidence_sha" ]] || \
        holdfast_die "persisted prepare archive differs from predecessor release authority"
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
    replay_archive="$state_dir/$archive_name"
    pending_archive="$state_dir/.${archive_name}.pending"
    [[ "$archive_name" == "OPEN-PREPARE-ABANDONED-G${predecessor_release_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt" ]] || \
      holdfast_die "pending prepare archive name differs from successor lineage"
    reject_conflicting_prepare_archives "$replay_archive" "$pending_archive"
    validate_stale_prepare_receipt "$replay_archive"
    [[ "$(holdfast_sha256 "$replay_archive")" == "$source_prepare_sha" && \
      "$source_release_evidence_sha" == "$predecessor_release_evidence_sha" ]] || \
      holdfast_die "recoverable prepare archive differs from predecessor release authority"
    validate_prepare_supersede_receipt "$pending_receipt" "$check_file"
    [[ ! -e "$pending_archive" && ! -L "$pending_archive" ]] || \
      holdfast_die "recoverable prepare abandonment retains a hybrid pending archive"
    [[ ! -e "$supersede_receipt" && ! -L "$supersede_receipt" ]] || \
      holdfast_die "prepare abandonment contains hybrid final and pending receipts"
    recheck_successor_abandon_authority
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
  [[ "$source_release_evidence_sha" == "$predecessor_release_evidence_sha" && \
    "$source_release_evidence_sha" != "$successor_release_evidence_sha" ]] || \
    holdfast_die "stale OPEN-PREPARE does not bind the immediate predecessor release"
  source_prepare_sha=$(holdfast_sha256 "$prepare_receipt")
  archive_name="OPEN-PREPARE-ABANDONED-G${predecessor_release_generation}-BY-G${successor_release_generation}-${source_prepare_sha}.receipt"
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
  recheck_successor_abandon_authority
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
  recheck_successor_abandon_authority
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
      select(type == "number" and floor == . and . >= 1 and . <= 4)
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

  if [[ "$policy_schema" == "4" ]]; then
    jq -e '
      .open_armed_public_host == "rikune.w33d.xyz" and
      .open_armed_legacy_public_host == "analyze.w33d.xyz"
    ' "$state_file" >/dev/null || \
      holdfast_die "schema-v4 armed open host namespace differs"
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
    '.schema_version | select(type == "number" and floor == . and . >= 1 and . <= 4)' \
    "$frozen_successor_policy") || holdfast_die "frozen successor policy schema is invalid"
  if [[ "$frozen_policy_schema" == "4" ]]; then
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
    [[ "$active_release_generation" == "5" ]] || \
      holdfast_die "schema-v4 dual-host open requires release generation 5"
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
