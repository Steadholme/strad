#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --mode restore|resume --backup-dir PATH [--estate-root PATH] [--state-dir PATH] [--legacy-empty-strad] [--quarantine-access-chain]" >&2
  echo "       $0 --verify-completed --mode resume --backup-dir PATH --release-root PATH --signing-key PATH --authority-public-key PATH [--estate-root PATH] [--state-dir PATH]" >&2
  echo "       --verify-completed v1 supports only current-production successor generation 2 -> 3, direct apply_activation_failed -> first resume completion; base, other lineage, and recovery retries are unsupported" >&2
  exit 2
}

execute="false"
verify_completed="false"
mode=""
backup=""
estate_root=""
state_dir="/var/lib/holdfast-rikune"
release_root=""
signing_key=""
authority_public_key=""
legacy_empty_strad="false"
quarantine_access_chain="false"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --verify-completed) verify_completed="true"; shift ;;
    --mode) [[ $# -ge 2 ]] || usage; mode=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    --release-root) [[ $# -ge 2 ]] || usage; release_root=$2; shift 2 ;;
    --signing-key) [[ $# -ge 2 ]] || usage; signing_key=$2; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; shift 2 ;;
    --legacy-empty-strad) legacy_empty_strad="true"; shift ;;
    --quarantine-access-chain) quarantine_access_chain="true"; shift ;;
    *) usage ;;
  esac
done
if [[ "$verify_completed" == "true" ]]; then
  [[ "$execute" == "false" && "$mode" == "resume" && -n "$backup" && \
    -n "$release_root" && -n "$signing_key" && -n "$authority_public_key" && \
    "$legacy_empty_strad" == "false" && "$quarantine_access_chain" == "false" ]] || usage
else
  [[ "$execute" == "true" && ( "$mode" == "restore" || "$mode" == "resume" ) && \
    -n "$backup" && -z "$release_root" && -z "$signing_key" && \
    -z "$authority_public_key" ]] || usage
fi
if [[ "$legacy_empty_strad" == "true" && "$mode" != "restore" ]]; then usage; fi
if [[ "$quarantine_access_chain" == "true" && "$mode" != "restore" ]]; then usage; fi
[[ $EUID -eq 0 ]] || { echo "apply recovery requires root" >&2; exit 1; }
[[ -n "${ROUTES_DATABASE_URL:-}" ]] || { echo "ROUTES_DATABASE_URL is required to prove closed ingress" >&2; exit 1; }

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
holdfast_require_absolute "$backup"
holdfast_require_absolute "$state_dir"
if [[ -n "$estate_root" ]]; then holdfast_require_absolute "$estate_root"; fi
if [[ "$verify_completed" == "true" ]]; then
  holdfast_require_absolute "$release_root"
  holdfast_require_absolute "$signing_key"
  holdfast_require_absolute "$authority_public_key"
fi
holdfast_acquire_lock

require_canonical_root_dir() {
  local path=$1
  [[ -d "$path" && ! -L "$path" && "$(readlink -f -- "$path")" == "$path" ]] || \
    holdfast_die "directory must be canonical and non-symlink: $path"
  [[ "$(stat -c '%u' -- "$path")" == "0" ]] || holdfast_die "directory must be root-owned: $path"
}

require_root_file() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || holdfast_die "required file is unsafe or absent: $path"
  [[ "$(stat -c '%u:%h' -- "$path")" == "0:1" ]] || \
    holdfast_die "required file must be root-owned with one link: $path"
}

resolve_verify_completed_helper() {
  local value=$1 label=$2 resolved
  if [[ "$value" == */* ]]; then
    resolved=$value
  else
    resolved=$(command -v -- "$value") || \
      holdfast_die "completed recovery $label helper is not executable: $value"
  fi
  resolved=$(readlink -f -- "$resolved") || \
    holdfast_die "completed recovery $label helper path is not canonical: $value"
  [[ "$resolved" == /* ]] || \
    holdfast_die "completed recovery $label helper path is not absolute: $value"
  require_root_file "$resolved"
  printf '%s\n' "$resolved"
}

snapshot_verify_completed_helper() {
  local path=$1 label=$2 metadata digest
  require_root_file "$path"
  metadata=$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- "$path") || \
    holdfast_die "could not inspect completed recovery $label helper: $path"
  digest=$(holdfast_sha256 "$path") || \
    holdfast_die "could not hash completed recovery $label helper: $path"
  printf '%s\t%s\n' "$metadata" "$digest"
}

validate_verify_completed_helper() {
  local path=$1 expected=$2 label=$3 observed
  observed=$(snapshot_verify_completed_helper "$path" "$label")
  [[ "$observed" == "$expected" ]] || \
    holdfast_die "completed recovery $label helper changed from its initial fence"
}

require_single_device_tree() {
  local root=$1 label=$2 root_device path
  root_device=$(stat -c '%d' -- "$root")
  while IFS= read -r -d '' path; do
    [[ "$(stat -c '%d' -- "$path")" == "$root_device" ]] || \
      holdfast_die "$label contains a cross-device subtree: $path"
  done < <(find -P "$root" -xdev -mindepth 1 -print0)
}

test_override() {
  local variable=$1
  local fallback=$2
  local value=${!variable:-}
  if [[ -n "$value" ]]; then
    [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "$variable override is test-only"
    printf '%s\n' "$value"
  else
    printf '%s\n' "$fallback"
  fi
}

run_python_tool() {
  local tool=$1 default=$2
  shift 2
  if [[ "$verify_completed" == "true" && \
    -n "${completion_attestation_helper_fence:-}" && \
    "$tool" == "${completion_attestation_tool:-}" ]]; then
    validate_verify_completed_helper \
      "$completion_attestation_tool" "$completion_attestation_helper_fence" \
      "completion attestation"
  fi
  if [[ "$tool" == "$default" ]]; then
    python3 "$tool" "$@"
  else
    "$tool" "$@"
  fi
}

completion_attestation_tool=$(test_override \
  HOLDFAST_RECOVERY_COMPLETION_ATTESTATION_BIN \
  "$script_dir/recovery_completion_attestation.py")
completion_attestation_helper_fence=""
if [[ "$verify_completed" == "true" ]]; then
  completion_attestation_tool=$(resolve_verify_completed_helper \
    "$completion_attestation_tool" "completion attestation")
  completion_attestation_helper_fence=$(snapshot_verify_completed_helper \
    "$completion_attestation_tool" "completion attestation")
fi

verify_completed_json_structure() {
  run_python_tool "$completion_attestation_tool" \
    "$script_dir/recovery_completion_attestation.py" structure \
    --json-file "$1" >/dev/null
  validate_v3_completed_terminal_candidate_namespace
}

verify_completed_receipt_structure() {
  run_python_tool "$completion_attestation_tool" \
    "$script_dir/recovery_completion_attestation.py" structure \
    --receipt-file "$1" >/dev/null
  validate_v3_completed_terminal_candidate_namespace
}

verify_completed_historical_apply_armed_structure() {
  run_python_tool "$completion_attestation_tool" \
    "$script_dir/recovery_completion_attestation.py" structure \
    --historical-apply-armed-file "$1" >/dev/null
  validate_v3_completed_terminal_candidate_namespace
}

verify_completed_exact_receipt_schema() {
  local path=$1 label=$2 index=0 key
  local -a actual_keys=()
  shift 2
  verify_completed_receipt_structure "$path"
  mapfile -t actual_keys < <(cut -d= -f1 -- "$path")
  ((${#actual_keys[@]} == $#)) || \
    holdfast_die "completed recovery attestation $label field set is not exact"
  for key in "$@"; do
    [[ "${actual_keys[$index]}" == "$key" ]] || \
      holdfast_die "completed recovery attestation $label field set is not exact"
    index=$((index + 1))
  done
}

verify_completed_exact_json_schema() {
  local path=$1 label=$2 key
  local -a actual_keys=()
  local -A expected_keys=()
  shift 2
  verify_completed_json_structure "$path"
  for key in "$@"; do expected_keys[$key]=1; done
  mapfile -t actual_keys < <(jq -r 'keys_unsorted[]' "$path")
  ((${#actual_keys[@]} == ${#expected_keys[@]})) || \
    holdfast_die "completed recovery attestation $label field set is not exact"
  for key in "${actual_keys[@]}"; do
    [[ -n "${expected_keys[$key]+x}" ]] || \
      holdfast_die "completed recovery attestation $label field set is not exact"
  done
}

verify_completed_activation_failure_keys=(
  failed_at phase activation_step status estate_root backup_dir
  apply_armed_receipt_sha256 control_sha256 transaction_sha256 ingress_opened
)
verify_completed_successor_armed_keys=(
  schema_version armed_at estate_root successor_backup_dir
  candidate_dry_run_receipt_sha256 candidate_release_evidence_sha256
  predecessor_current_file
  predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
  predecessor_apply_receipt_sha256 predecessor_release_evidence_sha256
  predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation route_database_state public_ipv4_ipv6_closed_status
  predecessor_runtime_verified ingress_opened
)
verify_completed_predecessor_current_keys=(
  schema_version state estate_root backup_dir apply_receipt_sha256
  apply_armed_receipt_sha256 control_sha256 release_evidence_sha256
  transaction_sha256 applied_targets_sha256 closed_verified_at
  route_database_state public_ipv4_ipv6_closed_status services_activated
  runtime_verified ingress_opened successor successor_armed_receipt
  successor_armed_receipt_sha256 predecessor_current_file
  predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
  predecessor_apply_receipt_sha256 predecessor_release_evidence_sha256
  predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation runtime_backup_receipt_sha256
  runtime_backup_manifest_sha256
)
verify_completed_predecessor_apply_keys=(
  schema_version completion_state applied_at closed_verified_at estate_root
  backup_dir release_env_sha256 release_evidence_sha256 render_inputs_sha256
  apply_armed_receipt_sha256 control_sha256 transaction_sha256
  applied_targets_sha256 cargo_gate runtime_backup closed_bracket
  route_database_state public_ipv4_ipv6_closed_status ingress_opened
  services_activated runtime_verified successor successor_armed_receipt
  successor_armed_receipt_sha256 predecessor_current_file
  predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
  predecessor_apply_receipt_sha256 predecessor_release_evidence_sha256
  predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation runtime_backup_receipt_sha256
  runtime_backup_manifest_sha256
)
verify_completed_recovery_armed_keys=(
  schema_version armed_at attempt_id mode prior_state legacy_orphan_adopted
  legacy_empty_strad runtime_backup_schema estate_transaction_state estate_root
  backup_dir control_sha256 transaction_sha256 applied_targets_sha256
  apply_armed_receipt_sha256 release_evidence_sha256 dry_run_receipt_sha256
  live_disposition restore_running_writers_manifest restore_running_writers_sha256
  writer_set_reconciled writer_set_source_attempt
  writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256
  writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256
  writer_set_quarantined pre_restored_retry pre_restored_source_attempt
  pre_restored_runtime_snapshot_sha256 pre_restored_estate_snapshot_sha256
  pre_restored_superseded_attempt pre_restored_superseded_failure_receipt_sha256
  pre_restored_superseded_state_sha256 pre_restored_runtime_disposition route_state
  public_host db_public_db_bracket successor successor_armed_receipt_sha256
  predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
  predecessor_apply_receipt_sha256 predecessor_release_evidence_sha256
  predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation
)
verify_completed_completion_keys=(
  schema_version completed_at attempt_id mode estate_root backup_dir control_sha256
  original_estate_transaction_state original_estate_transaction_sha256
  applied_targets_sha256 legacy_empty_strad recovery_armed_receipt_sha256
  release_evidence_sha256 dry_run_receipt_sha256 runtime_restore_receipt_sha256
  estate_restore_state_sha256 pre_restored_retry pre_restored_source_attempt
  pre_restored_superseded_attempt pre_restored_superseded_failure_receipt_sha256
  pre_restored_superseded_state_sha256 pre_restored_runtime_disposition
  restore_running_writers_manifest restore_running_writers_sha256
  writer_set_reconciled writer_set_source_attempt
  writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256
  writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256
  writer_set_quarantined writers_reactivated uncaptured_writers_inactive
  quarantined_writers_inactive runtime_verified live_estate_disposition route_state
  public_host db_public_db_bracket apply_receipt_created successor
  successor_armed_receipt_sha256 predecessor_current_sha256 predecessor_backup_dir
  predecessor_control_sha256 predecessor_apply_receipt_sha256
  predecessor_release_evidence_sha256 predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation
)
verify_completed_archive_keys=(
  schema_version state apply_armed_at estate_root backup_dir
  apply_armed_receipt_sha256 release_evidence_sha256 dry_run_receipt_sha256
  control_sha256 runtime_backup_caller_armed_sha256
  runtime_backup_stop_authority_sha256 ingress_opened successor
  successor_armed_receipt successor_armed_receipt_sha256 predecessor_current_file
  predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
  predecessor_apply_receipt_sha256 predecessor_release_evidence_sha256
  predecessor_runtime_backup_receipt_sha256
  predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
  release_generation apply_failure_receipt apply_failure_receipt_sha256
  recovery_prior_state recovery_mode recovery_attempt_id recovery_armed_receipt
  recovery_armed_receipt_sha256 restore_running_writers_manifest
  restore_running_writers_sha256 legacy_empty_strad pre_restored_retry
  pre_restored_source_attempt pre_restored_runtime_snapshot_sha256
  pre_restored_estate_snapshot_sha256 pre_restored_superseded_attempt
  pre_restored_superseded_failure_receipt_sha256 pre_restored_superseded_state_sha256
  pre_restored_runtime_disposition writer_set_reconciled writer_set_source_attempt
  writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256
  writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256
  writer_set_quarantined transaction_sha256 applied_targets_sha256
  recovery_receipt recovery_receipt_sha256
)
verify_completed_current_keys=(
  "${verify_completed_archive_keys[@]}"
  services_activated runtime_verified
)

verify_completed_successor_authority_structure() {
  local production_predecessor_backup production_predecessor_apply
  require_root_file "$backup/PREDECESSOR-CURRENT.json"
  require_root_file "$backup/SUCCESSOR-ARMED.receipt"
  verify_completed_exact_json_schema \
    "$backup/PREDECESSOR-CURRENT.json" "predecessor CURRENT" \
    "${verify_completed_predecessor_current_keys[@]}"
  verify_completed_exact_receipt_schema \
    "$backup/SUCCESSOR-ARMED.receipt" "successor arm authority" \
    "${verify_completed_successor_armed_keys[@]}"
  production_predecessor_backup=$(jq -er \
    '.backup_dir | select(type == "string")' \
    "$backup/PREDECESSOR-CURRENT.json") || \
    holdfast_die "completed recovery attestation predecessor CURRENT backup path is invalid"
  holdfast_require_absolute "$production_predecessor_backup"
  require_canonical_root_dir "$production_predecessor_backup"
  production_predecessor_apply="$production_predecessor_backup/APPLY.receipt"
  require_root_file "$production_predecessor_apply"
  verify_completed_exact_receipt_schema \
    "$production_predecessor_apply" "predecessor APPLY" \
    "${verify_completed_predecessor_apply_keys[@]}"
  jq -e \
    '(.release_generation | type) == "number" and
     (.release_generation | floor) == .release_generation and
     .release_generation == 2' "$backup/PREDECESSOR-CURRENT.json" >/dev/null || \
    holdfast_die "completion attestation v1 requires current-production successor generation 2 -> 3: immutable predecessor generation differs"
  [[ "$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" predecessor_release_generation)" == "2" && \
    "$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" release_generation)" == "3" ]] || \
    holdfast_die "completion attestation v1 requires current-production successor generation 2 -> 3: immutable successor generation differs"
}

psql_bin=$(test_override HOLDFAST_PSQL_BIN psql)
public_verify=$(test_override HOLDFAST_PUBLIC_VERIFY_BIN "$script_dir/public-origin-verify.sh")
public_verify_helper_fence=""
if [[ "$verify_completed" == "true" ]]; then
  public_verify=$(resolve_verify_completed_helper "$public_verify" "public verification")
  public_verify_helper_fence=$(snapshot_verify_completed_helper \
    "$public_verify" "public verification")
fi
docker_bin=$(test_override HOLDFAST_DOCKER_BIN docker)

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-apply-recover-db-absent "$psql_bin" "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: apply recovery does not prove rikune-root/analyze root absence" >&2
    return 1
  }
}

verify_closed_bracket() {
  verify_database_absent
  if [[ "$verify_completed" == "true" ]]; then
    validate_verify_completed_helper \
      "$public_verify" "$public_verify_helper_fence" "public verification"
  fi
  "$public_verify" --mode closed --url https://rikune.w33d.xyz/
  "$public_verify" --mode closed --url https://analyze.w33d.xyz/
  verify_database_absent
}

commit_recovery_file() {
  local temporary=$1 target=$2 parent
  parent=$(dirname -- "$target")
  [[ -f "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "recovery atomic source is unsafe: $temporary"
  [[ ! -e "$target" && ! -L "$target" ]] || \
    holdfast_die "recovery atomic target already exists: $target"
  chmod 0600 -- "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -f "$target"
  sync -f "$parent"
}

replace_recovery_file() {
  local temporary=$1 target=$2 parent
  parent=$(dirname -- "$target")
  [[ -f "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "recovery replacement source is unsafe: $temporary"
  chmod 0600 -- "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -f "$target"
  sync -f "$parent"
}

validate_successor_completion_namespace() {
  local authority_dir=$1 policy schema relative count
  local -a completion_names=(
    RECOVERY-COMPLETION-ATTESTATION.json
    RECOVERY-COMPLETION-ATTESTATION.sig
    RECOVERY-COMPLETION-ATTESTATION.pub
  )
  policy="$authority_dir/successor-policy.json"
  require_root_file "$policy"
  schema=$(jq -er \
    '.schema_version | select(type == "number" and floor == .)' "$policy") || \
    holdfast_die "successor policy schema is invalid"
  case "$schema" in
    1|2)
      for relative in "${completion_names[@]}"; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "legacy successor backup contains recovery completion authority: $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "0" ]] || \
        holdfast_die "legacy successor CONTROL contains recovery completion authority"
      ;;
    3)
      for relative in "${completion_names[@]}"; do
        require_root_file "$backup/$relative"
        count=$(grep -Fxc \
          "$(holdfast_sha256 "$backup/$relative")  $relative" \
          "$backup/CONTROL.sha256" || true)
        [[ "$count" == "1" ]] || \
          holdfast_die "schema-v3 successor CONTROL does not exactly bind $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "3" ]] || \
        holdfast_die "schema-v3 successor CONTROL recovery completion set is not exact"
      ;;
    4)
      for relative in "${completion_names[@]}"; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "schema-v4 successor backup contains predecessor completion authority: $relative"
      done
      count=$(grep -Ec \
        '[[:space:]][[:space:]]RECOVERY-COMPLETION-ATTESTATION\.(json|sig|pub)$' \
        "$backup/CONTROL.sha256" || true)
      [[ "$count" == "0" ]] || \
        holdfast_die "schema-v4 successor CONTROL contains predecessor completion authority"
      ;;
    *) holdfast_die "successor policy schema is unsupported" ;;
  esac
}

validate_v3_partial_backup_namespace() {
  local path relative schema
  local -A root_entries=(
    [DRY-RUN.receipt]=1
    [PREDECESSOR-CURRENT.json]=1
    [RELEASE-EVIDENCE.json]=1
    [RENDER-INPUTS.sha256]=1
    [RUNTIME-BACKUP-CALLER-ARMED.receipt]=1
    [RUNTIME-BACKUP-CALLER-CLEANUP.receipt]=1
    [SUCCESSOR-ARMED.receipt]=1
    [SUCCESSOR-DELTA.sha256]=1
    [SUPPLY-CHAIN.json]=1
    [SUPPLY-CHAIN.pub]=1
    [SUPPLY-CHAIN.sig]=1
    [release.env]=1
    [runtime]=1
    [successor-authority]=1
  )
  local -A authority_entries=(
    [Dockerfile.analyzer]=1
    [assets]=1
    [bridge-package-lock.json]=1
    [successor-absent.paths]=1
    [successor-frozen-targets.json]=1
    [successor-policy.json]=1
    [successor-preimages.sha256]=1
    [successor-static-targets.sha256]=1
    [successor-supporting-targets.sha256]=1
  )
  local -A route_entries=(
    [20260823_rikune_root_down.sql]=1
    [20260823_rikune_root_up.sql]=1
  )

  schema=$(jq -er '.schema_version' \
    "$backup/successor-authority/successor-policy.json")
  case "$schema" in
    3)
      root_entries[RECOVERY-COMPLETION-ATTESTATION.json]=1
      root_entries[RECOVERY-COMPLETION-ATTESTATION.pub]=1
      root_entries[RECOVERY-COMPLETION-ATTESTATION.sig]=1
      ;;
    4)
      for relative in RECOVERY-COMPLETION-ATTESTATION.json \
        RECOVERY-COMPLETION-ATTESTATION.pub RECOVERY-COMPLETION-ATTESTATION.sig; do
        [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
          holdfast_die "partial schema-v4 backup contains predecessor completion authority: $relative"
      done
      ;;
    *) holdfast_die "partial successor policy schema is unsupported" ;;
  esac

  require_canonical_root_dir "$backup"
  require_canonical_root_dir "$backup/runtime"
  require_canonical_root_dir "$backup/successor-authority"
  require_canonical_root_dir "$backup/successor-authority/assets"
  require_single_device_tree "$backup" "partial schema-v3 backup"
  [[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a symlink"
  [[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a non-root-owned entry"
  [[ -z "$(find "$backup" -xdev ! -type d ! -type f -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a special file"
  [[ -z "$(find "$backup" -xdev -type f -links +1 -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a hard-linked file"
  [[ -z "$(find "$backup" -xdev -type d ! -perm 0700 -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a non-private directory"
  [[ -z "$(find "$backup" -xdev -type f ! -perm 0600 -print -quit)" ]] || \
    holdfast_die "partial schema-v3 backup contains a file with unsafe mode"

  for relative in TARGETS.sha256 APPLY-PREIMAGES.sha256 APPLY-ABSENT.paths \
    APPLY-ARMED.receipt APPLY-PENDING.receipt APPLY.receipt CONTROL.sha256; do
    [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
      holdfast_die "partial schema-v3 backup contains post-runtime apply authority: $relative"
  done

  while IFS= read -r -d '' path; do
    relative=${path#"$backup"/}
    [[ -n "${root_entries[$relative]+x}" ]] || \
      holdfast_die "partial schema-v3 backup contains an unknown root entry: $relative"
  done < <(find "$backup" -xdev -mindepth 1 -maxdepth 1 -print0)
  while IFS= read -r -d '' path; do
    relative=${path#"$backup/successor-authority"/}
    [[ -n "${authority_entries[$relative]+x}" ]] || \
      holdfast_die "partial schema-v3 backup contains unknown successor authority: $relative"
  done < <(find "$backup/successor-authority" -xdev -mindepth 1 -maxdepth 1 -print0)
  while IFS= read -r -d '' path; do
    relative=${path#"$backup/successor-authority/assets"/}
    [[ -n "${route_entries[$relative]+x}" ]] || \
      holdfast_die "partial schema-v3 backup contains unknown route authority: $relative"
  done < <(find "$backup/successor-authority/assets" -xdev \
    -mindepth 1 -maxdepth 1 -print0)
}

derive_backup_successor_mode() {
  local line relative schema release_mode digest authority_dir authority_count=0
  local has_predecessor="false" has_arm="false"
  local -A expected_authorities=()
  [[ -e "$backup/PREDECESSOR-CURRENT.json" || -L "$backup/PREDECESSOR-CURRENT.json" ]] && has_predecessor="true"
  [[ -e "$backup/SUCCESSOR-ARMED.receipt" || -L "$backup/SUCCESSOR-ARMED.receipt" ]] && has_arm="true"
  if [[ ! -e "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" && \
    ! -e "$backup/RELEASE-EVIDENCE.json" && ! -L "$backup/RELEASE-EVIDENCE.json" ]]; then
    [[ "$has_predecessor" == "$has_arm" ]] || \
      holdfast_die "partial backup has a mixed successor authority set"
    printf '%s\n' "$has_predecessor"
    return
  fi
  if [[ ! -e "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" && \
    -f "$backup/RELEASE-EVIDENCE.json" && ! -L "$backup/RELEASE-EVIDENCE.json" ]]; then
    [[ "$verify_completed" != "true" && "$has_predecessor" == "true" && \
      "$has_arm" == "true" ]] || \
      holdfast_die "partial schema-v3 backup has a mixed successor authority set"
    for relative in release.env DRY-RUN.receipt SUPPLY-CHAIN.json \
      SUPPLY-CHAIN.sig SUPPLY-CHAIN.pub RENDER-INPUTS.sha256 \
      SUCCESSOR-DELTA.sha256 successor-authority/successor-policy.json; do
      require_root_file "$backup/$relative"
    done
    for relative in TARGETS.sha256 APPLY-PREIMAGES.sha256 APPLY-ABSENT.paths \
      APPLY-ARMED.receipt APPLY-PENDING.receipt APPLY.receipt; do
      [[ ! -e "$backup/$relative" && ! -L "$backup/$relative" ]] || \
        holdfast_die "partial schema-v3 backup contains post-runtime apply authority: $relative"
    done
    jq -e '.schema_version == 2 and .release_mode == "successor"' \
      "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
      holdfast_die "partial schema-v3 release evidence differs"
    schema=$(jq -er '.schema_version' \
      "$backup/successor-authority/successor-policy.json")
    case "$schema" in
      3)
        jq -e '.ceremony == "holdfast-rikune-successor-v3"' \
          "$backup/successor-authority/successor-policy.json" >/dev/null || \
          holdfast_die "partial schema-v3 successor policy ceremony differs"
        for relative in RECOVERY-COMPLETION-ATTESTATION.json \
          RECOVERY-COMPLETION-ATTESTATION.sig RECOVERY-COMPLETION-ATTESTATION.pub; do
          require_root_file "$backup/$relative"
        done
        ;;
      4)
        jq -e '.ceremony == "holdfast-rikune-successor-v4"' \
          "$backup/successor-authority/successor-policy.json" >/dev/null || \
          holdfast_die "partial schema-v4 successor policy ceremony differs"
        ;;
      *) holdfast_die "partial successor policy schema is unsupported" ;;
    esac
    require_canonical_root_dir "$backup/successor-authority"
    require_canonical_root_dir "$backup/successor-authority/assets"
    [[ "$(find "$backup/successor-authority" -mindepth 1 -maxdepth 1 \
      -type f | wc -l | tr -d ' ')" == "8" && \
      "$(find "$backup/successor-authority" -mindepth 1 -maxdepth 1 | \
        wc -l | tr -d ' ')" == "9" ]] || \
      holdfast_die "partial schema-v3 successor authority set is not exact"
    [[ "$(find "$backup/successor-authority/assets" -mindepth 1 -maxdepth 1 \
      -type f | wc -l | tr -d ' ')" == "2" && \
      "$(find "$backup/successor-authority/assets" -mindepth 1 -maxdepth 1 | \
        wc -l | tr -d ' ')" == "2" ]] || \
      holdfast_die "partial schema-v3 route authority set is not exact"
    validate_v3_partial_backup_namespace
    printf 'true\n'
    return
  fi
  [[ -f "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" && \
    -f "$backup/RELEASE-EVIDENCE.json" && ! -L "$backup/RELEASE-EVIDENCE.json" ]] || \
    holdfast_die "backup has a mixed release authority set"
  require_root_file "$backup/CONTROL.sha256"
  require_root_file "$backup/RELEASE-EVIDENCE.json"
  if [[ "$verify_completed" == "true" && \
    "$has_predecessor" == "true" && "$has_arm" == "true" ]]; then
    verify_completed_successor_authority_structure
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]] || \
      holdfast_die "CONTROL contains an invalid checksum line"
    relative=${BASH_REMATCH[1]}
    [[ "$relative" != /* && "$relative" != ".." && "$relative" != *"../"* ]] || \
      holdfast_die "CONTROL contains an unsafe path"
  done <"$backup/CONTROL.sha256"
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  grep -Fqx "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")  RELEASE-EVIDENCE.json" \
    "$backup/CONTROL.sha256" || holdfast_die "CONTROL omits RELEASE-EVIDENCE"
  schema=$(jq -er '.schema_version' "$backup/RELEASE-EVIDENCE.json")
  release_mode=$(jq -er '.release_mode // "base"' "$backup/RELEASE-EVIDENCE.json")
  if [[ "$schema" == "1" && "$release_mode" == "base" ]]; then
    [[ "$has_predecessor" == "false" && "$has_arm" == "false" && \
      ! -e "$backup/SUCCESSOR-DELTA.sha256" && ! -L "$backup/SUCCESSOR-DELTA.sha256" && \
      ! -e "$backup/successor-authority" && ! -L "$backup/successor-authority" ]] || \
      holdfast_die "base backup contains mixed successor authority"
    grep -Eq '[[:space:]][[:space:]](PREDECESSOR-CURRENT.json|SUCCESSOR-ARMED.receipt|SUCCESSOR-DELTA.sha256|successor-authority/)' \
      "$backup/CONTROL.sha256" && holdfast_die "base CONTROL contains successor authority"
    printf 'false\n'
    return
  fi
  [[ "$schema" == "2" && "$release_mode" == "successor" ]] || \
    holdfast_die "backup release mode is unsupported or mixed"
  for relative in PREDECESSOR-CURRENT.json SUCCESSOR-ARMED.receipt \
    SUCCESSOR-DELTA.sha256 RENDER-INPUTS.sha256; do
    require_root_file "$backup/$relative"
    grep -Fqx "$(holdfast_sha256 "$backup/$relative")  $relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits $relative"
  done
  authority_dir="$backup/successor-authority"
  require_canonical_root_dir "$authority_dir"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${expected_authorities[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    expected_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    [[ "$(holdfast_sha256 "$authority_dir/$relative")" == "$digest" ]] || \
      holdfast_die "successor generation authority differs: $relative"
    grep -Fqx "$digest  successor-authority/$relative" "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits generation authority: $relative"
    authority_count=$((authority_count + 1))
  done <"$backup/RENDER-INPUTS.sha256"
  ((authority_count == 6)) || holdfast_die "successor generation authority set is not exact"
  for relative in Dockerfile.analyzer bridge-package-lock.json; do
    expected_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/$relative")  successor-authority/$relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits generation authority: $relative"
  done
  require_canonical_root_dir "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_file "$authority_dir/assets/$relative"
    grep -Fqx "$(holdfast_sha256 "$authority_dir/assets/$relative")  successor-authority/assets/$relative" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits route authority: $relative"
  done
  [[ "$(find "$authority_dir/assets" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]] || \
    holdfast_die "successor route authority file set is not exact"
  while IFS= read -r relative; do
    [[ -n "${expected_authorities[$relative]+x}" ]] || \
      holdfast_die "successor authority directory contains an unbound generation file: $relative"
  done < <(find "$authority_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
  [[ "$(find "$authority_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "8" ]] || \
    holdfast_die "successor authority directory file set is not exact"
  validate_successor_completion_namespace "$authority_dir"
  printf 'true\n'
}

successor_recovery="false"
successor_recovery_v3="false"
backup_expected_successor=""
predecessor_current_file=""
predecessor_current_sha=""
predecessor_backup=""
predecessor_control_sha=""
predecessor_apply_sha=""
predecessor_release_sha=""
predecessor_runtime_receipt_sha=""
predecessor_runtime_manifest_sha=""
predecessor_generation=""
release_generation=""
successor_armed_receipt=""
successor_armed_sha=""
successor_policy_version=""
predecessor_completion_kind=""
predecessor_completion_attestation_sha=""
predecessor_completion_signature_sha=""
predecessor_completion_public_key_sha=""

validate_v3_completion_receipt_namespace() {
  local receipt=$1 observed
  observed=$(awk -F= '
    $1 ~ /^predecessor_completion_/ { print $1 }
  ' "$receipt" | sort)
  [[ "$observed" == $'predecessor_completion_attestation_sha256\npredecessor_completion_kind\npredecessor_completion_public_key_sha256\npredecessor_completion_signature_sha256' ]] || \
    holdfast_die "schema-v3 successor recovery completion receipt namespace differs"
}

validate_no_predecessor_completion_namespace() {
  local artifact=$1
  require_root_file "$artifact"
  ! grep -Eq 'predecessor_completion_[A-Za-z0-9_]+' "$artifact" || \
    holdfast_die "schema-v4 artifact contains predecessor completion authority: $artifact"
}

validate_recovery_route_contract() {
  local receipt=$1 label=$2 schema expected key value
  schema=$(holdfast_receipt_value "$receipt" schema_version)
  for expected in \
    "route_state=absent" "db_public_db_bracket=absent-404-absent"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "$label route contract differs: $key"
  done
  case "$schema" in
    2)
      [[ "$successor_policy_version" != "4" ]] || \
        holdfast_die "$label schema-v2 route contract is invalid for schema-v4 successor policy"
      [[ "$(holdfast_receipt_value "$receipt" public_host)" == \
        "analyze.w33d.xyz" ]] || \
        holdfast_die "$label schema-v2 public host differs"
      ! grep -Eq \
        '^(route_conflict_cleanup|public_ipv4_ipv6_closed_status|legacy_public_host|legacy_route_state|legacy_public_ipv4_ipv6_closed_status)=' \
        "$receipt" || \
        holdfast_die "$label schema-v2 contains dual-host fields"
      ;;
    3)
      [[ "$successor_recovery" == "true" && \
        "$successor_policy_version" == "4" ]] || \
        holdfast_die "$label schema-v3 route contract lacks schema-v4 successor authority"
      for expected in \
        "route_conflict_cleanup=same-name-or-rikune-root-or-analyze-host" \
        "public_host=rikune.w33d.xyz" \
        "public_ipv4_ipv6_closed_status=404" \
        "legacy_public_host=analyze.w33d.xyz" \
        "legacy_route_state=absent" \
        "legacy_public_ipv4_ipv6_closed_status=404"; do
        key=${expected%%=*}
        value=${expected#*=}
        [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
          holdfast_die "$label schema-v3 route contract differs: $key"
      done
      ;;
    *) holdfast_die "$label schema is unsupported" ;;
  esac
}

recovery_receipt_schema_version() {
  if [[ "$successor_recovery" == "true" && \
    "$successor_policy_version" == "4" ]]; then
    printf '3\n'
  else
    printf '2\n'
  fi
}

append_recovery_route_contract_fields() {
  printf 'route_state=absent\n'
  if [[ "$(recovery_receipt_schema_version)" == "3" ]]; then
    printf 'route_conflict_cleanup=same-name-or-rikune-root-or-analyze-host\n'
    printf 'public_host=rikune.w33d.xyz\n'
    printf 'public_ipv4_ipv6_closed_status=404\n'
    printf 'legacy_public_host=analyze.w33d.xyz\n'
    printf 'legacy_route_state=absent\n'
    printf 'legacy_public_ipv4_ipv6_closed_status=404\n'
  else
    printf 'public_host=analyze.w33d.xyz\n'
  fi
  printf 'db_public_db_bracket=absent-404-absent\n'
}

validate_exact_receipt_keys() {
  local receipt=$1 label=$2 index=0 key
  local -a actual=()
  shift 2
  require_root_file "$receipt"
  mapfile -t actual < <(cut -d= -f1 -- "$receipt")
  ((${#actual[@]} == $#)) || holdfast_die "$label field set is not exact"
  for key in "$@"; do
    [[ "${actual[$index]}" == "$key" ]] || holdfast_die "$label field set is not exact"
    index=$((index + 1))
  done
}

validate_exact_json_keys() {
  local document=$1 label=$2 key
  local -a actual=()
  local -A expected=()
  shift 2
  require_root_file "$document"
  for key in "$@"; do expected[$key]=1; done
  mapfile -t actual < <(jq -r 'keys_unsorted[]' "$document")
  ((${#actual[@]} == ${#expected[@]})) || holdfast_die "$label field set is not exact"
  for key in "${actual[@]}"; do
    [[ -n "${expected[$key]+x}" ]] || holdfast_die "$label field set is not exact"
  done
}

validate_verify_completed_predecessor_authority() {
  local predecessor_apply="$predecessor_backup/APPLY.receipt"
  local predecessor_apply_armed="$predecessor_backup/APPLY-ARMED.receipt"
  local predecessor_dry_run="$predecessor_backup/DRY-RUN.receipt"
  local predecessor_release_env="$predecessor_backup/release.env"
  local predecessor_render_inputs="$predecessor_backup/RENDER-INPUTS.sha256"
  local predecessor_transaction="$predecessor_backup/estate/TRANSACTION.json"
  local predecessor_applied_targets="$predecessor_backup/estate/APPLIED-TARGETS.sha256"
  local predecessor_successor_arm="$predecessor_backup/SUCCESSOR-ARMED.receipt"
  local prior_current="$predecessor_backup/PREDECESSOR-CURRENT.json"
  local prior_backup prior_control prior_apply prior_release prior_runtime_receipt
  local prior_runtime_manifest prior_control_sha prior_apply_sha prior_release_sha
  local prior_runtime_receipt_sha prior_runtime_manifest_sha prior_current_sha
  local predecessor_release_env_sha predecessor_render_inputs_sha
  local predecessor_apply_armed_sha predecessor_transaction_sha
  local predecessor_applied_targets_sha predecessor_successor_arm_sha
  local applied_at closed_verified_at current_closed successor_armed_at normalized
  local relative expected key value timestamp

  for relative in \
    "$predecessor_apply_armed" "$predecessor_dry_run" \
    "$predecessor_release_env" "$predecessor_render_inputs" \
    "$predecessor_transaction" "$predecessor_applied_targets" \
    "$predecessor_successor_arm" "$prior_current"; do
    require_root_file "$relative"
  done
  verify_completed_exact_receipt_schema \
    "$predecessor_successor_arm" "predecessor successor arm" \
    "${verify_completed_successor_armed_keys[@]}"
  verify_completed_json_structure "$prior_current"

  prior_backup=$(jq -er '.backup_dir | select(type == "string")' "$prior_current") || \
    holdfast_die "completed recovery attestation predecessor lineage backup path is invalid"
  holdfast_require_absolute "$prior_backup"
  require_canonical_root_dir "$prior_backup"
  [[ "$prior_backup" != "$predecessor_backup" && "$prior_backup" != "$backup" ]] || \
    holdfast_die "completed recovery attestation predecessor lineage backup overlaps a successor generation"
  [[ -z "$(find "$prior_backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "completed recovery attestation predecessor lineage backup is not private"
  [[ -z "$(find "$prior_backup" -xdev -type l -print -quit)" ]] || \
    holdfast_die "completed recovery attestation predecessor lineage backup contains a symlink"
  [[ -z "$(find "$prior_backup" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "completed recovery attestation predecessor lineage backup contains a non-root-owned entry"
  prior_control="$prior_backup/CONTROL.sha256"
  prior_apply="$prior_backup/APPLY.receipt"
  prior_release="$prior_backup/RELEASE-EVIDENCE.json"
  prior_runtime_receipt="$prior_backup/runtime/BACKUP.receipt"
  prior_runtime_manifest="$prior_backup/runtime/SHA256SUMS"
  for relative in "$prior_control" "$prior_apply" "$prior_release" \
    "$prior_runtime_receipt" "$prior_runtime_manifest"; do
    require_root_file "$relative"
  done
  verify_completed_receipt_structure "$prior_apply"
  verify_completed_json_structure "$prior_release"
  (cd "$prior_backup" && sha256sum --check CONTROL.sha256) >/dev/null
  (cd "$prior_backup/runtime" && sha256sum --check SHA256SUMS) >/dev/null

  prior_current_sha=$(holdfast_sha256 "$prior_current")
  prior_control_sha=$(holdfast_sha256 "$prior_control")
  prior_apply_sha=$(holdfast_sha256 "$prior_apply")
  prior_release_sha=$(holdfast_sha256 "$prior_release")
  prior_runtime_receipt_sha=$(holdfast_sha256 "$prior_runtime_receipt")
  prior_runtime_manifest_sha=$(holdfast_sha256 "$prior_runtime_manifest")
  predecessor_release_env_sha=$(holdfast_sha256 "$predecessor_release_env")
  predecessor_render_inputs_sha=$(holdfast_sha256 "$predecessor_render_inputs")
  predecessor_apply_armed_sha=$(holdfast_sha256 "$predecessor_apply_armed")
  predecessor_transaction_sha=$(holdfast_sha256 "$predecessor_transaction")
  predecessor_applied_targets_sha=$(holdfast_sha256 "$predecessor_applied_targets")
  predecessor_successor_arm_sha=$(holdfast_sha256 "$predecessor_successor_arm")

  for expected in \
    "successor_armed_receipt=SUCCESSOR-ARMED.receipt" \
    "successor_armed_receipt_sha256=$predecessor_successor_arm_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$prior_current_sha" \
    "predecessor_backup_dir=$prior_backup" \
    "predecessor_control_sha256=$prior_control_sha" \
    "predecessor_apply_receipt_sha256=$prior_apply_sha" \
    "predecessor_release_evidence_sha256=$prior_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$prior_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$prior_runtime_manifest_sha"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(jq -er --arg key "$key" '.[$key] | tostring' \
      "$predecessor_current_file")" == "$value" ]] || \
      holdfast_die "completed recovery attestation predecessor CURRENT differs: $key"
  done
  jq -e \
    --arg estate "$estate_root" \
    --arg backup "$predecessor_backup" \
    --arg apply "$predecessor_apply_sha" \
    --arg armed "$predecessor_apply_armed_sha" \
    --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" \
    --arg transaction "$predecessor_transaction_sha" \
    --arg targets "$predecessor_applied_targets_sha" \
    --arg closed "$(holdfast_receipt_value "$predecessor_apply" closed_verified_at)" \
    --arg runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg runtime_manifest "$predecessor_runtime_manifest_sha" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .estate_root == $estate and .backup_dir == $backup and
     .apply_receipt_sha256 == $apply and .apply_armed_receipt_sha256 == $armed and
     .control_sha256 == $control and .release_evidence_sha256 == $release and
     .transaction_sha256 == $transaction and .applied_targets_sha256 == $targets and
     .closed_verified_at == $closed and .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .services_activated == true and
     .runtime_verified == true and .ingress_opened == false and .successor == true and
     .predecessor_release_generation == 1 and .release_generation == 2 and
     .runtime_backup_receipt_sha256 == $runtime_receipt and
     .runtime_backup_manifest_sha256 == $runtime_manifest' \
    "$predecessor_current_file" >/dev/null || \
    holdfast_die "completed recovery attestation predecessor CURRENT semantics differ"

  for expected in \
    "schema_version=2" "completion_state=applied_ingress_closed" \
    "estate_root=$estate_root" "backup_dir=$predecessor_backup" \
    "release_env_sha256=$predecessor_release_env_sha" \
    "release_evidence_sha256=$predecessor_release_sha" \
    "render_inputs_sha256=$predecessor_render_inputs_sha" \
    "apply_armed_receipt_sha256=$predecessor_apply_armed_sha" \
    "control_sha256=$predecessor_control_sha" \
    "transaction_sha256=$predecessor_transaction_sha" \
    "applied_targets_sha256=$predecessor_applied_targets_sha" \
    "cargo_gate=passed" "runtime_backup=passed" "closed_bracket=passed" \
    "route_database_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "ingress_opened=false" "services_activated=true" "runtime_verified=true" \
    "successor=true" "successor_armed_receipt=SUCCESSOR-ARMED.receipt" \
    "successor_armed_receipt_sha256=$predecessor_successor_arm_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$prior_current_sha" \
    "predecessor_backup_dir=$prior_backup" \
    "predecessor_control_sha256=$prior_control_sha" \
    "predecessor_apply_receipt_sha256=$prior_apply_sha" \
    "predecessor_release_evidence_sha256=$prior_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$prior_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$prior_runtime_manifest_sha" \
    "predecessor_release_generation=1" "release_generation=2" \
    "runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$predecessor_apply" "$key")" == "$value" ]] || \
      holdfast_die "completed recovery attestation predecessor APPLY differs: $key"
  done

  applied_at=$(holdfast_receipt_value "$predecessor_apply" applied_at)
  closed_verified_at=$(holdfast_receipt_value "$predecessor_apply" closed_verified_at)
  current_closed=$(jq -er '.closed_verified_at' "$predecessor_current_file")
  successor_armed_at=$(holdfast_receipt_value "$predecessor_successor_arm" armed_at)
  for timestamp in "$successor_armed_at" "$closed_verified_at" "$applied_at"; do
    [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
      holdfast_die "completed recovery attestation predecessor timestamp is not canonical UTC"
    normalized=$(date -u -d "$timestamp" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || \
      holdfast_die "completed recovery attestation predecessor timestamp is invalid"
    [[ "$normalized" == "$timestamp" ]] || \
      holdfast_die "completed recovery attestation predecessor timestamp is not canonical UTC"
  done
  [[ "$current_closed" == "$closed_verified_at" && \
    ( "$successor_armed_at" < "$closed_verified_at" || \
      "$successor_armed_at" == "$closed_verified_at" ) && \
    ( "$closed_verified_at" < "$applied_at" || \
      "$closed_verified_at" == "$applied_at" ) ]] || \
    holdfast_die "completed recovery attestation predecessor timestamps are out of order"

  for expected in \
    "schema_version=1" "estate_root=$estate_root" \
    "successor_backup_dir=$predecessor_backup" \
    "candidate_dry_run_receipt_sha256=$(holdfast_sha256 "$predecessor_dry_run")" \
    "candidate_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$prior_current_sha" \
    "predecessor_backup_dir=$prior_backup" \
    "predecessor_control_sha256=$prior_control_sha" \
    "predecessor_apply_receipt_sha256=$prior_apply_sha" \
    "predecessor_release_evidence_sha256=$prior_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$prior_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$prior_runtime_manifest_sha" \
    "predecessor_release_generation=1" "release_generation=2" \
    "route_database_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "predecessor_runtime_verified=true" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$predecessor_successor_arm" "$key")" == "$value" ]] || \
      holdfast_die "completed recovery attestation predecessor successor arm differs: $key"
  done

  jq -e \
    --arg estate "$estate_root" --arg backup "$prior_backup" \
    --arg control "$prior_control_sha" --arg apply "$prior_apply_sha" \
    --arg release "$prior_release_sha" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .estate_root == $estate and .backup_dir == $backup and
     .control_sha256 == $control and .apply_receipt_sha256 == $apply and
     .release_evidence_sha256 == $release and
     .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .services_activated == true and
     .runtime_verified == true and .ingress_opened == false and
     ((.release_generation // 1) == 1) and (has("successor") | not)' \
    "$prior_current" >/dev/null || \
    holdfast_die "completed recovery attestation generation-1 CURRENT authority differs"
  [[ "$(holdfast_receipt_value "$prior_runtime_receipt" schema_version)" == "2" && \
    "$(holdfast_receipt_value "$prior_runtime_receipt" isolated_restore_probe)" == "passed" ]] || \
    holdfast_die "completed recovery attestation generation-1 runtime authority differs"

  verify_completed_json_structure "$predecessor_backup/RELEASE-EVIDENCE.json"
  jq -e \
    --arg env "$predecessor_release_env_sha" --arg current "$prior_current_sha" \
    --arg control "$prior_control_sha" --arg apply "$prior_apply_sha" \
    --arg release "$prior_release_sha" --arg runtime "$prior_runtime_manifest_sha" \
    '.schema_version == 2 and .release_mode == "successor" and
     .release_env_sha256 == $env and
     .predecessor_binding.current_state_sha256 == $current and
     .predecessor_binding.control_sha256 == $control and
     .predecessor_binding.apply_receipt_sha256 == $apply and
     .predecessor_binding.release_evidence_sha256 == $release and
     .predecessor_binding.runtime_manifest_sha256 == $runtime' \
    "$predecessor_backup/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "completed recovery attestation predecessor RELEASE-EVIDENCE lineage differs"
  for relative in RELEASE-EVIDENCE.json release.env DRY-RUN.receipt \
    RENDER-INPUTS.sha256 APPLY-ARMED.receipt runtime/SHA256SUMS \
    runtime/BACKUP.receipt PREDECESSOR-CURRENT.json SUCCESSOR-ARMED.receipt; do
    grep -Fqx "$(holdfast_sha256 "$predecessor_backup/$relative")  $relative" \
      "$predecessor_backup/CONTROL.sha256" || \
      holdfast_die "completed recovery attestation predecessor CONTROL omits $relative"
  done
}

validate_recovered_successor_authority() {
  local pointer=$1 authority_dir="$backup/successor-authority"
  local require_control=${2:-true}
  local policy="$authority_dir/successor-policy.json"
  local attestation="$backup/RECOVERY-COMPLETION-ATTESTATION.json"
  local signature="$backup/RECOVERY-COMPLETION-ATTESTATION.sig"
  local public_key="$backup/RECOVERY-COMPLETION-ATTESTATION.pub"
  local attestation_sha signature_sha public_key_sha observed expected key value
  local successor_delta_sha

  require_root_file "$policy"
  for observed in "$attestation" "$signature" "$public_key"; do
    require_root_file "$observed"
    [[ "$(stat -c '%a' -- "$observed")" == "600" ]] || \
      holdfast_die "schema-v3 recovery completion artifact must have mode 0600"
  done
  jq -e '
    keys == ["ceremony","overlay","predecessor","schema_version","successor"] and
    .schema_version == 3 and .ceremony == "holdfast-rikune-successor-v3" and
    (.predecessor | keys) == [
      "access_build_input_schema","access_build_input_sha256","access_image",
      "candidate_evidence_sha256","candidate_targets_sha256","completion",
      "control_sha256","current_state_sha256","package_catalog_sha256",
      "permission_catalog_sha256","release_evidence_sha256","runtime_manifest_sha256"
    ] and
    (.predecessor.completion | keys) == [
      "attestation_sha256","kind","public_key_sha256","signature_sha256"
    ] and
    .predecessor.completion.kind == "recovery-completion-attestation-v1" and
    (.predecessor | has("apply_receipt_sha256") | not)' \
    "$policy" >/dev/null || \
    holdfast_die "schema-v3 successor policy recovery completion binding differs"

  predecessor_completion_kind=$(jq -er '.predecessor.completion.kind' "$policy")
  predecessor_completion_attestation_sha=$(jq -er \
    '.predecessor.completion.attestation_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 attestation digest is invalid"
  predecessor_completion_signature_sha=$(jq -er \
    '.predecessor.completion.signature_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 signature digest is invalid"
  predecessor_completion_public_key_sha=$(jq -er \
    '.predecessor.completion.public_key_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$policy") || holdfast_die "schema-v3 public-key digest is invalid"
  attestation_sha=$(holdfast_sha256 "$attestation")
  signature_sha=$(holdfast_sha256 "$signature")
  public_key_sha=$(holdfast_sha256 "$public_key")
  [[ "$attestation_sha" == "$predecessor_completion_attestation_sha" && \
    "$signature_sha" == "$predecessor_completion_signature_sha" && \
    "$public_key_sha" == "$predecessor_completion_public_key_sha" ]] || \
    holdfast_die "schema-v3 recovery completion artifact differs from policy"
  run_python_tool "$completion_attestation_tool" \
    "$script_dir/recovery_completion_attestation.py" verify \
    --attestation "$attestation" --signature "$signature" \
    --public-key "$public_key" \
    --public-key-sha256 "$predecessor_completion_public_key_sha" >/dev/null

  predecessor_control_sha=$(jq -er '.predecessor.control_sha256' "$policy")
  predecessor_release_sha=$(jq -er '.predecessor.release_evidence_sha256' "$policy")
  predecessor_runtime_manifest_sha=$(jq -er '.predecessor.runtime_manifest_sha256' "$policy")
  predecessor_backup=$(jq -er '.backup_dir | select(type == "string")' \
    "$predecessor_current_file") || \
    holdfast_die "schema-v3 predecessor CURRENT backup identity is invalid"
  holdfast_require_absolute "$predecessor_backup"
  predecessor_runtime_receipt_sha=$(jq -er \
    '.runtime_receipt_sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$attestation") || holdfast_die "schema-v3 predecessor runtime receipt digest is invalid"
  predecessor_generation=$(jq -er '.release_generation' "$attestation")
  release_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  predecessor_apply_sha=""

  jq -e \
    --arg estate "$estate_root" --arg predecessor_backup "$predecessor_backup" \
    --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" \
    --arg runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg runtime_manifest "$predecessor_runtime_manifest_sha" '
    .schema_version == 1 and .kind == "recovery-completion-attestation-v1" and
    .mode == "resume" and .successor == true and .recovery_schema_version == 2 and
    .estate_root == $estate and .backup_dir == $predecessor_backup and
    .current_file == "CURRENT.json" and .current_sha256 == $current and
    .control_file == "CONTROL.sha256" and .control_sha256 == $control and
    .release_evidence_file == "RELEASE-EVIDENCE.json" and
    .release_evidence_sha256 == $release and
    .runtime_receipt_file == "runtime/BACKUP.receipt" and
    .runtime_receipt_sha256 == $runtime_receipt and
    .runtime_manifest_file == "runtime/SHA256SUMS" and
    .runtime_manifest_sha256 == $runtime_manifest and
    .predecessor_release_generation == 2 and .release_generation == 3 and
    .services_activated == true and .runtime_verified == true and
    .route_database_state == "absent" and .public_ipv4_ipv6_closed_status == 404 and
    .db_public_db_bracket == "absent-404-absent" and .ingress_opened == false and
    .apply_receipt_created == false' "$attestation" >/dev/null || \
    holdfast_die "schema-v3 recovery completion attestation lineage differs"
  jq -e \
    --arg estate "$estate_root" --arg backup "$predecessor_backup" \
    --arg control "$predecessor_control_sha" --arg release "$predecessor_release_sha" \
    --arg runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg runtime_manifest "$predecessor_runtime_manifest_sha" '
    .schema_version == 2 and .state == "applied_ingress_closed" and
    .estate_root == $estate and .backup_dir == $backup and
    .control_sha256 == $control and .release_evidence_sha256 == $release and
    ((has("runtime_backup_receipt_sha256") | not) or
      .runtime_backup_receipt_sha256 == $runtime_receipt) and
    ((has("runtime_backup_manifest_sha256") | not) or
      .runtime_backup_manifest_sha256 == $runtime_manifest) and
    (has("apply_receipt_sha256") | not) and
    (has("route_database_state") | not) and
    (has("public_ipv4_ipv6_closed_status") | not) and
    .services_activated == true and .runtime_verified == true and
    .ingress_opened == false and .successor == true and
    .predecessor_release_generation == 2 and .release_generation == 3' \
    "$predecessor_current_file" >/dev/null || \
    holdfast_die "schema-v3 recovered predecessor CURRENT differs"
  [[ "$predecessor_generation" == "3" && "$release_generation" == "4" ]] || \
    holdfast_die "schema-v3 successor recovery generation linkage is invalid"

  for expected in \
    "schema_version=1" "successor_backup_dir=$backup" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "successor_policy_sha256=$(holdfast_sha256 "$policy")" \
    "predecessor_completion_kind=$predecessor_completion_kind" \
    "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
    "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
    "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation" "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v3 successor recovery arm differs: $key"
  done
  validate_v3_completion_receipt_namespace "$successor_armed_receipt"
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$successor_armed_receipt" || \
    holdfast_die "schema-v3 successor recovery arm contains legacy APPLY authority"

  jq -e \
    --arg successor_sha "$successor_armed_sha" \
    --arg predecessor_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg completion_kind "$predecessor_completion_kind" \
    --arg completion_attestation "$predecessor_completion_attestation_sha" \
    --arg completion_signature "$predecessor_completion_signature_sha" \
    --arg completion_key "$predecessor_completion_public_key_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson predecessor_generation "$predecessor_generation" \
    --argjson generation "$release_generation" '
    .successor == true and .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
    .successor_armed_receipt_sha256 == $successor_sha and
    .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
    .predecessor_current_sha256 == $predecessor_sha and
    .predecessor_backup_dir == $predecessor_backup and
    .predecessor_control_sha256 == $predecessor_control and
    (has("predecessor_apply_receipt_sha256") | not) and
    .predecessor_completion_kind == $completion_kind and
    .predecessor_completion_attestation_sha256 == $completion_attestation and
    .predecessor_completion_signature_sha256 == $completion_signature and
    .predecessor_completion_public_key_sha256 == $completion_key and
    ([keys[] | select(startswith("predecessor_completion_"))] | sort) == [
      "predecessor_completion_attestation_sha256",
      "predecessor_completion_kind",
      "predecessor_completion_public_key_sha256",
      "predecessor_completion_signature_sha256"
    ] and
    .predecessor_release_evidence_sha256 == $predecessor_release and
    .predecessor_runtime_backup_receipt_sha256 == $predecessor_runtime_receipt and
    .predecessor_runtime_backup_manifest_sha256 == $predecessor_runtime_manifest and
    .predecessor_release_generation == $predecessor_generation and
    .release_generation == $generation' "$pointer" >/dev/null || \
    holdfast_die "schema-v3 successor recovery CURRENT linkage differs"
  jq -e \
    --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
    --arg release "$predecessor_release_sha" --arg runtime "$predecessor_runtime_manifest_sha" \
    --arg kind "$predecessor_completion_kind" \
    --arg attestation "$predecessor_completion_attestation_sha" \
    --arg signature "$predecessor_completion_signature_sha" \
    --arg public_key "$predecessor_completion_public_key_sha" '
    .schema_version == 2 and .release_mode == "successor" and
    .predecessor_binding.current_state_sha256 == $current and
    .predecessor_binding.control_sha256 == $control and
    (.predecessor_binding | has("apply_receipt_sha256") | not) and
    .predecessor_binding.release_evidence_sha256 == $release and
    .predecessor_binding.runtime_manifest_sha256 == $runtime and
    .predecessor_binding.completion == {
      kind: $kind, attestation_sha256: $attestation,
      signature_sha256: $signature, public_key_sha256: $public_key
    }' "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
    holdfast_die "schema-v3 successor recovery RELEASE-EVIDENCE lineage differs"

  successor_delta_sha=$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")
  for expected in \
    "release_evidence_sha256=$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
    "render_inputs_sha256=$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" \
    "successor_delta_sha256=$successor_delta_sha" \
    "predecessor_completion_kind=$predecessor_completion_kind" \
    "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
    "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
    "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha" \
    "supply_chain_evidence_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.json")" \
    "supply_chain_signature_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.sig")" \
    "supply_chain_public_key_sha256=$(holdfast_sha256 "$backup/SUPPLY-CHAIN.pub")"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v3 successor recovery dry-run authority differs: $key"
  done
  validate_v3_completion_receipt_namespace "$backup/DRY-RUN.receipt"
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$backup/DRY-RUN.receipt" || \
    holdfast_die "schema-v3 dry-run authority contains legacy predecessor APPLY authority"
  [[ "$attestation_sha" == "$(holdfast_sha256 "$attestation")" && \
    "$signature_sha" == "$(holdfast_sha256 "$signature")" && \
    "$public_key_sha" == "$(holdfast_sha256 "$public_key")" ]] || \
    holdfast_die "schema-v3 recovery completion authority changed during validation"
  if [[ "$require_control" == "true" ]]; then
    (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  else
    [[ ! -e "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" ]] || \
      holdfast_die "partial schema-v3 successor authority unexpectedly has CONTROL"
    [[ "$predecessor_current_sha" == "$(holdfast_sha256 "$predecessor_current_file")" && \
      "$successor_armed_sha" == "$(holdfast_sha256 "$successor_armed_receipt")" && \
      "$(holdfast_receipt_value "$successor_armed_receipt" successor_policy_sha256)" == \
        "$(holdfast_sha256 "$policy")" ]] || \
      holdfast_die "partial schema-v3 successor authority changed during validation"
  fi
}

load_successor_authority() {
  local pointer=$1 expected key value predecessor_apply predecessor_file
  local successor_armed_at normalized_successor_armed_at
  local pointer_successor pointer_sha
  local policy="$backup/successor-authority/successor-policy.json"
  local -a v4_predecessor_apply_keys=(
    schema_version completion_state applied_at closed_verified_at estate_root
    backup_dir release_env_sha256 release_evidence_sha256 render_inputs_sha256
    apply_armed_receipt_sha256 control_sha256 transaction_sha256
    applied_targets_sha256 cargo_gate runtime_backup closed_bracket
    route_database_state public_ipv4_ipv6_closed_status ingress_opened
    services_activated runtime_verified successor successor_armed_receipt
    successor_armed_receipt_sha256 predecessor_current_file
    predecessor_current_sha256 predecessor_backup_dir predecessor_control_sha256
    predecessor_completion_kind predecessor_completion_attestation_sha256
    predecessor_completion_signature_sha256 predecessor_completion_public_key_sha256
    predecessor_release_evidence_sha256 predecessor_runtime_backup_receipt_sha256
    predecessor_runtime_backup_manifest_sha256 predecessor_release_generation
    release_generation runtime_backup_receipt_sha256 runtime_backup_manifest_sha256
  )
  pointer_successor=$(jq -er 'if has("successor") then (.successor | tostring) else "absent" end' "$pointer")
  if [[ "$backup_expected_successor" == "false" ]]; then
    [[ "$pointer_successor" == "false" || "$pointer_successor" == "absent" ]] || \
      holdfast_die "base backup CURRENT successor mode differs"
    successor_recovery="false"
    return 0
  fi
  [[ "$backup_expected_successor" == "true" && "$pointer_successor" == "true" ]] || \
    holdfast_die "successor backup CURRENT mode is missing or downgraded"
  successor_recovery="true"
  predecessor_current_file="$backup/PREDECESSOR-CURRENT.json"
  successor_armed_receipt="$backup/SUCCESSOR-ARMED.receipt"
  require_root_file "$predecessor_current_file"
  require_root_file "$successor_armed_receipt"
  predecessor_current_sha=$(holdfast_sha256 "$predecessor_current_file")
  successor_armed_sha=$(holdfast_sha256 "$successor_armed_receipt")
  successor_policy_version=$(jq -er '.schema_version' "$policy")
  if [[ "$successor_policy_version" == "3" ]]; then
    require_root_file "$pointer"
    pointer_sha=$(holdfast_sha256 "$pointer")
    if [[ -f "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" ]]; then
      validate_recovered_successor_authority "$pointer" true
    else
      validate_recovered_successor_authority "$pointer" false
    fi
    [[ "$(holdfast_sha256 "$pointer")" == "$pointer_sha" ]] || \
      holdfast_die "schema-v3 successor recovery pointer changed during validation"
    return 0
  fi
  [[ "$successor_policy_version" == "1" || "$successor_policy_version" == "2" || \
    "$successor_policy_version" == "4" ]] || \
    holdfast_die "successor recovery policy schema is unsupported"
  if [[ "$successor_policy_version" == "4" ]]; then
    jq -e '
      keys == ["ceremony","overlay","predecessor","schema_version","successor"] and
      .schema_version == 4 and .ceremony == "holdfast-rikune-successor-v4" and
      (.predecessor | keys) == [
        "access_build_input_schema","access_build_input_sha256",
        "access_image","apply_receipt_sha256",
        "candidate_evidence_sha256","candidate_targets_sha256","control_sha256",
        "current_state_sha256","package_catalog_sha256","permission_catalog_sha256",
        "release_evidence_sha256","runtime_manifest_sha256"
      ] and (.predecessor | has("completion") | not)' "$policy" >/dev/null || \
      holdfast_die "schema-v4 successor policy authority differs"
    validate_no_predecessor_completion_namespace "$policy"
    validate_no_predecessor_completion_namespace "$successor_armed_receipt"
    validate_no_predecessor_completion_namespace "$pointer"
    validate_no_predecessor_completion_namespace "$backup/DRY-RUN.receipt"
    validate_no_predecessor_completion_namespace "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
    if [[ -f "$backup/APPLY-ARMED.receipt" && ! -L "$backup/APPLY-ARMED.receipt" ]]; then
      validate_no_predecessor_completion_namespace "$backup/APPLY-ARMED.receipt"
    fi
  fi
  jq -e \
    --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .estate_root == $estate and .route_database_state == "absent" and
     .public_ipv4_ipv6_closed_status == 404 and .runtime_verified == true and
     .services_activated == true and .ingress_opened == false' \
    "$predecessor_current_file" >/dev/null || \
    holdfast_die "successor recovery predecessor CURRENT is not eligible"
  predecessor_backup=$(jq -er '.backup_dir' "$predecessor_current_file")
  holdfast_require_absolute "$predecessor_backup"
  require_canonical_root_dir "$predecessor_backup"
  [[ -z "$(find "$predecessor_backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "successor recovery predecessor backup is not private"
  [[ -z "$(find "$predecessor_backup" -xdev -type l -print -quit)" ]] || \
    holdfast_die "successor recovery predecessor backup contains a symlink"
  [[ -z "$(find "$predecessor_backup" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "successor recovery predecessor backup contains a non-root-owned entry"
  for predecessor_file in \
    "$predecessor_backup/CONTROL.sha256" "$predecessor_backup/APPLY.receipt" \
    "$predecessor_backup/RELEASE-EVIDENCE.json" \
    "$predecessor_backup/runtime/BACKUP.receipt" \
    "$predecessor_backup/runtime/SHA256SUMS"; do
    require_root_file "$predecessor_file"
  done
  (cd "$predecessor_backup" && sha256sum --check CONTROL.sha256)
  (cd "$predecessor_backup/runtime" && sha256sum --check SHA256SUMS)
  predecessor_control_sha=$(holdfast_sha256 "$predecessor_backup/CONTROL.sha256")
  predecessor_apply_sha=$(holdfast_sha256 "$predecessor_backup/APPLY.receipt")
  predecessor_release_sha=$(holdfast_sha256 "$predecessor_backup/RELEASE-EVIDENCE.json")
  predecessor_runtime_receipt_sha=$(holdfast_sha256 "$predecessor_backup/runtime/BACKUP.receipt")
  predecessor_runtime_manifest_sha=$(holdfast_sha256 "$predecessor_backup/runtime/SHA256SUMS")
  if [[ "$successor_policy_version" == "4" ]]; then
    jq -e \
      --arg current "$predecessor_current_sha" --arg control "$predecessor_control_sha" \
      --arg apply "$predecessor_apply_sha" --arg release "$predecessor_release_sha" \
      --arg runtime "$predecessor_runtime_manifest_sha" '
      .predecessor.current_state_sha256 == $current and
      .predecessor.control_sha256 == $control and
      .predecessor.apply_receipt_sha256 == $apply and
      .predecessor.release_evidence_sha256 == $release and
      .predecessor.runtime_manifest_sha256 == $runtime' "$policy" >/dev/null || \
      holdfast_die "schema-v4 successor policy points to another predecessor authority"
    validate_no_predecessor_completion_namespace "$backup/RELEASE-EVIDENCE.json"
  fi
  if [[ "$verify_completed" == "true" ]]; then
    validate_verify_completed_predecessor_authority
  fi
  [[ "$(jq -er '.control_sha256' "$predecessor_current_file")" == "$predecessor_control_sha" && \
    "$(jq -er '.apply_receipt_sha256' "$predecessor_current_file")" == "$predecessor_apply_sha" && \
    "$(jq -er '.release_evidence_sha256' "$predecessor_current_file")" == "$predecessor_release_sha" ]] || \
    holdfast_die "successor recovery predecessor CURRENT authority differs"
  if jq -e 'has("runtime_backup_receipt_sha256")' "$predecessor_current_file" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_receipt_sha256' "$predecessor_current_file")" == \
      "$predecessor_runtime_receipt_sha" ]] || \
      holdfast_die "successor recovery predecessor runtime receipt differs"
  fi
  if jq -e 'has("runtime_backup_manifest_sha256")' "$predecessor_current_file" >/dev/null; then
    [[ "$(jq -er '.runtime_backup_manifest_sha256' "$predecessor_current_file")" == \
      "$predecessor_runtime_manifest_sha" ]] || \
      holdfast_die "successor recovery predecessor runtime manifest differs"
  fi
  predecessor_apply="$predecessor_backup/APPLY.receipt"
  if [[ "$successor_policy_version" == "4" ]]; then
    python3 "$script_dir/successor_binding.py" \
      --validate-gen4-lineage --current-state "$predecessor_current_file" \
      --estate-root "$estate_root" || \
      holdfast_die "schema-v4 predecessor CURRENT/APPLY lineage differs"
    validate_exact_receipt_keys "$predecessor_apply" \
      "schema-v4 predecessor APPLY" "${v4_predecessor_apply_keys[@]}"
    jq -e '
      .successor == true and .predecessor_release_generation == 3 and
      .release_generation == 4 and
      ([keys[] | select(startswith("predecessor_completion_"))] | sort) == [
        "predecessor_completion_attestation_sha256",
        "predecessor_completion_kind",
        "predecessor_completion_public_key_sha256",
        "predecessor_completion_signature_sha256"
      ] and (has("predecessor_apply_receipt_sha256") | not)' \
      "$predecessor_current_file" >/dev/null || \
      holdfast_die "schema-v4 predecessor CURRENT is not exact generation 3 -> 4 authority"
    [[ "$(holdfast_receipt_value "$predecessor_apply" successor)" == "true" && \
      "$(holdfast_receipt_value "$predecessor_apply" predecessor_release_generation)" == "3" && \
      "$(holdfast_receipt_value "$predecessor_apply" release_generation)" == "4" ]] || \
      holdfast_die "schema-v4 predecessor APPLY is not exact generation 3 -> 4 authority"
    validate_v3_completion_receipt_namespace "$predecessor_apply"
  fi
  for expected in \
    "schema_version=2" "completion_state=applied_ingress_closed" \
    "estate_root=$estate_root" "backup_dir=$predecessor_backup" \
    "control_sha256=$predecessor_control_sha" \
    "release_evidence_sha256=$predecessor_release_sha" \
    "runtime_backup=passed" "closed_bracket=passed" \
    "route_database_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "services_activated=true" "runtime_verified=true" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$predecessor_apply" "$key")" == "$value" ]] || \
      holdfast_die "successor recovery predecessor APPLY differs: $key"
  done
  [[ "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" schema_version)" == "2" && \
    "$(holdfast_receipt_value "$predecessor_backup/runtime/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
    holdfast_die "successor recovery predecessor runtime authority differs"
  predecessor_generation=$(jq -er '.release_generation // 1' "$predecessor_current_file")
  release_generation=$(holdfast_receipt_value "$successor_armed_receipt" release_generation)
  [[ "$predecessor_generation" =~ ^[1-9][0-9]*$ && \
    "$release_generation" =~ ^[1-9][0-9]*$ && \
    "$release_generation" -eq $((predecessor_generation + 1)) ]] || \
    holdfast_die "successor recovery generation linkage is invalid"
  if [[ "$successor_policy_version" == "4" ]]; then
    [[ "$predecessor_generation" == "4" && "$release_generation" == "5" ]] || \
      holdfast_die "schema-v4 successor recovery generation linkage is not exact 4 -> 5"
    [[ "$(jq -er '.predecessor.apply_receipt_sha256' "$policy")" == \
      "$predecessor_apply_sha" ]] || \
      holdfast_die "schema-v4 successor policy points to another predecessor APPLY"
  fi
  if [[ "$verify_completed" == "true" ]]; then
    successor_armed_at=$(holdfast_receipt_value "$successor_armed_receipt" armed_at)
    [[ "$successor_armed_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
      holdfast_die "successor recovery arm timestamp is not canonical UTC"
    normalized_successor_armed_at=$(date -u -d "$successor_armed_at" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || \
      holdfast_die "successor recovery arm timestamp is invalid"
    [[ "$normalized_successor_armed_at" == "$successor_armed_at" ]] || \
      holdfast_die "successor recovery arm timestamp is not canonical UTC"
    for expected in \
      "estate_root=$estate_root" \
      "candidate_dry_run_receipt_sha256=$dry_receipt_sha" \
      "candidate_release_evidence_sha256=$release_evidence_sha"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
        holdfast_die "successor recovery arm differs: $key"
    done
  fi
  for expected in \
    "schema_version=1" "successor_backup_dir=$backup" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation" "route_database_state=absent" \
    "public_ipv4_ipv6_closed_status=404" "predecessor_runtime_verified=true" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor recovery arm differs: $key"
  done
  if [[ "$successor_policy_version" == "4" ]]; then
    [[ "$(holdfast_receipt_value "$successor_armed_receipt" successor_policy_sha256)" == \
      "$(holdfast_sha256 "$policy")" ]] || \
      holdfast_die "schema-v4 successor recovery arm points to another policy"
  fi
  jq -e \
    --arg successor_sha "$successor_armed_sha" \
    --arg predecessor_sha "$predecessor_current_sha" \
    --arg predecessor_backup "$predecessor_backup" \
    --arg predecessor_control "$predecessor_control_sha" \
    --arg predecessor_apply "$predecessor_apply_sha" \
    --arg predecessor_release "$predecessor_release_sha" \
    --arg predecessor_runtime_receipt "$predecessor_runtime_receipt_sha" \
    --arg predecessor_runtime_manifest "$predecessor_runtime_manifest_sha" \
    --argjson predecessor_generation "$predecessor_generation" \
    --argjson generation "$release_generation" \
    '.successor == true and .successor_armed_receipt == "SUCCESSOR-ARMED.receipt" and
     .successor_armed_receipt_sha256 == $successor_sha and
     .predecessor_current_file == "PREDECESSOR-CURRENT.json" and
     .predecessor_current_sha256 == $predecessor_sha and
     .predecessor_backup_dir == $predecessor_backup and
     .predecessor_control_sha256 == $predecessor_control and
     .predecessor_apply_receipt_sha256 == $predecessor_apply and
     .predecessor_release_evidence_sha256 == $predecessor_release and
     .predecessor_runtime_backup_receipt_sha256 == $predecessor_runtime_receipt and
     .predecessor_runtime_backup_manifest_sha256 == $predecessor_runtime_manifest and
     .predecessor_release_generation == $predecessor_generation and
     .release_generation == $generation' "$pointer" >/dev/null || \
    holdfast_die "successor recovery CURRENT linkage differs"
  if [[ -f "$backup/RELEASE-EVIDENCE.json" && ! -L "$backup/RELEASE-EVIDENCE.json" ]]; then
    jq -e \
      --arg current "$predecessor_current_sha" \
      --arg control "$predecessor_control_sha" \
      --arg apply "$predecessor_apply_sha" \
      --arg release "$predecessor_release_sha" \
      --arg runtime "$predecessor_runtime_manifest_sha" \
      '.schema_version == 2 and .release_mode == "successor" and
       .predecessor_binding.current_state_sha256 == $current and
       .predecessor_binding.control_sha256 == $control and
       .predecessor_binding.apply_receipt_sha256 == $apply and
       .predecessor_binding.release_evidence_sha256 == $release and
       .predecessor_binding.runtime_manifest_sha256 == $runtime' \
      "$backup/RELEASE-EVIDENCE.json" >/dev/null || \
      holdfast_die "successor recovery RELEASE-EVIDENCE points to another predecessor"
  fi
  if [[ -f "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" ]]; then
    grep -Fqx "$predecessor_current_sha  PREDECESSOR-CURRENT.json" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits predecessor CURRENT"
    grep -Fqx "$successor_armed_sha  SUCCESSOR-ARMED.receipt" \
      "$backup/CONTROL.sha256" || holdfast_die "successor CONTROL omits successor arm"
  fi
}

restore_immediate_predecessor_current() {
  local archive=$1 temporary attempt armed_archive
  [[ "$successor_recovery" == "true" ]] || return 0
  if [[ -f "$state_file" && ! -L "$state_file" && \
    "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]]; then
    if [[ -e "$archive" || -L "$archive" ]]; then
      require_root_file "$archive"
      return 0
    fi
    [[ -n "${completed_state_match:-}" ]] || \
      holdfast_die "successor recovery predecessor CURRENT lacks its completion archive"
    [[ "$(basename -- "$archive")" =~ ^APPLY-RECOVERY-FINALIZED-STATE-([0-9]{8}T[0-9]{6}Z-[0-9]+)\.json$ ]] || \
      holdfast_die "successor recovery finalized archive name is unsafe"
    attempt=${BASH_REMATCH[1]}
    armed_archive="$state_dir/APPLY-RECOVERY-ARMED-STATE-${attempt}.json"
    require_root_file "$armed_archive"
    jq -e \
      --arg attempt "$attempt" --arg backup "$backup" \
      '.state == "apply_recovery_armed" and .recovery_mode == "restore" and
       .recovery_attempt_id == $attempt and .backup_dir == $backup' \
      "$armed_archive" >/dev/null || \
      holdfast_die "successor recovery armed-state archive differs"
    cmp -s \
      <(jq -S 'del(.state,.recovery_receipt,.recovery_receipt_sha256)' "$armed_archive") \
      <(jq -S 'del(.state,.recovery_receipt,.recovery_receipt_sha256)' "$completed_state_match") || \
      holdfast_die "successor recovery completion differs from its armed-state archive"
    return 0
  fi
  require_root_file "$state_file"
  if [[ -e "$archive" || -L "$archive" ]]; then
    require_root_file "$archive"
    [[ "$(holdfast_sha256 "$archive")" == "$(holdfast_sha256 "$state_file")" ]] || \
      holdfast_die "successor recovery state archive differs from active CURRENT"
  else
    temporary="$state_dir/.SUCCESSOR-STATE-ARCHIVE.$$"
    install -o 0 -g 0 -m 0600 -- "$state_file" "$temporary"
    commit_recovery_file "$temporary" "$archive"
  fi
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_SUCCESSOR_CURRENT_ARCHIVE:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  temporary="$state_dir/.PREDECESSOR-CURRENT.$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "predecessor CURRENT temporary path already exists"
  install -o 0 -g 0 -m 0600 -- "$predecessor_current_file" "$temporary"
  replace_recovery_file "$temporary" "$state_file"
  [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
    holdfast_die "successor recovery did not restore the immediate predecessor CURRENT"
}

append_successor_lineage_receipt_fields() {
  [[ "$successor_recovery" == "true" ]] || return 0
  printf 'successor=true\n'
  printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_sha"
  printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
  printf 'predecessor_backup_dir=%s\n' "$predecessor_backup"
  printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
  if [[ "$successor_policy_version" == "3" ]]; then
    printf 'predecessor_completion_kind=%s\n' "$predecessor_completion_kind"
    printf 'predecessor_completion_attestation_sha256=%s\n' "$predecessor_completion_attestation_sha"
    printf 'predecessor_completion_signature_sha256=%s\n' "$predecessor_completion_signature_sha"
    printf 'predecessor_completion_public_key_sha256=%s\n' "$predecessor_completion_public_key_sha"
  else
    printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_sha"
  fi
  printf 'predecessor_release_evidence_sha256=%s\n' "$predecessor_release_sha"
  printf 'predecessor_runtime_backup_receipt_sha256=%s\n' "$predecessor_runtime_receipt_sha"
  printf 'predecessor_runtime_backup_manifest_sha256=%s\n' "$predecessor_runtime_manifest_sha"
  printf 'predecessor_release_generation=%s\n' "$predecessor_generation"
  printf 'release_generation=%s\n' "$release_generation"
}

validate_successor_lineage_receipt() {
  local receipt=$1 expected key value
  local -a lineage_authority
  [[ "$successor_recovery" == "true" ]] || return 0
  require_root_file "$receipt"
  if [[ "$successor_policy_version" == "3" ]]; then
    lineage_authority=(
      "predecessor_completion_kind=$predecessor_completion_kind"
      "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha"
      "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha"
      "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha"
    )
    validate_v3_completion_receipt_namespace "$receipt"
    ! grep -Eq '^predecessor_apply_receipt_sha256=' "$receipt" || \
      holdfast_die "schema-v3 successor recovery receipt contains legacy APPLY authority"
  else
    lineage_authority=("predecessor_apply_receipt_sha256=$predecessor_apply_sha")
    if [[ "$successor_policy_version" == "4" ]]; then
      validate_no_predecessor_completion_namespace "$receipt"
    fi
  fi
  for expected in \
    "successor=true" "successor_armed_receipt_sha256=$successor_armed_sha" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "${lineage_authority[@]}" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=$predecessor_generation" \
    "release_generation=$release_generation"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "successor recovery receipt lineage differs: $key"
  done
}

validate_v3_apply_failure_completion_receipt() {
  local receipt=$1 expected key value
  require_root_file "$receipt"
  validate_v3_completion_receipt_namespace "$receipt"
  ! grep -Eq '^predecessor_apply_receipt_sha256=' "$receipt" || \
    holdfast_die "schema-v3 apply failure receipt contains legacy APPLY authority"
  for expected in \
    "predecessor_completion_kind=$predecessor_completion_kind" \
    "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
    "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
    "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v3 apply failure completion lineage differs: $key"
  done
}

validate_successor_persisted_supply_chain() {
  local require_control=${1:-true}
  local validator release_validator delta_sha relative authority_dir line digest
  local route_field route_relative route_expected file authority_count=0
  local -A seen_authorities=() v3_anchor_hashes=() v3_anchor_identities=()
  local -a v3_anchor_files=()
  [[ "$successor_recovery" == "true" ]] || return 0
  authority_dir="$backup/successor-authority"
  require_canonical_root_dir "$authority_dir"
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    v3_anchor_files=(
      "$authority_dir/successor-policy.json"
      "$authority_dir/Dockerfile.analyzer"
      "$authority_dir/bridge-package-lock.json"
      "$authority_dir/assets/20260823_rikune_root_up.sql"
      "$authority_dir/assets/20260823_rikune_root_down.sql"
      "$backup/PREDECESSOR-CURRENT.json"
      "$backup/SUCCESSOR-ARMED.receipt"
      "$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
      "$backup/RELEASE-EVIDENCE.json"
      "$backup/release.env"
      "$backup/DRY-RUN.receipt"
      "$backup/SUPPLY-CHAIN.json"
      "$backup/SUPPLY-CHAIN.sig"
      "$backup/SUPPLY-CHAIN.pub"
      "$backup/RENDER-INPUTS.sha256"
      "$backup/SUCCESSOR-DELTA.sha256"
    )
    if [[ "$successor_policy_version" == "3" ]]; then
      v3_anchor_files+=(
        "$backup/RECOVERY-COMPLETION-ATTESTATION.json"
        "$backup/RECOVERY-COMPLETION-ATTESTATION.sig"
        "$backup/RECOVERY-COMPLETION-ATTESTATION.pub"
      )
    fi
    if [[ "$require_control" == "true" ]]; then
      v3_anchor_files+=("$backup/CONTROL.sha256")
      if [[ -n "${control_sha:-}" && -n "${control_identity:-}" ]]; then
        require_root_file "$backup/CONTROL.sha256"
        [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$control_sha" && \
          "$(stat -c '%d:%i:%u:%h:%f' -- "$backup/CONTROL.sha256")" == \
            "$control_identity" ]] || \
          holdfast_die "schema-v3 CONTROL differs from the frozen recovery authority"
      fi
    fi
    for file in "${v3_anchor_files[@]}"; do
      require_root_file "$file"
      if [[ "$require_control" == "false" ]]; then
        [[ "$(stat -c '%a' -- "$file")" == "600" ]] || \
          holdfast_die "partial schema-v3 signed authority must have mode 0600: $file"
      fi
      v3_anchor_hashes["$file"]=$(holdfast_sha256 "$file")
      v3_anchor_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
    done
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "successor render-input authority contains an invalid line"
    digest=${BASH_REMATCH[1]}
    relative=${BASH_REMATCH[2]}
    [[ -z "${seen_authorities[$relative]+x}" ]] || \
      holdfast_die "successor render-input authority repeats a path"
    seen_authorities[$relative]=1
    require_root_file "$authority_dir/$relative"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      if [[ "$require_control" == "false" ]]; then
        [[ "$(stat -c '%a' -- "$authority_dir/$relative")" == "600" ]] || \
          holdfast_die "partial schema-v3 generation authority must have mode 0600: $relative"
      fi
      v3_anchor_hashes["$authority_dir/$relative"]=$(holdfast_sha256 "$authority_dir/$relative")
      v3_anchor_identities["$authority_dir/$relative"]=$(stat -c '%d:%i:%u:%h:%f' -- \
        "$authority_dir/$relative")
    fi
    [[ "$(holdfast_sha256 "$authority_dir/$relative")" == "$digest" ]] || \
      holdfast_die "successor generation authority differs from render inputs: $relative"
    if [[ "$require_control" == "true" ]]; then
      grep -Fqx "$digest  successor-authority/$relative" \
        "$backup/CONTROL.sha256" || \
        holdfast_die "successor CONTROL omits generation authority: $relative"
    fi
    authority_count=$((authority_count + 1))
  done <"$backup/RENDER-INPUTS.sha256"
  ((authority_count == 6)) || \
    holdfast_die "successor generation authority set is not exactly six files"
  for relative in Dockerfile.analyzer bridge-package-lock.json; do
    require_root_file "$authority_dir/$relative"
    if [[ "$require_control" == "true" ]]; then
      grep -Fqx "$(holdfast_sha256 "$authority_dir/$relative")  successor-authority/$relative" \
        "$backup/CONTROL.sha256" || \
        holdfast_die "successor CONTROL omits generation authority: $relative"
    fi
  done
  require_canonical_root_dir "$authority_dir/assets"
  for relative in 20260823_rikune_root_up.sql 20260823_rikune_root_down.sql; do
    require_root_file "$authority_dir/assets/$relative"
    if [[ "$require_control" == "true" ]]; then
      grep -Fqx "$(holdfast_sha256 "$authority_dir/assets/$relative")  successor-authority/assets/$relative" \
      "$backup/CONTROL.sha256" || \
        holdfast_die "successor CONTROL omits route authority: $relative"
    fi
  done
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    for route_field in route_up_sha256 route_down_sha256; do
      case "$route_field" in
        route_up_sha256) route_relative=20260823_rikune_root_up.sql ;;
        route_down_sha256) route_relative=20260823_rikune_root_down.sql ;;
      esac
      route_expected=$(jq -er --arg field "$route_field" \
        '.[$field] | select(type == "string" and test("^[0-9a-f]{64}$"))' \
        "$backup/RELEASE-EVIDENCE.json") || \
        holdfast_die "schema-v3 release evidence lacks route authority: $route_field"
      [[ "$route_expected" == \
        "$(holdfast_sha256 "$authority_dir/assets/$route_relative")" ]] || \
        holdfast_die "schema-v3 route authority differs: $route_field"
    done
  fi
  require_root_file "$backup/SUCCESSOR-DELTA.sha256"
  delta_sha=$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")
  [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" successor_delta_sha256)" == \
    "$delta_sha" && \
    "$(jq -er '.successor_delta_sha256' "$backup/RELEASE-EVIDENCE.json")" == \
    "$delta_sha" ]] || \
    holdfast_die "successor recovery delta authority differs"
  if [[ "$require_control" == "true" ]]; then
    grep -Fqx "$delta_sha  SUCCESSOR-DELTA.sha256" "$backup/CONTROL.sha256" || \
      holdfast_die "successor CONTROL omits the successor delta"
  else
    [[ ! -e "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" ]] || \
      holdfast_die "partial successor supply-chain authority unexpectedly has CONTROL"
  fi
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    release_validator=$(test_override \
      HOLDFAST_RELEASE_VALIDATOR_BIN "$script_dir/validate_release_evidence.py")
    run_python_tool "$release_validator" "$script_dir/validate_release_evidence.py" \
      --evidence "$backup/RELEASE-EVIDENCE.json" \
      --successor-policy "$authority_dir/successor-policy.json"
  fi
  validator=$(test_override HOLDFAST_SUPPLY_CHAIN_EVIDENCE_BIN "$script_dir/supply_chain_evidence.py")
  run_python_tool "$validator" "$script_dir/supply_chain_evidence.py" \
    --release-env "$backup/release.env" \
    --evidence "$backup/SUPPLY-CHAIN.json" \
    --signature "$backup/SUPPLY-CHAIN.sig" \
    --public-key "$backup/SUPPLY-CHAIN.pub" \
    --dockerfile "$authority_dir/Dockerfile.analyzer" \
    --bridge-lock "$authority_dir/bridge-package-lock.json" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --successor-policy "$authority_dir/successor-policy.json"
  if [[ "$require_control" == "true" ]]; then
    (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  else
    [[ "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" release_env_sha256)" == \
      "$(holdfast_sha256 "$backup/release.env")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" release_evidence_sha256)" == \
      "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" render_inputs_sha256)" == \
      "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" successor_delta_sha256)" == \
      "$(holdfast_sha256 "$backup/SUCCESSOR-DELTA.sha256")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" supply_chain_evidence_sha256)" == \
      "$(holdfast_sha256 "$backup/SUPPLY-CHAIN.json")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" supply_chain_signature_sha256)" == \
      "$(holdfast_sha256 "$backup/SUPPLY-CHAIN.sig")" && \
      "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" supply_chain_public_key_sha256)" == \
      "$(holdfast_sha256 "$backup/SUPPLY-CHAIN.pub")" && \
      "$(holdfast_receipt_value "$backup/SUCCESSOR-ARMED.receipt" successor_policy_sha256)" == \
      "$(holdfast_sha256 "$authority_dir/successor-policy.json")" ]] || \
      holdfast_die "partial successor signed authority changed during validation"
  fi
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    for file in "${!v3_anchor_hashes[@]}"; do
      require_root_file "$file"
      [[ "$(holdfast_sha256 "$file")" == "${v3_anchor_hashes[$file]}" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
          "${v3_anchor_identities[$file]}" ]] || \
        holdfast_die "schema-v3 signed authority changed during validation: $file"
    done
  fi
}

revalidate_v3_successor_authority() {
  local pointer=$1 pointer_sha expected_policy_version=$successor_policy_version
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  require_root_file "$pointer"
  pointer_sha=$(holdfast_sha256 "$pointer")
  load_successor_authority "$pointer"
  [[ "$successor_policy_version" == "$expected_policy_version" && \
    ( "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ) ]] || \
    holdfast_die "frozen successor recovery authority schema changed"
  validate_successor_persisted_supply_chain
  [[ "$(holdfast_sha256 "$pointer")" == "$pointer_sha" ]] || \
    holdfast_die "schema-v3 successor recovery pointer changed during validation"
}

validate_v3_cached_control_authority() {
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  require_root_file "$backup/CONTROL.sha256"
  [[ "$(holdfast_sha256 "$backup/CONTROL.sha256")" == "$control_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$backup/CONTROL.sha256")" == \
      "$control_identity" ]] || \
    holdfast_die "schema-v3 CONTROL changed before recovery mutation"
}

v3_completed_terminal_snapshot_active="false"
v3_completed_terminal_receipt=""
v3_completed_terminal_armed=""
v3_completed_terminal_state_sha=""
v3_completed_terminal_receipt_sha=""
v3_completed_terminal_armed_sha=""
v3_completed_terminal_state_identity=""
v3_completed_terminal_receipt_identity=""
v3_completed_terminal_armed_identity=""
v3_completed_terminal_current_sha=""
v3_completed_terminal_current_identity=""
v3_completed_terminal_candidate_scan_active="false"
v3_completed_terminal_candidate_state_dir_identity=""
v3_completed_terminal_candidate_files=()
declare -A v3_completed_terminal_candidate_hashes=() \
  v3_completed_terminal_candidate_identities=()

snapshot_v3_completed_terminal_candidate_namespace() {
  local candidate candidate_name
  v3_completed_terminal_candidate_files=()
  v3_completed_terminal_candidate_hashes=()
  v3_completed_terminal_candidate_identities=()
  require_canonical_root_dir "$state_dir"
  v3_completed_terminal_candidate_state_dir_identity=$(stat -c '%d:%i:%u:%f' -- \
    "$state_dir")
  while IFS= read -r candidate; do
    candidate_name=$(basename -- "$candidate")
    [[ "$candidate_name" =~ ^APPLY-RECOVERY-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.json$ ]] || \
      holdfast_die "schema-v3 completed recovery candidate has an unsafe name"
    require_root_file "$candidate"
    v3_completed_terminal_candidate_files+=("$candidate")
    v3_completed_terminal_candidate_hashes["$candidate"]=$(holdfast_sha256 "$candidate")
    v3_completed_terminal_candidate_identities["$candidate"]=$(stat -c '%d:%i:%u:%h:%f' -- \
      "$candidate")
  done < <(find "$state_dir" -mindepth 1 -maxdepth 1 \
    -name 'APPLY-RECOVERY-COMPLETE-*.json' -print | sort)
  v3_completed_terminal_candidate_scan_active="true"
}

validate_v3_completed_terminal_candidate_namespace() {
  local candidate index
  local -a current_candidates=()
  [[ "$v3_completed_terminal_candidate_scan_active" == "true" ]] || return 0
  require_canonical_root_dir "$state_dir"
  [[ "$(stat -c '%d:%i:%u:%f' -- "$state_dir")" == \
    "$v3_completed_terminal_candidate_state_dir_identity" ]] || \
    holdfast_die "completed recovery state directory changed during external validation"
  while IFS= read -r candidate; do current_candidates+=("$candidate"); done \
    < <(find "$state_dir" -mindepth 1 -maxdepth 1 \
      -name 'APPLY-RECOVERY-COMPLETE-*.json' -print | sort)
  ((${#current_candidates[@]} == ${#v3_completed_terminal_candidate_files[@]})) || \
    holdfast_die "schema-v3 completed recovery candidate namespace changed"
  for index in "${!v3_completed_terminal_candidate_files[@]}"; do
    [[ "${current_candidates[$index]}" == \
      "${v3_completed_terminal_candidate_files[$index]}" ]] || \
      holdfast_die "schema-v3 completed recovery candidate namespace changed"
  done
  for candidate in "${v3_completed_terminal_candidate_files[@]}"; do
    require_root_file "$candidate"
    [[ "$(holdfast_sha256 "$candidate")" == \
        "${v3_completed_terminal_candidate_hashes[$candidate]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$candidate")" == \
        "${v3_completed_terminal_candidate_identities[$candidate]}" ]] || \
      holdfast_die "schema-v3 completed recovery candidate changed during external validation"
  done
}

validate_v3_completed_terminal_core_fence() {
  local expected_current_sha=$1 expected_current_identity=$2
  validate_v3_completed_terminal_candidate_namespace
  [[ "$v3_completed_terminal_snapshot_active" == "true" ]] || return 0
  require_root_file "$state_file"
  require_root_file "$completed_state_match"
  require_root_file "$v3_completed_terminal_receipt"
  require_root_file "$v3_completed_terminal_armed"
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$expected_current_identity" && \
    "$(holdfast_sha256 "$completed_state_match")" == "$v3_completed_terminal_state_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$completed_state_match")" == \
      "$v3_completed_terminal_state_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_identity" ]] || \
    holdfast_die "schema-v3 completed recovery terminal core authority changed"
}

snapshot_v3_completed_terminal_authority() {
  local receipt_name armed_name
  [[ "$successor_recovery_v3" == "true" && -n "$completed_state_match" ]] || return 0
  if [[ "$v3_completed_terminal_snapshot_active" == "true" ]]; then
    validate_v3_completed_terminal_core_fence \
      "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
    return 0
  fi
  require_root_file "$state_file"
  require_root_file "$completed_state_match"
  receipt_name=$(jq -er '.recovery_receipt' "$completed_state_match")
  armed_name=$(jq -er '.recovery_armed_receipt' "$completed_state_match")
  [[ "$receipt_name" =~ ^APPLY-RECOVERY-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ && \
    "$armed_name" =~ ^APPLY-RECOVERY-ARMED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ ]] || \
    holdfast_die "schema-v3 completed recovery terminal authority has an unsafe receipt identity"
  v3_completed_terminal_receipt="$state_dir/$receipt_name"
  v3_completed_terminal_armed="$state_dir/$armed_name"
  require_root_file "$v3_completed_terminal_receipt"
  require_root_file "$v3_completed_terminal_armed"
  v3_completed_terminal_state_sha=$(holdfast_sha256 "$completed_state_match")
  v3_completed_terminal_receipt_sha=$(holdfast_sha256 "$v3_completed_terminal_receipt")
  v3_completed_terminal_armed_sha=$(holdfast_sha256 "$v3_completed_terminal_armed")
  v3_completed_terminal_state_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$completed_state_match")
  v3_completed_terminal_receipt_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
    "$v3_completed_terminal_receipt")
  v3_completed_terminal_armed_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
    "$v3_completed_terminal_armed")
  v3_completed_terminal_current_sha=$(holdfast_sha256 "$state_file")
  v3_completed_terminal_current_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")
  v3_completed_terminal_snapshot_active="true"
}

if [[ -e "$state_dir" || -L "$state_dir" ]]; then
  [[ -d "$state_dir" && ! -L "$state_dir" && "$(readlink -f -- "$state_dir")" == "$state_dir" ]] || \
    holdfast_die "state directory must be canonical and non-symlink"
  [[ "$(stat -c '%u' -- "$state_dir")" == "0" ]] || holdfast_die "state directory must be root-owned"
else
  [[ "$verify_completed" != "true" ]] || \
    holdfast_die "completed recovery verification requires an existing state directory"
  mkdir -p -- "$state_dir"
fi
if [[ "$verify_completed" == "true" ]]; then
  [[ -z "$(find "$state_dir" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "completed recovery verification requires a private state directory"
else
  chmod 0700 -- "$state_dir"
fi
require_canonical_root_dir "$state_dir"
require_canonical_root_dir "$backup"
[[ -z "$(find "$backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
  holdfast_die "backup directory must not be group/world accessible"
[[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || holdfast_die "backup contains a symlink"
[[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || holdfast_die "backup contains a non-root-owned entry"
[[ -z "$(find "$backup" -xdev ! -type d ! -type f -print -quit)" ]] || holdfast_die "backup contains a special file"
if [[ "$verify_completed" == "true" ]]; then
  snapshot_v3_completed_terminal_candidate_namespace
fi
backup_expected_successor=$(derive_backup_successor_mode)
validate_v3_completed_terminal_candidate_namespace

state_file="$state_dir/CURRENT.json"
completed_state_match=""
if [[ "$backup_expected_successor" == "true" ]]; then
  require_root_file "$backup/successor-authority/successor-policy.json"
  if [[ "$(jq -er '.schema_version' \
    "$backup/successor-authority/successor-policy.json")" =~ ^(3|4)$ ]]; then
    successor_recovery_v3="true"
    if [[ "$v3_completed_terminal_candidate_scan_active" != "true" ]]; then
      snapshot_v3_completed_terminal_candidate_namespace
    fi
  fi
fi
if [[ "$v3_completed_terminal_candidate_scan_active" == "true" ]]; then
  for completed_state in "${v3_completed_terminal_candidate_files[@]}"; do
    if [[ "$(jq -er --arg backup "$backup" \
      '.backup_dir == $backup and
       (.state == "apply_recovered_restored" or .state == "apply_recovered_resumed")' \
      "$completed_state" 2>/dev/null || true)" == "true" ]]; then
      [[ -z "$completed_state_match" ]] || \
        holdfast_die "multiple completion states exist for this backup"
      completed_state_match=$completed_state
    fi
  done
fi
if [[ "$successor_recovery_v3" == "true" ]]; then
  snapshot_v3_completed_terminal_authority
fi
runtime_caller_receipt="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
runtime_caller_sha=""
runtime_recovery_id=""
runtime_recovery_receipt=""
runtime_recovery_archive=""
runtime_dry_run_dir=""
runtime_prior_services=()
v3_partial_backup_entries=()
declare -A v3_partial_backup_hashes=() v3_partial_backup_identities=()
v3_partial_backup_root_identity=""

snapshot_v3_partial_backup_authority() {
  local path
  v3_partial_backup_entries=()
  v3_partial_backup_hashes=()
  v3_partial_backup_identities=()
  validate_v3_partial_backup_namespace
  v3_partial_backup_root_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$backup")
  while IFS= read -r -d '' path; do
    v3_partial_backup_entries+=("$path")
    v3_partial_backup_identities["$path"]=$(stat -c '%d:%i:%u:%h:%f' -- "$path")
    if [[ -f "$path" && ! -L "$path" ]]; then
      require_root_file "$path"
      v3_partial_backup_hashes["$path"]=$(holdfast_sha256 "$path")
    fi
  done < <(find "$backup" -xdev -mindepth 1 -print0 | sort -z)
  ((${#v3_partial_backup_entries[@]} > 0)) || \
    holdfast_die "partial schema-v3 backup authority is empty"
}

validate_v3_partial_backup_snapshot() {
  local path index
  local -a current_entries=()
  require_canonical_root_dir "$backup"
  [[ "$(stat -c '%d:%i:%u:%h:%f' -- "$backup")" == \
    "$v3_partial_backup_root_identity" ]] || \
    holdfast_die "partial schema-v3 backup root changed during recovery"
  validate_v3_partial_backup_namespace
  while IFS= read -r -d '' path; do current_entries+=("$path"); done \
    < <(find "$backup" -xdev -mindepth 1 -print0 | sort -z)
  ((${#current_entries[@]} == ${#v3_partial_backup_entries[@]})) || \
    holdfast_die "partial schema-v3 backup namespace changed during recovery"
  for index in "${!v3_partial_backup_entries[@]}"; do
    [[ "${current_entries[$index]}" == "${v3_partial_backup_entries[$index]}" ]] || \
      holdfast_die "partial schema-v3 backup namespace changed during recovery"
  done
  for path in "${v3_partial_backup_entries[@]}"; do
    [[ "$(stat -c '%d:%i:%u:%h:%f' -- "$path")" == \
      "${v3_partial_backup_identities[$path]}" ]] || \
      holdfast_die "partial schema-v3 backup entry changed during recovery: $path"
    if [[ -n "${v3_partial_backup_hashes[$path]+x}" ]]; then
      require_root_file "$path"
      [[ "$(holdfast_sha256 "$path")" == "${v3_partial_backup_hashes[$path]}" ]] || \
        holdfast_die "partial schema-v3 backup file changed during recovery: $path"
    fi
  done
}

validate_runtime_caller_authority() {
  local pointer=$1 expected key value caller_estate caller_backup caller_runtime
  local release_sha evidence_sha dry_sha targets_sha preimages_sha absent_sha render_sha
  local pointer_sha
  require_root_file "$pointer"
  pointer_sha=$(holdfast_sha256 "$pointer")
  require_root_file "$runtime_caller_receipt"
  runtime_caller_sha=$(holdfast_sha256 "$runtime_caller_receipt")
  runtime_recovery_id=${runtime_caller_sha:0:24}
  runtime_recovery_receipt="$state_dir/RUNTIME-BACKUP-RECOVERY-COMPLETE-${runtime_recovery_id}.receipt"
  runtime_recovery_archive="$state_dir/RUNTIME-BACKUP-ABORTED-${runtime_recovery_id}.json"

  caller_estate=$(holdfast_receipt_value "$runtime_caller_receipt" estate_root)
  caller_backup=$(holdfast_receipt_value "$runtime_caller_receipt" backup_dir)
  runtime_dry_run_dir=$(holdfast_receipt_value "$runtime_caller_receipt" dry_run_dir)
  caller_runtime=$(holdfast_receipt_value "$runtime_caller_receipt" runtime_backup_dir)
  for path in "$caller_estate" "$caller_backup" "$runtime_dry_run_dir" "$caller_runtime"; do
    holdfast_require_absolute "$path"
  done
  [[ "$caller_backup" == "$backup" && "$caller_runtime" == "$backup/runtime" ]] || \
    holdfast_die "runtime backup caller authority points to another backup"
  if [[ -n "$estate_root" && "$estate_root" != "$caller_estate" ]]; then
    holdfast_die "requested estate root differs from runtime backup caller authority"
  fi
  estate_root=$caller_estate

  release_sha=$(holdfast_receipt_value "$runtime_caller_receipt" release_env_sha256)
  evidence_sha=$(holdfast_receipt_value "$runtime_caller_receipt" release_evidence_sha256)
  dry_sha=$(holdfast_receipt_value "$runtime_caller_receipt" dry_run_receipt_sha256)
  targets_sha=$(holdfast_receipt_value "$runtime_caller_receipt" targets_sha256)
  preimages_sha=$(holdfast_receipt_value "$runtime_caller_receipt" apply_preimages_sha256)
  absent_sha=$(holdfast_receipt_value "$runtime_caller_receipt" apply_absent_sha256)
  render_sha=$(holdfast_receipt_value "$runtime_caller_receipt" render_inputs_sha256)
  for value in "$runtime_caller_sha" "$release_sha" "$evidence_sha" "$dry_sha" \
    "$targets_sha" "$preimages_sha" "$absent_sha" "$render_sha"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || holdfast_die "runtime backup caller authority has an invalid digest"
  done
  for expected in \
    "schema_version=2" "estate_root=$estate_root" "dry_run_dir=$runtime_dry_run_dir" \
    "backup_dir=$backup" "runtime_backup_dir=$backup/runtime" \
    "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt" \
    "stop_authority_contract=absence-means-stop-not-started" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$runtime_caller_receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup caller authority differs: $key"
  done
  jq -e \
    --arg estate "$estate_root" --arg backup "$backup" --arg dry "$runtime_dry_run_dir" \
    --arg runtime "$backup/runtime" --arg caller_sha "$runtime_caller_sha" \
    --arg release_sha "$release_sha" --arg evidence_sha "$evidence_sha" \
    --arg dry_sha "$dry_sha" --arg targets_sha "$targets_sha" \
    --arg preimages_sha "$preimages_sha" --arg absent_sha "$absent_sha" \
    --arg render_sha "$render_sha" \
    '.schema_version == 2 and .state == "runtime_backup_armed" and
     .estate_root == $estate and .backup_dir == $backup and .dry_run_dir == $dry and
     .runtime_backup_dir == $runtime and
     .runtime_backup_caller_armed_receipt == "RUNTIME-BACKUP-CALLER-ARMED.receipt" and
     .runtime_backup_caller_armed_receipt_sha256 == $caller_sha and
     .runtime_backup_armed_receipt == "runtime/RUNTIME-BACKUP-ARMED.receipt" and
     .release_env_sha256 == $release_sha and .release_evidence_sha256 == $evidence_sha and
     .dry_run_receipt_sha256 == $dry_sha and .targets_sha256 == $targets_sha and
     .apply_preimages_sha256 == $preimages_sha and .apply_absent_sha256 == $absent_sha and
     .render_inputs_sha256 == $render_sha and
     .stop_authority_contract == "absence-means-stop-not-started" and .ingress_opened == false' \
    "$pointer" >/dev/null || holdfast_die "runtime backup caller state differs from its authority"
  load_successor_authority "$pointer"
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    if [[ -f "$backup/CONTROL.sha256" && ! -L "$backup/CONTROL.sha256" ]]; then
      validate_successor_persisted_supply_chain true
    else
      validate_successor_persisted_supply_chain false
    fi
    for key in release_env_sha256 release_evidence_sha256 targets_sha256 \
      apply_preimages_sha256 apply_absent_sha256 render_inputs_sha256; do
      [[ "$(holdfast_receipt_value "$runtime_caller_receipt" "$key")" == \
        "$(holdfast_receipt_value "$backup/DRY-RUN.receipt" "$key")" ]] || \
        holdfast_die "runtime backup caller differs from frozen dry-run authority: $key"
    done
    [[ "$dry_sha" == "$(holdfast_sha256 "$backup/DRY-RUN.receipt")" ]] || \
      holdfast_die "runtime backup caller points to another frozen dry-run authority"
    [[ "$runtime_caller_sha" == "$(holdfast_sha256 "$runtime_caller_receipt")" && \
      "$pointer_sha" == "$(holdfast_sha256 "$pointer")" ]] || \
      holdfast_die "runtime backup caller authority changed during validation"
  fi
  validate_v3_completed_terminal_core_fence \
    "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
}

validate_runtime_stop_authority() {
  local arm="$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
  local manifest="$backup/runtime/RUNNING-SERVICES.before"
  local config="$backup/runtime/compose-config.json"
  local compose_project expected key value init_state previous=-1 service index
  require_canonical_root_dir "$backup/runtime"
  require_root_file "$arm"
  require_root_file "$manifest"
  require_root_file "$config"
  compose_project=$(jq -er '.name' "$config")
  [[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
    holdfast_die "runtime backup stop authority has an unsafe Compose project"
  for expected in \
    "schema_version=2" "backup_dir=$backup/runtime" "compose_project=$compose_project" \
    "compose_config_sha256=$(holdfast_sha256 "$config")" \
    "database_identity=postgres:5432/strad" \
    "prior_running_services_manifest=RUNNING-SERVICES.before" \
    "prior_running_services_sha256=$(holdfast_sha256 "$manifest")" \
    "runtime_writer_count=3" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "stop_authority=armed-before-writer-stop"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$arm" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup stop authority differs: $key"
  done
  init_state=$(holdfast_receipt_value "$arm" volume_init_prior_state)
  [[ "$init_state" == "absent" || "$init_state" == "created" || \
    "$init_state" == "exited" || "$init_state" == "dead" ]] || \
    holdfast_die "runtime backup stop authority has an active volume initializer"
  runtime_prior_services=()
  while IFS= read -r service || [[ -n "$service" ]]; do
    [[ -n "$service" ]] || holdfast_die "runtime prior-running manifest contains a blank service"
    case "$service" in
      strad) index=0 ;;
      rikune-analyzer) index=1 ;;
      *) holdfast_die "runtime prior-running manifest contains an unknown service: $service" ;;
    esac
    ((index > previous)) || \
      holdfast_die "runtime prior-running manifest is duplicated or out of order"
    previous=$index
    runtime_prior_services+=("$service")
  done <"$manifest"
}

validate_runtime_backup_success_authority() {
  local arm="$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
  local manifest="$backup/runtime/RUNNING-SERVICES.before"
  local receipt="$backup/runtime/BACKUP.receipt" checksums="$backup/runtime/SHA256SUMS"
  local expected key value
  if [[ ! -e "$receipt" && ! -L "$receipt" ]]; then
    if [[ -e "$checksums" || -L "$checksums" ]]; then require_root_file "$checksums"; fi
    return 0
  fi
  require_root_file "$receipt"
  require_root_file "$checksums"
  for expected in \
    "schema_version=2" "database_identity=postgres:5432/strad" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "prior_running_services_manifest=RUNNING-SERVICES.before" \
    "prior_running_services_sha256=$(holdfast_sha256 "$manifest")" \
    "runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt" \
    "runtime_backup_armed_sha256=$(holdfast_sha256 "$arm")" \
    "isolated_restore_probe=passed"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup success authority differs: $key"
  done
  [[ "$(holdfast_receipt_value "$receipt" runtime_writers_stopped)" == "passed" ]] || \
    holdfast_die "runtime backup did not prove stopped writers"
  [[ "$(holdfast_receipt_value "$receipt" writers_left_quiesced)" == "passed" ]] || \
    holdfast_die "runtime backup did not leave writers quiesced"
  grep -Fqx "$(holdfast_sha256 "$arm")  RUNTIME-BACKUP-ARMED.receipt" "$checksums" || \
    holdfast_die "runtime backup checksums do not bind the stop authority"
  grep -Fqx "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" "$checksums" || \
    holdfast_die "runtime backup checksums do not bind the prior-running manifest"
  validate_runtime_checksum_manifest
  (cd "$backup/runtime" && sha256sum --check SHA256SUMS)
}

validate_runtime_checksum_manifest() {
  local line name
  declare -A seen=()
  require_root_file "$backup/runtime/SHA256SUMS"
  while IFS= read -r line; do
    [[ "$line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "runtime checksum manifest contains an unsafe line"
    name=${BASH_REMATCH[1]}
    [[ -z "${seen[$name]:-}" ]] || holdfast_die "runtime checksum manifest contains a duplicate path"
    seen[$name]=1
  done <"$backup/runtime/SHA256SUMS"
  ((${#seen[@]} > 0)) || holdfast_die "runtime checksum manifest is empty"
}

validate_runtime_compensation_authority() {
  local passed="$backup/runtime/RUNTIME-BACKUP-COMPENSATED.receipt"
  local failed="$backup/runtime/RUNTIME-BACKUP-COMPENSATION-FAILED.receipt"
  local receipt result expected key value
  [[ ! ( -e "$passed" && -e "$failed" ) ]] || \
    holdfast_die "runtime backup has conflicting compensation receipts"
  if [[ -e "$passed" || -L "$passed" ]]; then receipt=$passed; result=passed
  elif [[ -e "$failed" || -L "$failed" ]]; then receipt=$failed; result=failed
  else return 0
  fi
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" \
    "runtime_backup_armed_sha256=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" \
    "prior_running_services_sha256=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" \
    "prior_running_services_restored=$result" \
    "excluded_runtime_services_inactive=$result" "volume_init_inactive=$result"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup compensation authority differs: $key"
  done
}

validate_runtime_partial_boundary_authority() {
  local arm_state=$1
  case "$arm_state" in
    present)
      validate_runtime_stop_authority
      validate_runtime_backup_success_authority
      validate_runtime_compensation_authority
      ;;
    not-created)
      [[ ! -e "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" && \
        ! -L "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" && \
        ! -e "$backup/runtime/BACKUP.receipt" && \
        ! -L "$backup/runtime/BACKUP.receipt" ]] || \
        holdfast_die "runtime backup authority exists despite not-created disposition"
      ;;
    *) holdfast_die "runtime backup boundary has an invalid stop authority" ;;
  esac
}

runtime_service_was_running() {
  local wanted=$1 service
  for service in "${runtime_prior_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

restore_runtime_prior_subset() {
  local config="$backup/runtime/compose-config.json" service output state health ready
  local compose=("$docker_bin" compose -f "$config")
  local ids=() excluded=() stop_services=(rikune-volume-init)
  "${compose[@]}" config --quiet
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    validate_v3_partial_backup_snapshot
  fi
  for service in strad rikune-analyzer; do
    if ! runtime_service_was_running "$service"; then
      excluded+=("$service")
      stop_services+=("$service")
    fi
  done
  "${compose[@]}" stop -t 120 "${stop_services[@]}" >/dev/null
  if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
    validate_v3_partial_backup_snapshot
  fi
  if ((${#runtime_prior_services[@]})); then
    "${compose[@]}" start "${runtime_prior_services[@]}" >/dev/null
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_v3_partial_backup_snapshot
    fi
  fi
  ready=false
  for _ in $(seq 1 60); do
    ready=true
    for service in "${runtime_prior_services[@]}"; do
      output=$("${compose[@]}" ps -aq "$service")
      ids=()
      if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
      if ((${#ids[@]} != 1)); then ready=false; continue; fi
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
      health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}")
      if [[ "$state" != "running" || ( "$health" != "none" && "$health" != "healthy" ) ]]; then
        ready=false
      fi
    done
    [[ "$ready" == "true" ]] && break
    sleep 5
  done
  [[ "$ready" == "true" ]] || holdfast_die "runtime prior-running subset did not become healthy"
  for service in "${excluded[@]}" rikune-volume-init; do
    output=$("${compose[@]}" ps -aq "$service")
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple excluded runtime containers exist: $service"
    for container_id in "${ids[@]}"; do
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "excluded runtime service remains active: $service"
    done
  done
}

verify_runtime_prior_subset_disposition() {
  local config="$backup/runtime/compose-config.json" service output state health container_id
  local compose=("$docker_bin" compose -f "$config")
  local -a ids=()
  "${compose[@]}" config --quiet
  for service in strad rikune-analyzer; do
    output=$("${compose[@]}" ps -aq "$service")
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple runtime containers exist: $service"
    if runtime_service_was_running "$service"; then
      ((${#ids[@]} == 1)) || holdfast_die "restored runtime service disappeared: $service"
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
      health=$("$docker_bin" inspect -f \
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}")
      [[ "$state" == "running" && ( "$health" == "none" || "$health" == "healthy" ) ]] || \
        holdfast_die "restored runtime service is not healthy: $service"
    else
      for container_id in "${ids[@]}"; do
        state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
        [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
          holdfast_die "excluded runtime service became active: $service"
      done
    fi
  done
  output=$("${compose[@]}" ps -aq rikune-volume-init)
  ids=()
  if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
  ((${#ids[@]} <= 1)) || holdfast_die "multiple runtime volume initializers exist"
  for container_id in "${ids[@]}"; do
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
    [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
      holdfast_die "runtime volume initializer became active"
  done
}

record_runtime_caller_cleanup() {
  local arm_state=$1 arm_sha=not-created manifest_sha=not-created success_sha=not-created
  local result=not-required receipt="$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
  local temporary="$backup/.RUNTIME-BACKUP-CALLER-CLEANUP.receipt.$$" expected key value reason
  if [[ "$arm_state" == "present" ]]; then
    arm_sha=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")
    manifest_sha=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")
    result=passed
  fi
  if [[ -f "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]]; then
    success_sha=$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")
  fi
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    require_root_file "$receipt"
  else
    {
      printf 'schema_version=2\n'
      printf 'cleaned_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'cleanup_reason=apply-recover-runtime-backup-arm\n'
      printf 'runtime_backup_caller_armed_sha256=%s\n' "$runtime_caller_sha"
      printf 'runtime_stop_authority=%s\n' "$arm_state"
      printf 'runtime_backup_armed_sha256=%s\n' "$arm_sha"
      printf 'prior_running_services_sha256=%s\n' "$manifest_sha"
      printf 'runtime_backup_success_receipt_sha256=%s\n' "$success_sha"
      printf 'prior_running_services_restored=%s\n' "$result"
      printf 'excluded_runtime_services_inactive=%s\n' "$result"
      printf 'volume_init_inactive=%s\n' "$result"
      printf 'cleanup_status=passed\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_recovery_file "$temporary" "$receipt"
  fi
  reason=$(holdfast_receipt_value "$receipt" cleanup_reason)
  [[ "$reason" == "apply-recover-runtime-backup-arm" || "$reason" == "prearm_failure" || \
    "$reason" == "reentry" ]] || holdfast_die "runtime backup caller cleanup reason differs"
  for expected in \
    "schema_version=2" "runtime_backup_caller_armed_sha256=$runtime_caller_sha" \
    "runtime_stop_authority=$arm_state" "runtime_backup_armed_sha256=$arm_sha" \
    "prior_running_services_sha256=$manifest_sha" \
    "runtime_backup_success_receipt_sha256=$success_sha" \
    "prior_running_services_restored=$result" \
    "excluded_runtime_services_inactive=$result" "volume_init_inactive=$result" \
    "cleanup_status=passed" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup caller cleanup authority differs: $key"
  done
}

validate_runtime_recovery_completion() {
  local original_state_sha cleanup_sha arm_state expected key value old_apply_resumed
  require_root_file "$runtime_recovery_receipt"
  require_root_file "$runtime_recovery_archive"
  require_root_file "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
  original_state_sha=$(holdfast_sha256 "$runtime_recovery_archive")
  cleanup_sha=$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")
  arm_state=$(holdfast_receipt_value "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt" runtime_stop_authority)
  old_apply_resumed="false"
  [[ "$successor_recovery" == "true" ]] && old_apply_resumed="true"
  [[ "$arm_state" == "present" || "$arm_state" == "not-created" ]] || \
    holdfast_die "runtime backup recovery cleanup has an invalid stop authority"
  validate_recovery_route_contract \
    "$runtime_recovery_receipt" "runtime backup recovery completion"
  for expected in \
    "recovery_id=$runtime_recovery_id" \
    "estate_root=$estate_root" "backup_dir=$backup" \
    "runtime_stop_authority=$arm_state" \
    "runtime_backup_caller_armed_sha256=$runtime_caller_sha" \
    "original_state_sha256=$original_state_sha" \
    "runtime_backup_caller_cleanup_sha256=$cleanup_sha" \
    "active_state_archive=$(basename -- "$runtime_recovery_archive")" \
    "old_apply_resumed=$old_apply_resumed" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup recovery completion differs: $key"
  done
  if [[ "$successor_recovery" == "true" ]]; then
    for expected in \
      "successor_armed_receipt_sha256=$successor_armed_sha" \
      "predecessor_current_sha256=$predecessor_current_sha" \
      "predecessor_backup_dir=$predecessor_backup" \
      "predecessor_control_sha256=$predecessor_control_sha"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
        holdfast_die "runtime backup successor recovery completion differs: $key"
    done
    if [[ "$successor_policy_version" == "3" ]]; then
      validate_v3_completion_receipt_namespace "$runtime_recovery_receipt"
      ! grep -Eq '^predecessor_apply_receipt_sha256=' "$runtime_recovery_receipt" || \
        holdfast_die "schema-v3 runtime recovery completion contains legacy APPLY authority"
      for expected in \
        "predecessor_completion_kind=$predecessor_completion_kind" \
        "predecessor_completion_attestation_sha256=$predecessor_completion_attestation_sha" \
        "predecessor_completion_signature_sha256=$predecessor_completion_signature_sha" \
        "predecessor_completion_public_key_sha256=$predecessor_completion_public_key_sha"; do
        key=${expected%%=*}
        value=${expected#*=}
        [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
          holdfast_die "runtime backup recovery completion lineage differs: $key"
      done
    else
      if [[ "$successor_policy_version" == "4" ]]; then
        validate_no_predecessor_completion_namespace "$runtime_recovery_receipt"
      fi
      [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" predecessor_apply_receipt_sha256)" == \
        "$predecessor_apply_sha" ]] || \
        holdfast_die "runtime backup successor recovery completion differs: predecessor_apply_receipt_sha256"
    fi
    for expected in \
      "predecessor_release_evidence_sha256=$predecessor_release_sha" \
      "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
      "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
        holdfast_die "runtime backup successor recovery completion differs: $key"
    done
    [[ -f "$state_file" && ! -L "$state_file" && \
      "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
      holdfast_die "runtime backup successor recovery did not retain predecessor CURRENT"
  fi
}

complete_runtime_caller_recovery() {
  local arm_state=$1 original_state_sha cleanup_sha temporary expected key value
  local old_apply_resumed="false"
  [[ "$successor_recovery" == "true" ]] && old_apply_resumed="true"
  cleanup_sha=$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")
  if [[ -e "$runtime_recovery_archive" || -L "$runtime_recovery_archive" ]]; then
    require_root_file "$runtime_recovery_archive"
    original_state_sha=$(holdfast_sha256 "$runtime_recovery_archive")
    if [[ "$successor_recovery" == "true" ]]; then
      restore_immediate_predecessor_current "$runtime_recovery_archive"
    else
      [[ ! -e "$state_file" && ! -L "$state_file" ]] || \
        holdfast_die "runtime backup recovery archive has an unexpected active CURRENT"
    fi
  else
    original_state_sha=$(holdfast_sha256 "$state_file")
    if [[ "$successor_recovery" == "true" ]]; then
      restore_immediate_predecessor_current "$runtime_recovery_archive"
    else
      mv -T -- "$state_file" "$runtime_recovery_archive"
      sync -f "$runtime_recovery_archive"
      sync -f "$state_dir"
    fi
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_PREDECESSOR_CURRENT_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  fi
  if [[ -e "$runtime_recovery_receipt" || -L "$runtime_recovery_receipt" ]]; then
    require_root_file "$runtime_recovery_receipt"
    validate_recovery_route_contract \
      "$runtime_recovery_receipt" "runtime backup pending recovery completion"
    for expected in \
      "recovery_id=$runtime_recovery_id" \
      "estate_root=$estate_root" "backup_dir=$backup" \
      "runtime_stop_authority=$arm_state" \
      "runtime_backup_caller_armed_sha256=$runtime_caller_sha" \
      "original_state_sha256=$original_state_sha" \
      "runtime_backup_caller_cleanup_sha256=$cleanup_sha" \
      "active_state_archive=$(basename -- "$runtime_recovery_archive")" \
      "old_apply_resumed=$old_apply_resumed" "ingress_opened=false"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
        holdfast_die "runtime backup pending recovery completion differs: $key"
    done
  else
    temporary="$state_dir/.RUNTIME-BACKUP-RECOVERY-COMPLETE.$$"
    {
      printf 'schema_version=%s\n' "$(recovery_receipt_schema_version)"
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'recovery_id=%s\n' "$runtime_recovery_id"
      printf 'estate_root=%s\n' "$estate_root"
      printf 'backup_dir=%s\n' "$backup"
      printf 'runtime_stop_authority=%s\n' "$arm_state"
      printf 'runtime_backup_caller_armed_sha256=%s\n' "$runtime_caller_sha"
      printf 'original_state_sha256=%s\n' "$original_state_sha"
      printf 'runtime_backup_caller_cleanup_sha256=%s\n' "$cleanup_sha"
      printf 'active_state_archive=%s\n' "$(basename -- "$runtime_recovery_archive")"
      append_recovery_route_contract_fields
      printf 'old_apply_resumed=%s\n' "$old_apply_resumed"
      if [[ "$successor_recovery" == "true" ]]; then
        printf 'successor_armed_receipt_sha256=%s\n' "$successor_armed_sha"
        printf 'predecessor_current_sha256=%s\n' "$predecessor_current_sha"
        printf 'predecessor_backup_dir=%s\n' "$predecessor_backup"
        printf 'predecessor_control_sha256=%s\n' "$predecessor_control_sha"
        if [[ "$successor_policy_version" == "3" ]]; then
          printf 'predecessor_completion_kind=%s\n' "$predecessor_completion_kind"
          printf 'predecessor_completion_attestation_sha256=%s\n' "$predecessor_completion_attestation_sha"
          printf 'predecessor_completion_signature_sha256=%s\n' "$predecessor_completion_signature_sha"
          printf 'predecessor_completion_public_key_sha256=%s\n' "$predecessor_completion_public_key_sha"
        else
          printf 'predecessor_apply_receipt_sha256=%s\n' "$predecessor_apply_sha"
        fi
        printf 'predecessor_release_evidence_sha256=%s\n' "$predecessor_release_sha"
        printf 'predecessor_runtime_backup_receipt_sha256=%s\n' "$predecessor_runtime_receipt_sha"
        printf 'predecessor_runtime_backup_manifest_sha256=%s\n' "$predecessor_runtime_manifest_sha"
      fi
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_recovery_file "$temporary" "$runtime_recovery_receipt"
  fi
  validate_runtime_recovery_completion
}

# runtime-backup may be killed after its caller has durably armed CURRENT but
# before apply can persist a full CONTROL-bound backup.  Recover that boundary
# before requiring the normal apply artifacts below.  This branch restores only
# the exact pre-backup product subset; it never restores DB, volumes, or estate.
if [[ "$verify_completed" != "true" && \
  -f "$runtime_caller_receipt" && ! -L "$runtime_caller_receipt" ]]; then
  runtime_caller_sha=$(holdfast_sha256 "$runtime_caller_receipt")
  runtime_recovery_id=${runtime_caller_sha:0:24}
  runtime_recovery_receipt="$state_dir/RUNTIME-BACKUP-RECOVERY-COMPLETE-${runtime_recovery_id}.receipt"
  runtime_recovery_archive="$state_dir/RUNTIME-BACKUP-ABORTED-${runtime_recovery_id}.json"
  if [[ -e "$runtime_recovery_receipt" || -L "$runtime_recovery_receipt" ]]; then
    [[ -e "$runtime_recovery_archive" || -L "$runtime_recovery_archive" ]] || \
      holdfast_die "runtime backup recovery receipt lacks its state archive"
  fi
  if [[ -e "$runtime_recovery_archive" || -L "$runtime_recovery_archive" ]]; then
    [[ "$mode" == "restore" && "$legacy_empty_strad" == "false" ]] || \
      holdfast_die "runtime backup recovery completion requires non-legacy restore mode"
    validate_runtime_caller_authority "$runtime_recovery_archive"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_v3_partial_backup_namespace
    fi
    if [[ "$successor_recovery" == "true" ]]; then
      require_root_file "$state_file"
      [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" || \
        "$(holdfast_sha256 "$state_file")" == "$(holdfast_sha256 "$runtime_recovery_archive")" ]] || \
        holdfast_die "successor runtime recovery CURRENT differs from predecessor and archive"
    else
      [[ ! -e "$state_file" && ! -L "$state_file" ]] || \
        holdfast_die "completed first-apply runtime recovery unexpectedly has CURRENT"
    fi
    require_root_file "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
    runtime_arm_state=$(holdfast_receipt_value \
      "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt" runtime_stop_authority)
    [[ "$runtime_arm_state" == "present" || "$runtime_arm_state" == "not-created" ]] || \
      holdfast_die "runtime backup recovery cleanup has an invalid stop authority"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_runtime_partial_boundary_authority "$runtime_arm_state"
    fi
    record_runtime_caller_cleanup "$runtime_arm_state"
    if [[ ! -e "$runtime_recovery_receipt" && ! -L "$runtime_recovery_receipt" ]]; then
      complete_runtime_caller_recovery "$runtime_arm_state"
    fi
    validate_runtime_recovery_completion
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      snapshot_v3_partial_backup_authority
      runtime_terminal_receipt_sha=$(holdfast_sha256 "$runtime_recovery_receipt")
      runtime_terminal_archive_sha=$(holdfast_sha256 "$runtime_recovery_archive")
      runtime_terminal_cleanup_sha=$(holdfast_sha256 \
        "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")
      runtime_terminal_current_sha=$(holdfast_sha256 "$state_file")
    fi
    verify_closed_bracket
    validate_runtime_caller_authority "$runtime_recovery_archive"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_runtime_partial_boundary_authority "$runtime_arm_state"
      validate_v3_partial_backup_snapshot
      [[ "$runtime_terminal_receipt_sha" == \
        "$(holdfast_sha256 "$runtime_recovery_receipt")" && \
        "$runtime_terminal_archive_sha" == \
        "$(holdfast_sha256 "$runtime_recovery_archive")" && \
        "$runtime_terminal_cleanup_sha" == \
        "$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")" && \
        "$runtime_terminal_current_sha" == "$(holdfast_sha256 "$state_file")" ]] || \
        holdfast_die "schema-v3 runtime backup terminal authority changed during validation"
      validate_runtime_recovery_completion
    fi
    if [[ "$successor_recovery" == "true" ]]; then
      [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]] || \
        holdfast_die "runtime backup recovery terminal CURRENT changed during validation"
    fi
    echo "previously completed runtime backup recovery verified; rerun apply with a fresh ceremony"
    exit 0
  fi
fi
if [[ "$verify_completed" != "true" && ( -e "$state_file" || -L "$state_file" ) ]]; then
  require_root_file "$state_file"
  current_state=$(jq -er '.state' "$state_file")
  if [[ "$current_state" == "runtime_backup_armed" ]]; then
    [[ "$mode" == "restore" && "$legacy_empty_strad" == "false" ]] || \
      holdfast_die "runtime backup recovery requires non-legacy restore mode"
    runtime_arm_state=not-created
    if [[ -e "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" || \
      -L "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" ]]; then
      runtime_arm_state=present
    fi
    validate_runtime_caller_authority "$state_file"
    partial_current_sha=""
    partial_current_identity=""
    partial_caller_sha=""
    partial_caller_identity=""
    partial_arm_sha="not-created"
    partial_arm_identity="not-created"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      snapshot_v3_partial_backup_authority
      require_root_file "$state_file"
      require_root_file "$runtime_caller_receipt"
      partial_current_sha=$(holdfast_sha256 "$state_file")
      partial_current_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")
      partial_caller_sha=$(holdfast_sha256 "$runtime_caller_receipt")
      partial_caller_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$runtime_caller_receipt")
      if [[ "$runtime_arm_state" == "present" ]]; then
        require_root_file "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
        partial_arm_sha=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")
        partial_arm_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
          "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")
      fi
    fi
    verify_closed_bracket
    validate_runtime_caller_authority "$state_file"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_v3_partial_backup_snapshot
      require_root_file "$state_file"
      require_root_file "$runtime_caller_receipt"
      [[ "$(holdfast_sha256 "$state_file")" == "$partial_current_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$partial_current_identity" && \
        "$(holdfast_sha256 "$runtime_caller_receipt")" == "$partial_caller_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$runtime_caller_receipt")" == \
          "$partial_caller_identity" ]] || \
        holdfast_die "schema-v3 partial runtime authority changed during initial probe"
      if [[ "$runtime_arm_state" == "present" ]]; then
        require_root_file "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
        [[ "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == \
            "$partial_arm_sha" && \
          "$(stat -c '%d:%i:%u:%h:%f' -- \
            "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == "$partial_arm_identity" ]] || \
          holdfast_die "schema-v3 partial runtime stop authority changed during initial probe"
      fi
    fi
    if [[ "$runtime_arm_state" == "present" ]]; then
      validate_runtime_caller_authority "$state_file"
      validate_runtime_partial_boundary_authority "$runtime_arm_state"
      if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
        validate_v3_partial_backup_snapshot
      fi
      restore_runtime_prior_subset
      if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
        validate_v3_partial_backup_snapshot
      fi
    else
      [[ ! -e "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]] || \
        holdfast_die "runtime backup succeeded without durable stop authority"
    fi
    verify_closed_bracket
    validate_runtime_caller_authority "$state_file"
    if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
      validate_runtime_partial_boundary_authority "$runtime_arm_state"
      validate_v3_partial_backup_snapshot
      require_root_file "$state_file"
      require_root_file "$runtime_caller_receipt"
      [[ "$(holdfast_sha256 "$state_file")" == "$partial_current_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$partial_current_identity" && \
        "$(holdfast_sha256 "$runtime_caller_receipt")" == "$partial_caller_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$runtime_caller_receipt")" == \
          "$partial_caller_identity" ]] || \
        holdfast_die "schema-v3 partial runtime authority changed during recovery"
      if [[ "$runtime_arm_state" == "present" ]]; then
        require_root_file "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
        [[ "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == \
            "$partial_arm_sha" && \
          "$(stat -c '%d:%i:%u:%h:%f' -- \
            "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" == "$partial_arm_identity" ]] || \
          holdfast_die "schema-v3 partial runtime stop authority changed during recovery"
        verify_runtime_prior_subset_disposition
        validate_runtime_caller_authority "$state_file"
        validate_runtime_partial_boundary_authority "$runtime_arm_state"
        validate_v3_partial_backup_snapshot
        [[ "$(holdfast_sha256 "$state_file")" == "$partial_current_sha" && \
          "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == \
            "$partial_current_identity" ]] || \
          holdfast_die "schema-v3 partial runtime CURRENT changed during live verification"
      fi
      validate_v3_partial_backup_snapshot
    fi
    record_runtime_caller_cleanup "$runtime_arm_state"
    complete_runtime_caller_recovery "$runtime_arm_state"
    echo "interrupted runtime backup recovered; rerun apply with a fresh ceremony"
    exit 0
  fi
fi

require_canonical_root_dir "$backup/runtime"
for file in \
  "$backup/CONTROL.sha256" "$backup/DRY-RUN.receipt" "$backup/RELEASE-EVIDENCE.json" \
  "$backup/release.env" "$backup/SUPPLY-CHAIN.json" "$backup/SUPPLY-CHAIN.sig" \
  "$backup/SUPPLY-CHAIN.pub" "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" \
  "$backup/RENDER-INPUTS.sha256" "$backup/runtime/SHA256SUMS" \
  "$backup/runtime/BACKUP.receipt" "$backup/runtime/VOLUMES.tsv" \
  "$backup/runtime/compose-config.json"; do
  require_root_file "$file"
done

runtime_schema=$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" schema_version)
case "$runtime_schema" in
  1)
    require_root_file "$backup/runtime/postgres.dump"
    [[ "$legacy_empty_strad" == "true" ]] || \
      holdfast_die "schema-v1 runtime restore is unsafe; explicit --legacy-empty-strad proof is required"
    ;;
  2)
    require_root_file "$backup/runtime/strad.dump"
    require_root_file "$backup/runtime/RUNNING-SERVICES.before"
    require_root_file "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
    [[ "$legacy_empty_strad" == "false" ]] || \
      holdfast_die "legacy empty-Strad recovery is valid only for schema-v1 backups"
    validate_runtime_stop_authority
    validate_runtime_backup_success_authority
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" postgres_database)" == "strad" ]] || \
      holdfast_die "schema-v2 runtime backup is not bound to the Strad database"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" database_identity)" == "postgres:5432/strad" ]] || \
      holdfast_die "schema-v2 runtime backup database identity differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" runtime_writers)" == \
      "strad,rikune-analyzer,rikune-volume-init" ]] || \
      holdfast_die "schema-v2 runtime backup writer set differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" runtime_writers_stopped)" == "passed" ]] || \
      holdfast_die "schema-v2 runtime backup did not prove stopped writers"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" writers_left_quiesced)" == "passed" ]] || \
      holdfast_die "schema-v2 runtime backup did not leave writers quiesced"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_manifest)" == \
      "RUNNING-SERVICES.before" ]] || \
      holdfast_die "schema-v2 runtime backup prior-running manifest differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_sha256)" == \
      "$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" ]] || \
      holdfast_die "schema-v2 runtime backup prior-running manifest was replaced"
    ;;
  *) holdfast_die "unsupported runtime backup schema" ;;
esac
if [[ "$quarantine_access_chain" == "true" && "$runtime_schema" != "2" ]]; then
  holdfast_die "access-chain quarantine requires a schema-v2 runtime backup"
fi

# Reject path tricks before handing the immutable manifest to sha256sum.
while IFS= read -r control_line; do
  [[ "$control_line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]] || \
    holdfast_die "CONTROL contains an invalid checksum line"
  control_path=${BASH_REMATCH[1]}
  [[ "$control_path" != /* && "$control_path" != *"../"* && "$control_path" != ".." ]] || \
    holdfast_die "CONTROL contains an unsafe path"
done <"$backup/CONTROL.sha256"
(cd "$backup" && sha256sum --check CONTROL.sha256)
validate_runtime_checksum_manifest
(cd "$backup/runtime" && sha256sum --check SHA256SUMS)
control_sha=$(holdfast_sha256 "$backup/CONTROL.sha256")
control_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$backup/CONTROL.sha256")

# New applies bind immutable input manifests before the first estate mutation.
# Legacy orphan backups predate that contract and bind the same identities only
# through the completed estate transaction.
early_bound_contract="false"
if [[ -f "$backup/TARGETS.sha256" && ! -L "$backup/TARGETS.sha256" ]]; then
  early_bound_contract="true"
  require_root_file "$backup/TARGETS.sha256"
  target_manifest="$backup/TARGETS.sha256"
else
  [[ ! -e "$backup/TARGETS.sha256" && ! -L "$backup/TARGETS.sha256" ]] || \
    holdfast_die "unsafe top-level target manifest"
  target_manifest="$backup/estate/APPLIED-TARGETS.sha256"
fi

transaction_state="not_started"
transaction_sha="not-started"
if [[ -e "$backup/estate" || -L "$backup/estate" ]]; then
  require_canonical_root_dir "$backup/estate"
  if [[ -e "$backup/estate/tree" || -L "$backup/estate/tree" ]]; then
    require_canonical_root_dir "$backup/estate/tree"
  fi
  if [[ -f "$backup/estate/TRANSACTION.json" && ! -L "$backup/estate/TRANSACTION.json" ]]; then
    for file in "$backup/estate/APPLIED-TARGETS.sha256" "$backup/estate/PREIMAGES.sha256" \
      "$backup/estate/ABSENT.before" "$backup/estate/TRANSACTION.json"; do
      require_root_file "$file"
    done
    transaction_state=$(jq -er 'select(.schema_version == 1) | .state' "$backup/estate/TRANSACTION.json")
    [[ "$transaction_state" == "prepared" || "$transaction_state" == "applied" || \
      "$transaction_state" == "rolled_back_after_failure" ]] || \
      holdfast_die "estate transaction is not recoverable: $transaction_state"
    transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
    if [[ "$early_bound_contract" == "true" ]]; then
      cmp -s -- "$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256" || \
        holdfast_die "estate targets differ from the armed release binding"
    fi
    cmp -s -- "$backup/APPLY-PREIMAGES.sha256" "$backup/estate/PREIMAGES.sha256" || \
      holdfast_die "estate preimages differ from the release binding"
    cmp -s -- "$backup/APPLY-ABSENT.paths" "$backup/estate/ABSENT.before" || \
      holdfast_die "estate absent dispositions differ from the release binding"
    target_manifest="$backup/estate/APPLIED-TARGETS.sha256"
    target_count=$(wc -l <"$target_manifest" | tr -d ' ')
    if [[ "$transaction_state" == "applied" ]]; then
      [[ "$(jq -er '.target_count' "$backup/estate/TRANSACTION.json")" == "$target_count" ]] || \
        holdfast_die "estate transaction target count differs"
    fi
  else
    [[ "$early_bound_contract" == "true" ]] || \
      holdfast_die "legacy recovery requires a durable estate transaction"
    [[ ! -e "$backup/estate/TRANSACTION.json" && ! -L "$backup/estate/TRANSACTION.json" ]] || \
      holdfast_die "unsafe estate transaction path"
  fi
else
  [[ "$early_bound_contract" == "true" ]] || holdfast_die "legacy recovery lacks an estate backup"
fi
if [[ "$transaction_state" != "applied" && "$mode" == "resume" ]]; then
  holdfast_die "resume requires an applied estate transaction"
fi
transaction_is_preimage="false"
if [[ "$transaction_state" == "not_started" || \
  "$transaction_state" == "rolled_back_after_failure" ]]; then
  transaction_is_preimage="true"
fi
applied_targets_sha=$(holdfast_sha256 "$target_manifest")
[[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
  holdfast_die "runtime backup lacks a passed isolated restore probe"

release_validator=$(test_override HOLDFAST_RELEASE_VALIDATOR_BIN "$script_dir/validate_release_evidence.py")
release_validator_args=(--evidence "$backup/RELEASE-EVIDENCE.json")
if jq -e '.schema_version == 2 and .release_mode == "successor"' \
  "$backup/RELEASE-EVIDENCE.json" >/dev/null; then
  recovery_successor_policy="$backup/successor-authority/successor-policy.json"
  require_root_file "$recovery_successor_policy"
  grep -Fqx "$(holdfast_sha256 "$recovery_successor_policy")  successor-authority/successor-policy.json" \
    "$backup/CONTROL.sha256" || \
    holdfast_die "successor CONTROL omits its frozen release policy"
  release_validator_args+=(--successor-policy "$recovery_successor_policy")
fi
run_python_tool "$release_validator" "$script_dir/validate_release_evidence.py" \
  "${release_validator_args[@]}"
validate_v3_completed_terminal_core_fence \
  "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"

dry_receipt="$backup/DRY-RUN.receipt"
release_env_sha=$(holdfast_sha256 "$backup/release.env")
release_evidence_sha=$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")
dry_receipt_sha=$(holdfast_sha256 "$dry_receipt")
[[ "$(holdfast_receipt_value "$dry_receipt" cargo_gate)" == "passed" ]] || holdfast_die "dry-run Rust gate was not passed"
[[ "$(holdfast_receipt_value "$dry_receipt" targets_sha256)" == "$(holdfast_sha256 "$target_manifest")" ]] || \
  holdfast_die "dry-run target binding differs from the applied transaction"
[[ "$(holdfast_receipt_value "$dry_receipt" release_evidence_sha256)" == "$release_evidence_sha" ]] || \
  holdfast_die "dry-run release evidence binding differs"
[[ "$(holdfast_receipt_value "$dry_receipt" release_env_sha256)" == "$release_env_sha" ]] || \
  holdfast_die "dry-run release env binding differs"
[[ "$(jq -er '.release_env_sha256' "$backup/RELEASE-EVIDENCE.json")" == "$release_env_sha" ]] || \
  holdfast_die "release evidence points to another release env"
[[ "$(holdfast_receipt_value "$dry_receipt" apply_preimages_sha256)" == "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" ]] || \
  holdfast_die "dry-run preimage binding differs"
[[ "$(holdfast_receipt_value "$dry_receipt" apply_absent_sha256)" == "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" ]] || \
  holdfast_die "dry-run absent binding differs"
[[ "$(holdfast_receipt_value "$dry_receipt" render_inputs_sha256)" == "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" ]] || \
  holdfast_die "dry-run render-input binding differs"
for key in evidence signature public_key; do
  case "$key" in
    evidence) supply_file="$backup/SUPPLY-CHAIN.json" ;;
    signature) supply_file="$backup/SUPPLY-CHAIN.sig" ;;
    public_key) supply_file="$backup/SUPPLY-CHAIN.pub" ;;
  esac
  [[ "$(holdfast_receipt_value "$dry_receipt" "supply_chain_${key}_sha256")" == "$(holdfast_sha256 "$supply_file")" ]] || \
    holdfast_die "dry-run supply-chain binding differs: $key"
done

armed_receipt="$backup/APPLY-ARMED.receipt"
legacy_orphan="false"
if [[ -f "$armed_receipt" && ! -L "$armed_receipt" ]]; then
  require_root_file "$armed_receipt"
  armed_estate=$(holdfast_receipt_value "$armed_receipt" estate_root)
  holdfast_require_absolute "$armed_estate"
  if [[ -n "$estate_root" && "$estate_root" != "$armed_estate" ]]; then
    holdfast_die "requested estate root differs from the armed apply"
  fi
  estate_root=$armed_estate
  [[ "$(holdfast_receipt_value "$armed_receipt" backup_dir)" == "$backup" ]] || holdfast_die "armed apply points to another backup"
  [[ "$(holdfast_receipt_value "$armed_receipt" release_env_sha256)" == "$release_env_sha" ]] || holdfast_die "armed release env differs"
  [[ "$(holdfast_receipt_value "$armed_receipt" release_evidence_sha256)" == "$release_evidence_sha" ]] || holdfast_die "armed release evidence differs"
  [[ "$(holdfast_receipt_value "$armed_receipt" dry_run_receipt_sha256)" == "$dry_receipt_sha" ]] || holdfast_die "armed dry-run receipt differs"
  [[ "$(holdfast_receipt_value "$armed_receipt" targets_sha256)" == "$(holdfast_sha256 "$target_manifest")" ]] || holdfast_die "armed targets differ"
  [[ "$(holdfast_receipt_value "$armed_receipt" apply_preimages_sha256)" == "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" ]] || holdfast_die "armed preimages differ"
  [[ "$(holdfast_receipt_value "$armed_receipt" apply_absent_sha256)" == "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" ]] || holdfast_die "armed absent dispositions differ"
  [[ "$(holdfast_receipt_value "$armed_receipt" render_inputs_sha256)" == "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" ]] || holdfast_die "armed render inputs differ"
  [[ "$(holdfast_receipt_value "$armed_receipt" runtime_backup_receipt_sha256)" == "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" ]] || holdfast_die "armed runtime receipt differs"
  [[ "$(holdfast_receipt_value "$armed_receipt" runtime_backup_manifest_sha256)" == "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" ]] || holdfast_die "armed runtime manifest differs"
  grep -Fqx "$(holdfast_sha256 "$armed_receipt")  APPLY-ARMED.receipt" "$backup/CONTROL.sha256" || \
    holdfast_die "CONTROL does not bind the armed apply receipt"
  armed_receipt_sha=$(holdfast_sha256 "$armed_receipt")
else
  [[ ! -e "$armed_receipt" && ! -L "$armed_receipt" ]] || holdfast_die "unsafe armed receipt path"
  [[ -n "$estate_root" ]] || holdfast_die "legacy orphan recovery requires --estate-root"
  legacy_orphan="true"
  armed_receipt_sha="legacy-absent"
fi
holdfast_require_absolute "$estate_root"
require_canonical_root_dir "$estate_root"
[[ -d "$estate_root/access-governance" && -d "$estate_root/deploy" ]] || holdfast_die "estate root is incomplete"
require_canonical_root_dir "$estate_root/access-governance"
require_canonical_root_dir "$estate_root/deploy"

apply_receipt="$backup/APPLY.receipt"
pending_apply_receipt="$backup/APPLY-PENDING.receipt"
for finalization_receipt in "$apply_receipt" "$pending_apply_receipt"; do
  if [[ -e "$finalization_receipt" || -L "$finalization_receipt" ]]; then
    require_root_file "$finalization_receipt"
  fi
done
rescanned_completed_state_match=""
shopt -s nullglob
for completed_state in "$state_dir"/APPLY-RECOVERY-COMPLETE-*.json; do
  require_root_file "$completed_state"
  if [[ "$verify_completed" == "true" ]]; then
    verify_completed_json_structure "$completed_state"
  fi
  if [[ "$(jq -er --arg backup "$backup" '.backup_dir == $backup and (.state == "apply_recovered_restored" or .state == "apply_recovered_resumed")' "$completed_state" 2>/dev/null || true)" == "true" ]]; then
    [[ -z "$rescanned_completed_state_match" ]] || holdfast_die "multiple completion states exist for this backup"
    rescanned_completed_state_match=$completed_state
  fi
done
shopt -u nullglob
if [[ "$v3_completed_terminal_candidate_scan_active" == "true" ]]; then
  validate_v3_completed_terminal_candidate_namespace
  [[ "$rescanned_completed_state_match" == "$completed_state_match" ]] || \
    holdfast_die "schema-v3 completed recovery match changed during validation"
else
  completed_state_match=$rescanned_completed_state_match
fi

if [[ -n "$completed_state_match" && "$backup_expected_successor" == "true" ]]; then
  require_root_file "$backup/successor-authority/successor-policy.json"
  if [[ "$(jq -er '.schema_version' \
    "$backup/successor-authority/successor-policy.json")" =~ ^(3|4)$ ]]; then
    successor_recovery_v3="true"
    snapshot_v3_completed_terminal_authority
  fi
fi

successor_completed_pointer="false"
if [[ -n "$completed_state_match" && \
  -f "$backup/SUCCESSOR-ARMED.receipt" && ! -L "$backup/SUCCESSOR-ARMED.receipt" && \
  -f "$state_file" && ! -L "$state_file" ]]; then
  load_successor_authority "$completed_state_match"
  if [[ "$(holdfast_sha256 "$state_file")" == "$predecessor_current_sha" ]]; then
    successor_completed_pointer="true"
  fi
fi
validate_v3_completed_terminal_core_fence \
  "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"

prior_state="legacy_orphan_applied"
armed_pointer_missing="false"
if [[ ( -e "$state_file" || -L "$state_file" ) && \
  "$successor_completed_pointer" != "true" ]]; then
  require_root_file "$state_file"
  if [[ "$verify_completed" == "true" ]]; then
    verify_completed_json_structure "$state_file"
  fi
  prior_state=$(jq -er '.state' "$state_file")
  [[ "$prior_state" == "apply_armed" || "$prior_state" == "apply_estate_recovery_required" || "$prior_state" == "apply_activation_armed" || "$prior_state" == "apply_activation_failed" || "$prior_state" == "apply_finalizing_ingress_closed" || "$prior_state" == "apply_recovery_armed" || "$prior_state" == "apply_recovery_failed" || "$prior_state" == "restore_failed" || ( "$prior_state" == "applied_ingress_closed" && ( -n "$completed_state_match" || -e "$apply_receipt" ) ) ]] || \
    holdfast_die "apply recovery refuses current state $prior_state"
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || holdfast_die "current state points to another backup"
  [[ "$(jq -er '.estate_root' "$state_file")" == "$estate_root" ]] || holdfast_die "current state points to another estate"
  if [[ "$legacy_orphan" == "true" ]]; then
    [[ ( "$prior_state" == "apply_recovery_armed" || "$prior_state" == "apply_recovery_failed" || "$prior_state" == "restore_failed" ) && "$(jq -er '.legacy_orphan_adopted // false' "$state_file")" == "true" ]] || \
      holdfast_die "legacy orphan has an unaudited active current state"
  else
    [[ "$(jq -er '.apply_armed_receipt_sha256' "$state_file")" == "$armed_receipt_sha" ]] || holdfast_die "current state armed receipt differs"
  fi
  [[ "$(jq -er '.release_evidence_sha256' "$state_file")" == "$release_evidence_sha" ]] || holdfast_die "current state release differs"
  state_control_sha=$(jq -er '.control_sha256 // "none"' "$state_file")
  if [[ "$prior_state" == "apply_armed" ]]; then
    [[ "$state_control_sha" == "none" || "$state_control_sha" == "$control_sha" ]] || holdfast_die "current state CONTROL differs"
  else
    [[ "$state_control_sha" == "$control_sha" ]] || holdfast_die "current state CONTROL differs"
  fi
  failure_name=$(jq -er '.apply_failure_receipt // "none"' "$state_file")
  if [[ "$failure_name" != "none" ]]; then
    [[ "$failure_name" =~ ^APPLY-(ACTIVATION-FAILED|ESTATE-FAILED|RECOVERY-FAILED)-[0-9]{8}T[0-9]{6}Z-[0-9]+(-retry-[0-9]+)?\.receipt$ ]] || \
      holdfast_die "current state failure receipt name is unsafe"
    require_root_file "$state_dir/$failure_name"
    [[ "$(jq -er '.apply_failure_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$state_dir/$failure_name")" ]] || \
      holdfast_die "current state failure receipt was replaced"
  fi
  if [[ "$transaction_state" == "rolled_back_after_failure" ]]; then
    [[ "$prior_state" == "apply_estate_recovery_required" || \
      "$prior_state" == "apply_recovery_armed" || "$prior_state" == "restore_failed" ]] || \
      holdfast_die "rolled-back transaction is not bound to a recovery-required state"
    [[ "$(jq -er '.estate_transaction_state // "none"' "$state_file")" == \
      "rolled_back_after_failure" ]] || holdfast_die "current state transaction disposition differs"
    [[ "$(jq -er '.estate_transaction_sha256 // "none"' "$state_file")" == \
      "$transaction_sha" ]] || holdfast_die "current state transaction receipt was replaced"
    if [[ "$failure_name" != "none" ]]; then
      [[ "$(holdfast_receipt_value "$state_dir/$failure_name" transaction_state)" == \
        "rolled_back_after_failure" ]] || holdfast_die "failure receipt transaction state differs"
      [[ "$(holdfast_receipt_value "$state_dir/$failure_name" transaction_sha256)" == \
        "$transaction_sha" ]] || holdfast_die "failure receipt transaction was replaced"
    fi
  fi
else
  [[ ! -e "$apply_receipt" && ! -L "$apply_receipt" && \
    ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]] || \
    holdfast_die "apply finalization receipt exists without its active state"
  if [[ "$legacy_orphan" == "false" && "$early_bound_contract" == "true" ]]; then
    [[ "$transaction_state" != "rolled_back_after_failure" ]] || \
      holdfast_die "rolled-back apply recovery requires its active failure state"
    prior_state="apply_armed_pointer_missing"
    armed_pointer_missing="true"
  else
    [[ "$legacy_orphan" == "true" || -n "$completed_state_match" ]] || \
      holdfast_die "active apply state is absent"
  fi
fi

if [[ "$successor_completed_pointer" == "true" ]]; then
  load_successor_authority "$completed_state_match"
elif [[ -e "$backup/SUCCESSOR-ARMED.receipt" || -L "$backup/SUCCESSOR-ARMED.receipt" || \
  -e "$backup/PREDECESSOR-CURRENT.json" || -L "$backup/PREDECESSOR-CURRENT.json" ]]; then
  [[ -f "$state_file" && ! -L "$state_file" ]] || \
    holdfast_die "successor recovery requires its active lineage-bearing CURRENT"
  load_successor_authority "$state_file"
elif [[ -f "$state_file" && ! -L "$state_file" ]]; then
  load_successor_authority "$state_file"
fi
validate_successor_persisted_supply_chain
validate_v3_completed_terminal_core_fence \
  "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
if [[ "$successor_policy_version" == "3" || "$successor_policy_version" == "4" ]]; then
  successor_recovery_v3="true"
  case "${failure_name:-none}" in
    APPLY-RECOVERY-FAILED-*)
      validate_successor_lineage_receipt "$state_dir/$failure_name"
      ;;
    APPLY-ACTIVATION-FAILED-*|APPLY-ESTATE-FAILED-*)
      [[ "$successor_policy_version" == "3" ]] || \
        validate_no_predecessor_completion_namespace "$state_dir/$failure_name"
      if [[ "$successor_policy_version" == "3" ]]; then
      validate_v3_apply_failure_completion_receipt "$state_dir/$failure_name"
      fi
      ;;
  esac
fi

if [[ "$quarantine_access_chain" == "true" && \
  "$prior_state" != "restore_failed" && "$prior_state" != "apply_recovery_armed" && \
  -z "$completed_state_match" ]]; then
  holdfast_die "access-chain quarantine requires a restore-failed retry"
fi

runtime_restore=$(test_override HOLDFAST_RUNTIME_RESTORE_BIN "$script_dir/runtime-restore.sh")
runtime_verify=$(test_override HOLDFAST_RUNTIME_VERIFY_BIN "$script_dir/runtime-verify.sh")
runtime_verify_helper_fence=""
if [[ "$verify_completed" == "true" ]]; then
  runtime_verify=$(resolve_verify_completed_helper "$runtime_verify" "runtime verification")
  runtime_verify_helper_fence=$(snapshot_verify_completed_helper \
    "$runtime_verify" "runtime verification")
fi

run_runtime_verify() {
  if [[ "$verify_completed" == "true" ]]; then
    validate_verify_completed_helper \
      "$runtime_verify" "$runtime_verify_helper_fence" "runtime verification"
  fi
  "$runtime_verify" "$@"
}
recovery_compose_root="$estate_root"
recovery_stage=""
recovery_dry_root=""

v3_stage_entries=()
declare -A v3_stage_hashes=() v3_stage_identities=()

snapshot_v3_recovery_stage_authority() {
  local file
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  v3_stage_entries=()
  v3_stage_hashes=()
  v3_stage_identities=()
  for file in "$recovery_dry_root" "$recovery_stage"; do
    require_canonical_root_dir "$file"
    v3_stage_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
  require_single_device_tree "$recovery_stage" "schema-v3 recovery stage"
  while IFS= read -r -d '' file; do
    v3_stage_entries+=("$file")
    v3_stage_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
    if [[ -f "$file" && ! -L "$file" ]]; then
      require_root_file "$file"
      v3_stage_hashes["$file"]=$(holdfast_sha256 "$file")
    fi
  done < <(find "$recovery_stage" -xdev -mindepth 1 -print0 | sort -z)
  ((${#v3_stage_entries[@]} > 0)) || holdfast_die "schema-v3 recovery stage is empty"
}

validate_v3_recovery_stage_snapshot() {
  local file index
  local -a current_entries=()
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  for file in "$recovery_dry_root" "$recovery_stage" "$recovery_stage/deploy"; do
    require_canonical_root_dir "$file"
    [[ -z "$(find "$file" -maxdepth 0 -perm /077 -print -quit)" ]] || \
      holdfast_die "schema-v3 recovery staged directories must remain private"
  done
  require_single_device_tree "$recovery_stage" "schema-v3 recovery stage"
  [[ -z "$(find "$recovery_stage" -xdev -type l -print -quit)" ]] || \
    holdfast_die "schema-v3 recovery stage gained a symlink"
  [[ -z "$(find "$recovery_stage" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "schema-v3 recovery stage gained a non-root-owned entry"
  [[ -z "$(find "$recovery_stage" -xdev ! -type d ! -type f -print -quit)" ]] || \
    holdfast_die "schema-v3 recovery stage gained a special file"
  [[ -z "$(find "$recovery_stage" -xdev -type f -links +1 -print -quit)" ]] || \
    holdfast_die "schema-v3 recovery stage gained a hard-linked file"
  while IFS= read -r -d '' file; do current_entries+=("$file"); done \
    < <(find "$recovery_stage" -xdev -mindepth 1 -print0 | sort -z)
  ((${#current_entries[@]} == ${#v3_stage_entries[@]})) || \
    holdfast_die "schema-v3 recovery stage entry set changed during validation"
  for index in "${!v3_stage_entries[@]}"; do
    [[ "${current_entries[$index]}" == "${v3_stage_entries[$index]}" ]] || \
      holdfast_die "schema-v3 recovery stage entry set changed during validation"
  done
  for file in "$recovery_dry_root" "$recovery_stage" "${v3_stage_entries[@]}"; do
    [[ "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
      "${v3_stage_identities[$file]}" ]] || \
      holdfast_die "schema-v3 recovery stage changed during external validation: $file"
    if [[ -n "${v3_stage_hashes[$file]+x}" ]]; then
      require_root_file "$file"
      [[ "$(holdfast_sha256 "$file")" == "${v3_stage_hashes[$file]}" ]] || \
        holdfast_die "schema-v3 recovery stage changed during external validation: $file"
    fi
  done
  cmp -s -- "$recovery_stage/TARGETS.sha256" "$backup/TARGETS.sha256" || \
    holdfast_die "schema-v3 recovery stage target manifest changed"
  (cd "$recovery_stage" && sha256sum --check TARGETS.sha256) >/dev/null
}

validate_recovery_stage_authority() {
  local armed_dry caller_dry resolved_config expected key value
  local target_line target_path
  local -A target_paths=()

  [[ "$early_bound_contract" == "true" ]] || \
    holdfast_die "armed recovery lacks an early-bound staged Compose authority"
  require_root_file "$runtime_caller_receipt"
  grep -Fqx "$(holdfast_sha256 "$runtime_caller_receipt")  RUNTIME-BACKUP-CALLER-ARMED.receipt" \
    "$backup/CONTROL.sha256" || \
    holdfast_die "CONTROL does not bind the runtime backup caller receipt"

  armed_dry=$(holdfast_receipt_value "$armed_receipt" dry_run_dir)
  caller_dry=$(holdfast_receipt_value "$runtime_caller_receipt" dry_run_dir)
  holdfast_require_absolute "$armed_dry"
  holdfast_require_absolute "$caller_dry"
  [[ "$armed_dry" == "$caller_dry" ]] || \
    holdfast_die "armed recovery staged Compose roots differ"
  recovery_stage="$armed_dry/stage"
  recovery_dry_root="$armed_dry"
  [[ "$(readlink -m -- "$recovery_stage")" == "$recovery_stage" ]] || \
    holdfast_die "recovery staged Compose root is not canonical"

  [[ "$(holdfast_receipt_value "$armed_receipt" runtime_backup_caller_armed_sha256)" == \
    "$(holdfast_sha256 "$runtime_caller_receipt")" ]] || \
    holdfast_die "armed runtime backup caller authority differs"
  [[ "$(holdfast_receipt_value "$armed_receipt" runtime_backup_stop_authority_sha256)" == \
    "$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" ]] || \
    holdfast_die "armed runtime stop authority differs"
  for expected in \
    "schema_version=2" "estate_root=$estate_root" "dry_run_dir=$armed_dry" \
    "backup_dir=$backup" "runtime_backup_dir=$backup/runtime" \
    "release_env_sha256=$release_env_sha" \
    "release_evidence_sha256=$release_evidence_sha" \
    "dry_run_receipt_sha256=$dry_receipt_sha" \
    "targets_sha256=$(holdfast_sha256 "$backup/TARGETS.sha256")" \
    "apply_preimages_sha256=$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" \
    "apply_absent_sha256=$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" \
    "render_inputs_sha256=$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" \
    "runtime_backup_armed_receipt=runtime/RUNTIME-BACKUP-ARMED.receipt" \
    "stop_authority_contract=absence-means-stop-not-started" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$runtime_caller_receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup caller staged authority differs: $key"
  done

  for directory in "$armed_dry" "$recovery_stage" "$recovery_stage/deploy"; do
    require_canonical_root_dir "$directory"
    [[ -z "$(find "$directory" -maxdepth 0 -perm /077 -print -quit)" ]] || \
      holdfast_die "recovery staged Compose directories must be private"
  done
  [[ -z "$(find "$recovery_stage" -xdev -type l -print -quit)" ]] || \
    holdfast_die "recovery stage contains a symlink"
  [[ -z "$(find "$recovery_stage" -xdev ! -user root -print -quit)" ]] || \
    holdfast_die "recovery stage contains a non-root-owned entry"
  [[ -z "$(find "$recovery_stage" -xdev ! -type d ! -type f -print -quit)" ]] || \
    holdfast_die "recovery stage contains a special file"
  for file in "$recovery_stage/TARGETS.sha256" \
    "$recovery_stage/deploy/docker-compose.yml" "$recovery_stage/deploy/.env"; do
    require_root_file "$file"
  done
  cmp -s -- "$recovery_stage/TARGETS.sha256" "$backup/TARGETS.sha256" || \
    holdfast_die "recovery stage target manifest differs from its armed copy"

  while IFS= read -r target_line; do
    [[ "$target_line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]] || \
      holdfast_die "recovery stage target manifest contains an invalid line"
    target_path=${BASH_REMATCH[1]}
    [[ "$target_path" != /* && "$target_path" != ".." && "$target_path" != *"../"* ]] || \
      holdfast_die "recovery stage target manifest contains an unsafe path"
    [[ -z "${target_paths[$target_path]:-}" ]] || \
      holdfast_die "recovery stage target manifest repeats a path"
    target_paths[$target_path]=1
  done <"$recovery_stage/TARGETS.sha256"
  [[ -n "${target_paths[deploy/docker-compose.yml]:-}" && \
    -n "${target_paths[deploy/.env]:-}" ]] || \
    holdfast_die "recovery stage target manifest does not bind Compose and its env"
  (cd "$recovery_stage" && sha256sum --check TARGETS.sha256)
  snapshot_v3_recovery_stage_authority

  if [[ "$successor_recovery" == "true" ]]; then
    local render_validator
    require_root_file "$recovery_stage/RELEASE-EVIDENCE.json"
    require_root_file "$recovery_stage/SUCCESSOR-DELTA.sha256"
    cmp -s -- "$recovery_stage/SUCCESSOR-DELTA.sha256" \
      "$backup/SUCCESSOR-DELTA.sha256" || \
      holdfast_die "recovery staged successor delta differs from its CONTROL copy"
    render_validator=$(test_override HOLDFAST_RENDER_INPUT_BINDING_BIN "$script_dir/render_input_binding.py")
    run_python_tool "$render_validator" "$script_dir/render_input_binding.py" verify \
      --ops-root "$backup/successor-authority" \
      --manifest "$backup/RENDER-INPUTS.sha256" \
      --stage-root "$recovery_stage" \
      --release-evidence "$recovery_stage/RELEASE-EVIDENCE.json" \
      --expected-mode successor --require-root-owner
  fi

  umask 077
  resolved_config=$(mktemp "${TMPDIR:-/var/tmp}/holdfast-recovery-compose.XXXXXX")
  if ! "$docker_bin" compose --env-file "$recovery_stage/deploy/.env" \
    -f "$recovery_stage/deploy/docker-compose.yml" config --format json >"$resolved_config"; then
    rm -f -- "$resolved_config"
    holdfast_die "could not resolve the recovery staged Compose authority"
  fi
  if ! python3 - "$resolved_config" "$backup/runtime/compose-config.json" <<'PY'
import json
import sys
from pathlib import Path


def load(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


raise SystemExit(0 if load(sys.argv[1]) == load(sys.argv[2]) else 1)
PY
  then
    rm -f -- "$resolved_config"
    holdfast_die "recovery staged Compose differs from the frozen runtime authority"
  fi
  rm -f -- "$resolved_config"
  validate_v3_recovery_stage_snapshot
  recovery_compose_root="$recovery_stage"
}

compose=("$docker_bin" compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml")
application_writers=(
  access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
)
access_chain_writers=(access-governance newapi)
runtime_prior_services=()
if [[ "$runtime_schema" == "2" ]]; then
  mapfile -t runtime_prior_services <"$backup/runtime/RUNNING-SERVICES.before"
  previous_runtime_index=-1
  runtime_service_order=(strad rikune-analyzer)
  for service in "${runtime_prior_services[@]}"; do
    runtime_index=-1
    for index in "${!runtime_service_order[@]}"; do
      if [[ "${runtime_service_order[$index]}" == "$service" ]]; then runtime_index=$index; break; fi
    done
    ((runtime_index >= 0 && runtime_index > previous_runtime_index)) || \
      holdfast_die "runtime prior-running manifest is unknown, duplicated, or out of order"
    previous_runtime_index=$runtime_index
  done
fi
compose_project=$(jq -er '.name' "$backup/runtime/compose-config.json")
[[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "runtime backup has an unsafe Compose project name"

service_container_ids() {
  local service=$1
  "$docker_bin" ps -aq \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter "label=com.docker.compose.service=$service"
}

validate_access_chain_live_failure() {
  local output state health
  local -a ids=()
  output=$(service_container_ids access-governance) || \
    holdfast_die "could not inspect access-governance for quarantine"
  if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
  ((${#ids[@]} == 1)) || \
    holdfast_die "access-chain quarantine lacks one failed access-governance container"
  state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}") || \
    holdfast_die "could not inspect access-governance state for quarantine"
  case "$state" in
    restarting|exited|dead|created) ;;
    running)
      health=$("$docker_bin" inspect -f \
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}") || \
        holdfast_die "could not inspect access-governance health for quarantine"
      [[ "$health" == "unhealthy" ]] || \
        holdfast_die "access-chain quarantine requires failed access-governance health evidence"
      ;;
    *) holdfast_die "access-chain quarantine refuses access-governance state: $state" ;;
  esac
}

verify_live_quarantine_absence() {
  local service output
  [[ "$writer_set_quarantined" == "access-governance,newapi" ]] || return 0
  for service in "${access_chain_writers[@]}"; do
    output=$(service_container_ids "$service") || \
      holdfast_die "could not verify quarantined writer absence: $service"
    [[ -z "$output" ]] || \
      holdfast_die "quarantined writer container exists at completion: $service"
  done
}

validate_writer_sequence() {
  local -n writers=$1
  local previous_index=-1 service candidate index found
  for service in "${writers[@]}"; do
    found=-1
    for index in "${!application_writers[@]}"; do
      candidate=${application_writers[$index]}
      if [[ "$candidate" == "$service" ]]; then
        found=$index
        break
      fi
    done
    ((found >= 0)) || holdfast_die "restore writer manifest contains an unknown service: $service"
    ((found > previous_index)) || holdfast_die "restore writer manifest is duplicated or out of order"
    previous_index=$found
  done
}

validate_restore_writer_set() {
  validate_writer_sequence restore_running_writers
}

verify_restore_writer_runtime_disposition() {
  local service output state health container_id
  local -a ids=()
  for service in "${application_writers[@]}"; do
    output=$(service_container_ids "$service") || \
      holdfast_die "could not verify recovery writer disposition: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || \
      holdfast_die "multiple recovery writer containers exist: $service"
    if restore_writer_was_running "$service"; then
      ((${#ids[@]} == 1)) || holdfast_die "restored writer disappeared: $service"
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
      health=$("$docker_bin" inspect -f \
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}")
      [[ "$state" == "running" && ( "$health" == "none" || "$health" == "healthy" ) ]] || \
        holdfast_die "restored writer is not healthy and running: $service"
    else
      for container_id in "${ids[@]}"; do
        state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
        [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
          holdfast_die "writer excluded from restore became active: $service"
      done
    fi
  done
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    verify_live_quarantine_absence
  fi
}

declare -A preimage_compose_services=()
preimage_compose_sha="none"
load_preimage_compose_authority() {
  local compose_path expected_sha="" digest relative extra output service
  local matches=0
  if [[ "$transaction_state" == "not_started" ]]; then
    compose_path="$estate_root/deploy/docker-compose.yml"
  else
    compose_path="$backup/estate/tree/deploy/docker-compose.yml"
  fi
  require_root_file "$compose_path"
  while read -r digest relative extra; do
    if [[ "$relative" == "deploy/docker-compose.yml" ]]; then
      [[ -z "${extra:-}" && "$digest" =~ ^[0-9a-f]{64}$ ]] || \
        holdfast_die "estate preimage Compose authority is malformed"
      expected_sha=$digest
      ((matches += 1))
    fi
  done <"$backup/APPLY-PREIMAGES.sha256"
  [[ "$matches" == "1" ]] || \
    holdfast_die "estate preimage Compose authority is absent or ambiguous"
  preimage_compose_sha=$(holdfast_sha256 "$compose_path")
  [[ "$preimage_compose_sha" == "$expected_sha" ]] || \
    holdfast_die "estate preimage Compose differs from its frozen preimage"

  output=$("$docker_bin" compose -f "$compose_path" config --no-interpolate --services) || \
    holdfast_die "could not resolve estate preimage Compose services"
  preimage_compose_services=()
  while IFS= read -r service; do
    [[ -n "$service" && "$service" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || \
      holdfast_die "estate preimage Compose contains an unsafe service identity"
    [[ -z "${preimage_compose_services[$service]:-}" ]] || \
      holdfast_die "estate preimage Compose service inventory is duplicated"
    preimage_compose_services["$service"]=1
  done <<<"$output"
  ((${#preimage_compose_services[@]} > 0)) || \
    holdfast_die "estate preimage Compose service inventory is empty"
}

validate_writer_reconciliation_source() {
  local source_state source_failure_name source_failure source_arm_name source_arm
  local source_manifest_name source_manifest source_arm_sha service
  local access_found="false" newapi_found="false"
  local -a source_writers=() expected_writers=()

  source_state="$state_dir/APPLY-RECOVERY-FAILED-${writer_set_source_attempt}.json"
  require_root_file "$source_state"
  [[ "$(holdfast_sha256 "$source_state")" == "$writer_set_source_state_sha" ]] || \
    holdfast_die "writer reconciliation source state was replaced"
  jq -e \
    --arg attempt "$writer_set_source_attempt" --arg backup "$backup" \
    --arg estate "$estate_root" --arg control "$control_sha" \
    --arg transaction "$transaction_sha" --arg writers "$writer_set_source_manifest_sha" \
    --arg failure "$writer_set_source_failure_sha" \
    '.schema_version == 2 and .state == "restore_failed" and
     .recovery_attempt_id == $attempt and .recovery_mode == "restore" and
     .recovery_failure_stage == "restore_prior_running_writers" and
     .backup_dir == $backup and .estate_root == $estate and
     .control_sha256 == $control and .transaction_sha256 == $transaction and
     .restore_running_writers_sha256 == $writers and
     .apply_failure_receipt_sha256 == $failure and
     .recovery_route_database_state == "absent" and .ingress_opened == false' \
    "$source_state" >/dev/null || \
    holdfast_die "writer reconciliation source state authority differs"
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    jq -e \
      '.recovery_prior_state == "apply_activation_failed" and
       (.writer_set_quarantined // "none") == "none"' \
      "$source_state" >/dev/null || \
      holdfast_die "access-chain quarantine source was not an activation failure"
  fi

  source_failure_name=$(jq -er '.apply_failure_receipt' "$source_state")
  [[ "$source_failure_name" =~ ^APPLY-RECOVERY-FAILED-${writer_set_source_attempt}(-retry-[0-9]+)?\.receipt$ ]] || \
    holdfast_die "writer reconciliation source failure identity is unsafe"
  source_failure="$state_dir/$source_failure_name"
  require_root_file "$source_failure"
  [[ "$(holdfast_sha256 "$source_failure")" == "$writer_set_source_failure_sha" ]] || \
    holdfast_die "writer reconciliation source failure was replaced"

  source_arm_name=$(jq -er '.recovery_armed_receipt' "$source_state")
  [[ "$source_arm_name" == "APPLY-RECOVERY-ARMED-${writer_set_source_attempt}.receipt" ]] || \
    holdfast_die "writer reconciliation source arm identity is unsafe"
  source_arm="$state_dir/$source_arm_name"
  require_root_file "$source_arm"
  source_arm_sha=$(holdfast_sha256 "$source_arm")
  [[ "$(jq -er '.recovery_armed_receipt_sha256' "$source_state")" == "$source_arm_sha" && \
    "$(holdfast_receipt_value "$source_failure" recovery_armed_receipt_sha256)" == "$source_arm_sha" ]] || \
    holdfast_die "writer reconciliation source arm was replaced"
  [[ "$(holdfast_receipt_value "$source_failure" attempt_id)" == "$writer_set_source_attempt" && \
    "$(holdfast_receipt_value "$source_failure" mode)" == "restore" && \
    "$(holdfast_receipt_value "$source_failure" stage)" == "restore_prior_running_writers" && \
    "$(holdfast_receipt_value "$source_failure" estate_root)" == "$estate_root" && \
    "$(holdfast_receipt_value "$source_failure" backup_dir)" == "$backup" && \
    "$(holdfast_receipt_value "$source_failure" control_sha256)" == "$control_sha" && \
    "$(holdfast_receipt_value "$source_failure" transaction_sha256)" == "$transaction_sha" && \
    "$(holdfast_receipt_value "$source_failure" restore_running_writers_sha256)" == \
      "$writer_set_source_manifest_sha" && \
    "$(holdfast_receipt_value "$source_failure" route_database_state)" == "absent" && \
    "$(holdfast_receipt_value "$source_failure" ingress_opened)" == "false" ]] || \
    holdfast_die "writer reconciliation source failure authority differs"
  [[ "$(holdfast_receipt_value "$source_arm" attempt_id)" == "$writer_set_source_attempt" && \
    "$(holdfast_receipt_value "$source_arm" mode)" == "restore" && \
    "$(holdfast_receipt_value "$source_arm" control_sha256)" == "$control_sha" && \
    "$(holdfast_receipt_value "$source_arm" transaction_sha256)" == "$transaction_sha" && \
    "$(holdfast_receipt_value "$source_arm" restore_running_writers_sha256)" == \
      "$writer_set_source_manifest_sha" ]] || \
    holdfast_die "writer reconciliation source arm authority differs"
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    [[ "$(holdfast_receipt_value "$source_arm" prior_state)" == \
        "apply_activation_failed" && \
      "$(holdfast_receipt_value "$source_arm" writer_set_quarantined 2>/dev/null || printf none)" == \
        "none" && \
      "$(holdfast_receipt_value "$source_failure" writer_set_quarantined 2>/dev/null || printf none)" == \
        "none" ]] || \
      holdfast_die "access-chain quarantine source receipt authority differs"
  fi

  source_manifest_name=$(jq -er '.restore_running_writers_manifest' "$source_state")
  [[ "$source_manifest_name" == "RESTORE-RUNNING-WRITERS-${writer_set_source_attempt}.txt" ]] || \
    holdfast_die "writer reconciliation source manifest identity is unsafe"
  source_manifest="$state_dir/$source_manifest_name"
  require_root_file "$source_manifest"
  [[ "$(holdfast_sha256 "$source_manifest")" == "$writer_set_source_manifest_sha" ]] || \
    holdfast_die "writer reconciliation source manifest was replaced"
  mapfile -t source_writers <"$source_manifest"
  validate_writer_sequence source_writers
  for service in "${source_writers[@]}"; do
    if [[ "$service" == "access-governance" ]]; then access_found="true"; fi
    if [[ "$service" == "newapi" ]]; then newapi_found="true"; fi
    if [[ -n "${preimage_compose_services[$service]:-}" ]]; then
      if [[ "$writer_set_quarantined" == "access-governance,newapi" && \
        ( "$service" == "access-governance" || "$service" == "newapi" ) ]]; then
        continue
      fi
      expected_writers+=("$service")
    fi
  done
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    [[ "$access_found" == "true" && "$newapi_found" == "true" && \
      -n "${preimage_compose_services[access-governance]:-}" && \
      -n "${preimage_compose_services[newapi]:-}" ]] || \
      holdfast_die "access-chain quarantine source lacks both bound writers"
  elif [[ "$writer_set_quarantined" != "none" ]]; then
    holdfast_die "writer reconciliation carries an unknown quarantine set"
  fi
  ((${#expected_writers[@]} == ${#restore_running_writers[@]})) || \
    holdfast_die "writer reconciliation result differs from estate preimage"
  for index in "${!expected_writers[@]}"; do
    [[ "${expected_writers[$index]}" == "${restore_running_writers[$index]}" ]] || \
      holdfast_die "writer reconciliation result differs from estate preimage"
  done
}

restore_writer_was_running() {
  local wanted=$1 service
  for service in "${restore_running_writers[@]}"; do
    if [[ "$service" == "$wanted" ]]; then return 0; fi
  done
  return 1
}

verify_live_disposition() {
  local expected_mode=$1
  local tree_arg="none"
  if [[ "$transaction_state" != "not_started" ]]; then tree_arg="$backup/estate/tree"; fi
  python3 - "$expected_mode" "$estate_root" "$target_manifest" \
    "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" "$tree_arg" <<'PY'
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

mode, estate_arg, targets_arg, preimages_arg, absent_arg, tree_arg = sys.argv[1:]
estate = Path(estate_arg)
tree = None if tree_arg == "none" else Path(tree_arg)
line_re = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def parse_manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = line_re.fullmatch(line)
        if not match:
            raise RuntimeError(f"invalid recovery manifest: {path}")
        relative = match.group(2)
        if relative.startswith("/") or ".." in Path(relative).parts or relative in result:
            raise RuntimeError(f"unsafe recovery manifest path: {relative}")
        result[relative] = match.group(1)
    return result

def regular_digest(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1 or info.st_uid != 0:
        raise RuntimeError(f"unsafe live recovery target: {path}")
    return digest(path)

def validate_parent_chain(relative: str) -> None:
    current = estate
    for component in Path(relative).parts[:-1]:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise RuntimeError(f"recovery target parent is absent: {relative}") from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or current.is_symlink()
            or info.st_uid != 0
            or current.resolve() != current
        ):
            raise RuntimeError(f"unsafe recovery target parent: {relative}")

targets = parse_manifest(Path(targets_arg))
preimages = parse_manifest(Path(preimages_arg))
absent = {line for line in Path(absent_arg).read_text(encoding="utf-8").splitlines() if line}
if set(targets) != set(preimages) | absent or set(preimages) & absent:
    raise RuntimeError("recovery dispositions do not exactly cover targets")
if tree is not None:
    for relative, expected in preimages.items():
        backup_file = tree / relative
        if regular_digest(backup_file) != expected:
            raise RuntimeError(f"recovery backup tree drift: {relative}")
for relative, applied in targets.items():
    validate_parent_chain(relative)
    live_digest = regular_digest(estate / relative)
    if mode == "applied":
        allowed = {applied}
    elif mode == "mixed":
        allowed = {applied, preimages.get(relative)} if relative in preimages else {applied, None}
    elif mode == "preimage":
        allowed = {preimages[relative]} if relative in preimages else {None}
    else:
        raise RuntimeError(f"unknown recovery disposition mode: {mode}")
    if live_digest not in allowed:
        raise RuntimeError(f"live recovery disposition drift: {relative}")
PY
}

validate_v3_recovery_mutation_authority() {
  local file compensation writer_authority=""
  local -a fence_files=()
  local -A fence_hashes=() fence_identities=()
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  validate_v3_cached_control_authority
  fence_files=(
    "$state_file"
    "$backup/CONTROL.sha256"
    "$target_manifest"
    "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt"
    "$backup/runtime/RUNNING-SERVICES.before"
    "$backup/runtime/compose-config.json"
  )
  if [[ -e "$backup/runtime/BACKUP.receipt" || -L "$backup/runtime/BACKUP.receipt" ]]; then
    fence_files+=("$backup/runtime/BACKUP.receipt" "$backup/runtime/SHA256SUMS")
  fi
  for compensation in RUNTIME-BACKUP-COMPENSATED.receipt \
    RUNTIME-BACKUP-COMPENSATION-FAILED.receipt; do
    if [[ -e "$backup/runtime/$compensation" || -L "$backup/runtime/$compensation" ]]; then
      fence_files+=("$backup/runtime/$compensation")
    fi
  done
  if [[ "$transaction_state" != "not_started" ]]; then
    fence_files+=(
      "$backup/estate/TRANSACTION.json"
      "$backup/estate/PREIMAGES.sha256"
      "$backup/estate/ABSENT.before"
      "$backup/APPLY-PREIMAGES.sha256"
      "$backup/APPLY-ABSENT.paths"
    )
    if [[ "$early_bound_contract" == "true" ]]; then
      fence_files+=("$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256")
    fi
  fi
  if [[ "$mode" == "restore" && "$restore_writers_manifest" != "none" ]]; then
    if [[ -e "$restore_writers_manifest" || -L "$restore_writers_manifest" ]]; then
      writer_authority=$restore_writers_manifest
    elif [[ -n "${restore_writers_tmp:-}" && \
      ( -e "$restore_writers_tmp" || -L "$restore_writers_tmp" ) ]]; then
      writer_authority=$restore_writers_tmp
    else
      holdfast_die "schema-v3 recovery writer authority is absent before mutation"
    fi
    fence_files+=("$writer_authority")
  fi
  if [[ -n "${recovery_armed_receipt:-}" && \
    ( -e "$recovery_armed_receipt" || -L "$recovery_armed_receipt" ) ]]; then
    fence_files+=("$recovery_armed_receipt")
  fi
  for file in "${fence_files[@]}"; do
    require_root_file "$file"
    fence_hashes["$file"]=$(holdfast_sha256 "$file")
    fence_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
  validate_runtime_stop_authority
  validate_runtime_backup_success_authority
  validate_runtime_compensation_authority
  [[ "$(holdfast_sha256 "$target_manifest")" == "$applied_targets_sha" ]] || \
    holdfast_die "schema-v3 recovery applied-target authority changed before mutation"
  if [[ "$transaction_state" == "not_started" ]]; then
    [[ "$transaction_sha" == "not-started" && \
      ! -e "$backup/estate/TRANSACTION.json" && \
      ! -L "$backup/estate/TRANSACTION.json" ]] || \
      holdfast_die "schema-v3 recovery transaction authority changed before mutation"
  else
    require_root_file "$backup/estate/TRANSACTION.json"
    [[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$transaction_sha" && \
      "$(jq -er '.state' "$backup/estate/TRANSACTION.json")" == "$transaction_state" ]] || \
      holdfast_die "schema-v3 recovery transaction authority changed before mutation"
    cmp -s -- "$backup/APPLY-PREIMAGES.sha256" "$backup/estate/PREIMAGES.sha256" || \
      holdfast_die "schema-v3 recovery estate preimage authority changed before mutation"
    cmp -s -- "$backup/APPLY-ABSENT.paths" "$backup/estate/ABSENT.before" || \
      holdfast_die "schema-v3 recovery estate absent authority changed before mutation"
    if [[ "$early_bound_contract" == "true" ]]; then
      cmp -s -- "$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256" || \
        holdfast_die "schema-v3 recovery estate target authority changed before mutation"
    fi
  fi
  if [[ "$transaction_is_preimage" == "true" ]]; then
    verify_live_disposition preimage
  elif [[ "$mode" == "resume" ]]; then
    verify_live_disposition applied
  else
    verify_live_disposition mixed
  fi
  if [[ "$mode" == "restore" && "$restore_writers_manifest" != "none" ]]; then
    require_root_file "$writer_authority"
    if [[ "$writer_authority" == "$restore_writers_manifest" ]]; then
      [[ "$(holdfast_sha256 "$restore_writers_manifest")" == "$restore_writers_sha" ]] || \
        holdfast_die "schema-v3 recovery writer authority changed before mutation"
    fi
  fi
  for file in "${fence_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${fence_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${fence_identities[$file]}" ]] || \
      holdfast_die "schema-v3 recovery authority changed during live mutation validation: $file"
  done
  validate_v3_cached_control_authority
}

validate_v3_active_recovery_arm_authority() {
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  validate_v3_cached_control_authority
  require_root_file "$state_file"
  require_root_file "$recovery_armed_receipt"
  [[ "$(holdfast_sha256 "$recovery_armed_receipt")" == "$recovery_armed_sha" ]] || \
    holdfast_die "schema-v3 active recovery arm was replaced"
  validate_successor_lineage_receipt "$recovery_armed_receipt"
  jq -e \
    --arg attempt "$attempt_id" --arg mode "$mode" --arg backup "$backup" \
    --arg estate "$estate_root" --arg armed "$(basename -- "$recovery_armed_receipt")" \
    --arg armed_sha "$recovery_armed_sha" --arg transaction "$transaction_sha" \
    --arg targets "$applied_targets_sha" \
    '.state == "apply_recovery_armed" and .recovery_attempt_id == $attempt and
     .recovery_mode == $mode and .backup_dir == $backup and .estate_root == $estate and
     .recovery_armed_receipt == $armed and .recovery_armed_receipt_sha256 == $armed_sha and
     .transaction_sha256 == $transaction and .applied_targets_sha256 == $targets and
     .ingress_opened == false' "$state_file" >/dev/null || \
    holdfast_die "schema-v3 active recovery state differs from its arm"
}

validate_v3_recovery_completion_fence() {
  local receipt=$1 completed=$2 expected_current_sha=$3 expected_receipt_sha=$4
  local expected_completed_sha=$5
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  validate_v3_cached_control_authority
  require_root_file "$state_file"
  require_root_file "$receipt"
  require_root_file "$completed"
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(holdfast_sha256 "$receipt")" == "$expected_receipt_sha" && \
    "$(holdfast_sha256 "$completed")" == "$expected_completed_sha" ]] || \
    holdfast_die "schema-v3 recovery completion authority changed before finalization"
  validate_v3_active_recovery_arm_authority
  validate_v3_recovery_mutation_authority
  validate_successor_lineage_receipt "$receipt"
  jq -e \
    --arg state "$([[ "$mode" == "resume" ]] && printf apply_recovered_resumed || printf apply_recovered_restored)" \
    --arg receipt "$(basename -- "$receipt")" --arg receipt_sha "$expected_receipt_sha" \
    --arg armed "$(basename -- "$recovery_armed_receipt")" \
    --arg armed_sha "$recovery_armed_sha" --arg transaction "$transaction_sha" \
    --arg targets "$applied_targets_sha" \
    '.state == $state and .recovery_receipt == $receipt and
     .recovery_receipt_sha256 == $receipt_sha and .recovery_armed_receipt == $armed and
     .recovery_armed_receipt_sha256 == $armed_sha and .transaction_sha256 == $transaction and
     .applied_targets_sha256 == $targets and .ingress_opened == false' "$completed" >/dev/null || \
    holdfast_die "schema-v3 recovery completion state differs from its receipts"
  if [[ "$mode" == "restore" ]]; then
    verify_live_disposition preimage
    verify_live_quarantine_absence
    verify_restore_writer_runtime_disposition
    require_root_file "$predecessor_current_file"
    [[ "$(holdfast_sha256 "$predecessor_current_file")" == "$predecessor_current_sha" ]] || \
      holdfast_die "schema-v3 recovery predecessor CURRENT changed before finalization"
  else
    verify_live_disposition applied
    "${compose[@]}" config --quiet
    run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
  fi
  validate_v3_active_recovery_arm_authority
  validate_v3_recovery_mutation_authority
  validate_v3_cached_control_authority
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(holdfast_sha256 "$receipt")" == "$expected_receipt_sha" && \
    "$(holdfast_sha256 "$completed")" == "$expected_completed_sha" ]] || \
    holdfast_die "schema-v3 recovery completion authority changed during finalization validation"
}

validate_v3_completed_terminal_local_fence() {
  local expected_current_sha=$1 expected_current_identity=$2
  [[ "$v3_completed_terminal_snapshot_active" == "true" ]] || return 0
  validate_v3_cached_control_authority
  require_root_file "$state_file"
  require_root_file "$completed_state_match"
  require_root_file "$v3_completed_terminal_receipt"
  require_root_file "$v3_completed_terminal_armed"
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$expected_current_identity" && \
    "$(holdfast_sha256 "$completed_state_match")" == "$v3_completed_terminal_state_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$completed_state_match")" == \
      "$v3_completed_terminal_state_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_identity" ]] || \
    holdfast_die "schema-v3 completed recovery terminal authority changed"
  (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
  validate_successor_lineage_receipt "$v3_completed_terminal_receipt"
  validate_successor_lineage_receipt "$v3_completed_terminal_armed"
  jq -e \
    --arg receipt "$(basename -- "$v3_completed_terminal_receipt")" \
    --arg receipt_sha "$v3_completed_terminal_receipt_sha" \
    --arg armed "$(basename -- "$v3_completed_terminal_armed")" \
    --arg armed_sha "$v3_completed_terminal_armed_sha" \
    '.recovery_receipt == $receipt and .recovery_receipt_sha256 == $receipt_sha and
     .recovery_armed_receipt == $armed and .recovery_armed_receipt_sha256 == $armed_sha' \
    "$completed_state_match" >/dev/null || \
    holdfast_die "schema-v3 completed recovery terminal state differs from its receipts"
}

validate_v3_completed_terminal_authority() {
  local expected_current_sha=$1 expected_current_identity=$2
  [[ "$v3_completed_terminal_snapshot_active" == "true" ]] || return 0
  validate_v3_completed_terminal_local_fence "$expected_current_sha" "$expected_current_identity"
  require_root_file "$state_file"
  require_root_file "$completed_state_match"
  require_root_file "$v3_completed_terminal_receipt"
  require_root_file "$v3_completed_terminal_armed"
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$expected_current_identity" && \
    "$(holdfast_sha256 "$completed_state_match")" == "$v3_completed_terminal_state_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$completed_state_match")" == \
      "$v3_completed_terminal_state_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_identity" ]] || \
    holdfast_die "schema-v3 completed recovery terminal authority changed during external verification"
  revalidate_v3_successor_authority "$completed_state_match"
  validate_successor_lineage_receipt "$v3_completed_terminal_receipt"
  validate_successor_lineage_receipt "$v3_completed_terminal_armed"
  jq -e \
    --arg receipt "$(basename -- "$v3_completed_terminal_receipt")" \
    --arg receipt_sha "$v3_completed_terminal_receipt_sha" \
    --arg armed "$(basename -- "$v3_completed_terminal_armed")" \
    --arg armed_sha "$v3_completed_terminal_armed_sha" \
    '.recovery_receipt == $receipt and .recovery_receipt_sha256 == $receipt_sha and
     .recovery_armed_receipt == $armed and .recovery_armed_receipt_sha256 == $armed_sha' \
    "$completed_state_match" >/dev/null || \
    holdfast_die "schema-v3 completed recovery terminal state differs from its receipts"
  [[ "$(holdfast_sha256 "$state_file")" == "$expected_current_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == "$expected_current_identity" && \
    "$(holdfast_sha256 "$completed_state_match")" == "$v3_completed_terminal_state_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$completed_state_match")" == \
      "$v3_completed_terminal_state_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_receipt")" == \
      "$v3_completed_terminal_receipt_identity" && \
    "$(holdfast_sha256 "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$v3_completed_terminal_armed")" == \
      "$v3_completed_terminal_armed_identity" ]] || \
    holdfast_die "schema-v3 completed recovery terminal authority changed during revalidation"
  validate_v3_completed_terminal_local_fence "$expected_current_sha" "$expected_current_identity"
}

pre_restored_retry="false"
pre_restored_source_attempt="none"
pre_restored_runtime_snapshot="none"
pre_restored_estate_snapshot="none"
pre_restored_superseded_attempt="none"
pre_restored_superseded_failure_sha="none"
pre_restored_superseded_state_sha="none"
pre_restored_runtime_disposition="not-applicable"
writer_set_quarantined="none"

pre_restored_runtime_writers_are_inactive() {
  local service output state
  local -a ids
  for service in strad rikune-analyzer rikune-volume-init; do
    ids=()
    output=$(service_container_ids "$service") || \
      holdfast_die "could not inspect runtime writer before pre-restored retry: $service"
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || \
      holdfast_die "multiple runtime writer containers exist before pre-restored retry: $service"
    if ((${#ids[@]})); then
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}") || \
        holdfast_die "could not inspect runtime writer state before pre-restored retry: $service"
      case "$state" in
        created|exited|dead) ;;
        running|restarting|paused) return 1 ;;
        *) holdfast_die "runtime writer has an unknown state before pre-restored retry: $service" ;;
      esac
    fi
  done
  return 0
}

verify_legacy_pre_restored_runtime_disposition() {
  local logical volume_state actual extra volume_output volume_count=0 volume_name
  local database_exists public_tables user_relations connections
  local -a frozen_compose
  local -a expected_volumes=(
    strad_uploads
    rikune_workspaces
    rikune_storage
    rikune_state
    rikune_cache
    rikune_audit
  )
  [[ "$legacy_empty_strad" == "true" ]] || return 1
  pre_restored_runtime_writers_are_inactive || return 1

  volume_output=$("$docker_bin" volume ls --format '{{.Name}}') || \
    holdfast_die "could not inspect runtime volumes before pre-restored retry"
  while IFS=$'\t' read -r logical volume_state actual extra; do
    [[ "$logical" == "${expected_volumes[$volume_count]:-}" ]] || \
      holdfast_die "legacy pre-restored retry volume set or order differs"
    ((volume_count += 1))
    [[ -z "${extra:-}" && "$volume_state" == "absent" && \
      "$actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
      holdfast_die "legacy pre-restored retry volume authority differs"
    while IFS= read -r volume_name; do
      [[ -z "$volume_name" || "$volume_name" != "$actual" ]] || return 1
    done <<<"$volume_output"
  done <"$backup/runtime/VOLUMES.tsv"
  [[ "$volume_count" == "6" ]] || \
    holdfast_die "legacy pre-restored retry volume count differs"

  frozen_compose=("$docker_bin" compose -f "$backup/runtime/compose-config.json")
  # The quoted program is intentionally expanded inside the PostgreSQL container.
  # shellcheck disable=SC2016
  database_exists=$("${frozen_compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d postgres -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_database WHERE datname = 'strad';
SQL
  ) || holdfast_die "could not verify the pre-restored Strad database identity"
  [[ "$database_exists" == "1" ]] || return 1
  # The quoted program is intentionally expanded inside the PostgreSQL container.
  # shellcheck disable=SC2016
  public_tables=$("${frozen_compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d strad -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_tables WHERE schemaname = 'public';
SQL
  ) || holdfast_die "could not verify the pre-restored Strad public schema"
  [[ "$public_tables" == "0" ]] || return 1
  # The quoted program is intentionally expanded inside the PostgreSQL container.
  # shellcheck disable=SC2016
  user_relations=$("${frozen_compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d strad -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*)
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname !~ '^pg_toast'
   AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f');
SQL
  ) || holdfast_die "could not verify the pre-restored Strad relations"
  [[ "$user_relations" == "0" ]] || return 1
  # The quoted program is intentionally expanded inside the PostgreSQL container.
  # shellcheck disable=SC2016
  connections=$("${frozen_compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d postgres -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_stat_activity WHERE datname = 'strad';
SQL
  ) || holdfast_die "could not verify pre-restored Strad connections"
  [[ "$connections" == "0" ]] || return 1
  return 0
}

qualify_pre_restored_retry() {
  local expected_source_attempt=${1:-}
  local current_writers_sha candidate_state candidate_attempt candidate_failure_name
  local candidate_failure candidate_arm_name candidate_arm candidate_writers_name
  local candidate_writers expected_restore_mode expected_database_restore found
  local qualified_attempt qualified_runtime_sha qualified_estate_sha
  local superseded_attempt superseded_failure_sha superseded_state_sha
  local -a candidate_states runtime_snapshots estate_snapshots

  [[ "$legacy_empty_strad" == "true" ]] || return 1
  current_writers_sha=$(jq -er '.restore_running_writers_sha256' "$state_file") || return 1
  [[ "$current_writers_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  found="false"
  shopt -s nullglob
  candidate_states=("$state_dir"/APPLY-RECOVERY-FAILED-*.json)
  shopt -u nullglob
  for candidate_state in "${candidate_states[@]}"; do
    require_root_file "$candidate_state"
    if ! jq -e \
      --arg backup "$backup" --arg estate "$estate_root" \
      --arg transaction "$transaction_sha" --arg targets "$applied_targets_sha" \
      --arg writers_sha "$current_writers_sha" --argjson legacy "$legacy_empty_strad" \
      '.schema_version == 2 and .state == "restore_failed" and
       .backup_dir == $backup and .estate_root == $estate and
       .recovery_mode == "restore" and
       (.recovery_failure_stage == "restore_prior_running_writers" or
        .recovery_failure_stage == "post_recovery_closed_bracket") and
       .transaction_sha256 == $transaction and
       .applied_targets_sha256 == $targets and
       .restore_running_writers_sha256 == $writers_sha and
       .legacy_empty_strad == $legacy and
       .recovery_route_database_state == "absent" and
       .ingress_opened == false' "$candidate_state" >/dev/null; then
      continue
    fi

    candidate_attempt=$(jq -er '.recovery_attempt_id' "$candidate_state")
    [[ "$candidate_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
      "$(basename -- "$candidate_state")" == "APPLY-RECOVERY-FAILED-${candidate_attempt}.json" ]] || \
      holdfast_die "pre-restored retry failure state identity is unsafe"
    if [[ -n "$expected_source_attempt" && \
      "$candidate_attempt" != "$expected_source_attempt" ]]; then
      continue
    fi

    candidate_failure_name=$(jq -er '.apply_failure_receipt' "$candidate_state")
    [[ "$candidate_failure_name" =~ ^APPLY-RECOVERY-FAILED-${candidate_attempt}(-retry-[0-9]+)?\.receipt$ ]] || \
      holdfast_die "pre-restored retry failure receipt identity is unsafe"
    candidate_failure="$state_dir/$candidate_failure_name"
    require_root_file "$candidate_failure"
    [[ "$(jq -er '.apply_failure_receipt_sha256' "$candidate_state")" == \
      "$(holdfast_sha256 "$candidate_failure")" ]] || \
      holdfast_die "pre-restored retry failure receipt was replaced"
    [[ "$(holdfast_receipt_value "$candidate_failure" attempt_id)" == "$candidate_attempt" && \
      "$(holdfast_receipt_value "$candidate_failure" mode)" == "restore" && \
      "$(holdfast_receipt_value "$candidate_failure" estate_root)" == "$estate_root" && \
      "$(holdfast_receipt_value "$candidate_failure" backup_dir)" == "$backup" && \
      "$(holdfast_receipt_value "$candidate_failure" control_sha256)" == "$control_sha" && \
      "$(holdfast_receipt_value "$candidate_failure" transaction_sha256)" == "$transaction_sha" && \
      "$(holdfast_receipt_value "$candidate_failure" restore_running_writers_sha256)" == \
        "$current_writers_sha" && \
      "$(holdfast_receipt_value "$candidate_failure" route_database_state)" == "absent" && \
      "$(holdfast_receipt_value "$candidate_failure" ingress_opened)" == "false" ]] || \
      holdfast_die "pre-restored retry failure receipt authority differs"
    case "$(holdfast_receipt_value "$candidate_failure" stage)" in
      restore_prior_running_writers|post_recovery_closed_bracket) ;;
      *) holdfast_die "pre-restored retry failure stage differs" ;;
    esac

    candidate_arm_name=$(jq -er '.recovery_armed_receipt' "$candidate_state")
    [[ "$candidate_arm_name" == "APPLY-RECOVERY-ARMED-${candidate_attempt}.receipt" ]] || \
      holdfast_die "pre-restored retry arm identity is unsafe"
    candidate_arm="$state_dir/$candidate_arm_name"
    require_root_file "$candidate_arm"
    [[ "$(jq -er '.recovery_armed_receipt_sha256' "$candidate_state")" == \
      "$(holdfast_sha256 "$candidate_arm")" && \
      "$(holdfast_receipt_value "$candidate_failure" recovery_armed_receipt_sha256)" == \
        "$(holdfast_sha256 "$candidate_arm")" ]] || \
      holdfast_die "pre-restored retry arm was replaced"
    [[ "$(holdfast_receipt_value "$candidate_arm" attempt_id)" == "$candidate_attempt" && \
      "$(holdfast_receipt_value "$candidate_arm" mode)" == "restore" && \
      "$(holdfast_receipt_value "$candidate_arm" estate_root)" == "$estate_root" && \
      "$(holdfast_receipt_value "$candidate_arm" backup_dir)" == "$backup" && \
      "$(holdfast_receipt_value "$candidate_arm" control_sha256)" == "$control_sha" && \
      "$(holdfast_receipt_value "$candidate_arm" transaction_sha256)" == "$transaction_sha" && \
      "$(holdfast_receipt_value "$candidate_arm" applied_targets_sha256)" == \
        "$applied_targets_sha" && \
      "$(holdfast_receipt_value "$candidate_arm" restore_running_writers_sha256)" == \
        "$current_writers_sha" && \
      "$(holdfast_receipt_value "$candidate_arm" legacy_empty_strad)" == "$legacy_empty_strad" ]] || \
      holdfast_die "pre-restored retry arm authority differs"

    candidate_writers_name=$(jq -er '.restore_running_writers_manifest' "$candidate_state")
    [[ "$candidate_writers_name" == "RESTORE-RUNNING-WRITERS-${candidate_attempt}.txt" ]] || \
      holdfast_die "pre-restored retry writer manifest identity is unsafe"
    candidate_writers="$state_dir/$candidate_writers_name"
    require_root_file "$candidate_writers"
    [[ "$(holdfast_sha256 "$candidate_writers")" == "$current_writers_sha" ]] || \
      holdfast_die "pre-restored retry writer manifest differs"
    # If Strad or its analyzer was reactivated before the failed health check,
    # it may already have changed the restored database or volumes. Only a
    # retry whose frozen subset excludes both runtime writers may reuse the
    # earlier runtime restore evidence.
    if grep -Eq '^(strad|rikune-analyzer)$' "$candidate_writers"; then continue; fi

    shopt -s nullglob
    runtime_snapshots=("$state_dir/RUNTIME-RESTORE-${candidate_attempt}-"*.receipt)
    estate_snapshots=("$state_dir/ESTATE-RESTORE-${candidate_attempt}-"*.json)
    shopt -u nullglob
    ((${#runtime_snapshots[@]} == 1 && ${#estate_snapshots[@]} == 1)) || \
      holdfast_die "pre-restored retry lacks an exact runtime or estate snapshot"
    require_root_file "${runtime_snapshots[0]}"
    require_root_file "${estate_snapshots[0]}"
    expected_restore_mode="schema-v2"
    expected_database_restore="restored"
    if [[ "$legacy_empty_strad" == "true" ]]; then
      expected_restore_mode="legacy-empty-strad"
      expected_database_restore="skipped_proven_empty"
    fi
    [[ "$(holdfast_receipt_value "${runtime_snapshots[0]}" schema_version)" == "2" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" restore_mode)" == \
        "$expected_restore_mode" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" database_identity)" == \
        "postgres:5432/strad" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" database_restore)" == \
        "$expected_database_restore" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" runtime_writers_removed)" == "passed" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" volume_mount_release)" == "passed" && \
      "$(holdfast_receipt_value "${runtime_snapshots[0]}" volume_count)" == "6" ]] || \
      holdfast_die "pre-restored retry runtime snapshot differs"
    jq -e '.schema_version == 1 and .state == "restored" and
      .mixed_estate_supported == true' "${estate_snapshots[0]}" >/dev/null || \
      holdfast_die "pre-restored retry estate snapshot differs"

    qualified_attempt="$candidate_attempt"
    qualified_runtime_sha=$(holdfast_sha256 "${runtime_snapshots[0]}") || \
      holdfast_die "could not hash the pre-restored runtime snapshot"
    qualified_estate_sha=$(holdfast_sha256 "${estate_snapshots[0]}") || \
      holdfast_die "could not hash the pre-restored estate snapshot"
    [[ "$qualified_runtime_sha" =~ ^[0-9a-f]{64}$ && \
      "$qualified_estate_sha" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "pre-restored snapshot hash is invalid"
    found="true"
    break
  done
  [[ "$found" == "true" ]] || return 1
  verify_live_disposition preimage || return 1
  verify_legacy_pre_restored_runtime_disposition || return 1

  if [[ "$prior_state" == "restore_failed" ]]; then
    superseded_attempt=$(jq -er '.recovery_attempt_id' "$state_file") || \
      holdfast_die "restore-failed retry lacks a superseded attempt"
    superseded_failure_sha=$(jq -er '.apply_failure_receipt_sha256' "$state_file") || \
      holdfast_die "restore-failed retry lacks a superseded failure receipt"
    superseded_state_sha=$(holdfast_sha256 "$state_file") || \
      holdfast_die "could not hash the superseded recovery state"
    [[ "$superseded_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
      "$superseded_failure_sha" =~ ^[0-9a-f]{64}$ && \
      "$superseded_state_sha" =~ ^[0-9a-f]{64}$ ]] || \
      holdfast_die "superseded recovery authority is invalid"
    pre_restored_superseded_attempt="$superseded_attempt"
    pre_restored_superseded_failure_sha="$superseded_failure_sha"
    pre_restored_superseded_state_sha="$superseded_state_sha"
  fi
  pre_restored_retry="true"
  pre_restored_source_attempt="$qualified_attempt"
  pre_restored_runtime_snapshot="$qualified_runtime_sha"
  pre_restored_estate_snapshot="$qualified_estate_sha"
  pre_restored_runtime_disposition="legacy-empty-strad+six-volumes-absent+runtime-writers-inactive"
}

snapshot_verify_completed_tree() {
  local root=$1 output=$2 inventory path relative metadata digest
  local root_device path_device
  inventory="$output.paths"
  root_device=$(stat -c '%d' -- "$root") || \
    holdfast_die "could not inspect completed recovery tree root: $root"
  : >"$inventory"
  chmod 0600 -- "$inventory"
  if ! find -P "$root" -xdev -print0 | sort -z >"$inventory"; then
    rm -f -- "$inventory" "$output"
    holdfast_die "could not enumerate completed recovery tree: $root"
  fi
  : >"$output"
  chmod 0600 -- "$output"
  while IFS= read -r -d '' path; do
    path_device=$(stat -c '%d' -- "$path") || \
      holdfast_die "could not inspect completed recovery path device: $path"
    [[ "$path_device" == "$root_device" ]] || \
      holdfast_die "completed recovery tree contains a cross-device subtree: $path"
    if [[ "$path" == "$root" ]]; then relative=.; else relative=${path#"$root"/}; fi
    metadata=$(stat -c '%F|%a|%u|%g|%h|%s|%y' -- "$path") || \
      holdfast_die "could not snapshot completed recovery path: $path"
    digest=-
    if [[ -f "$path" && ! -L "$path" ]]; then
      digest=$(holdfast_sha256 "$path") || \
        holdfast_die "could not hash completed recovery path: $path"
    fi
    printf '%q\t%s\t%s\n' "$relative" "$metadata" "$digest" >>"$output"
  done <"$inventory"
  rm -f -- "$inventory"
}

verify_completed_manifest="$backup/estate/APPLIED-TARGETS.sha256"
verify_completed_manifest_copy=""
verify_completed_manifest_sha=""
verify_completed_manifest_identity=""
verify_completed_estate_ancestors=()
verify_completed_estate_targets=()
declare -A verify_completed_estate_target_hashes=()

prepare_verify_completed_estate_fence() {
  local digest relative component ancestor expected_count index parsed_manifest
  local -a components=()
  local -A seen_targets=() seen_ancestors=()

  require_root_file "$verify_completed_manifest"
  verify_completed_manifest_sha=$(holdfast_sha256 "$verify_completed_manifest")
  verify_completed_manifest_identity=$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- \
    "$verify_completed_manifest")
  verify_completed_manifest_copy="$verify_workspace/APPLIED-TARGETS.authority"
  cp -- "$verify_completed_manifest" "$verify_completed_manifest_copy"
  chmod 0600 -- "$verify_completed_manifest_copy"
  [[ "$(holdfast_sha256 "$verify_completed_manifest")" == \
      "$verify_completed_manifest_sha" && \
    "$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- \
      "$verify_completed_manifest")" == "$verify_completed_manifest_identity" && \
    "$(holdfast_sha256 "$verify_completed_manifest_copy")" == \
      "$verify_completed_manifest_sha" ]] || \
    holdfast_die "completed recovery applied-target manifest changed while freezing authority"

  verify_completed_estate_ancestors=("$estate_root")
  seen_ancestors["$estate_root"]=1
  verify_completed_estate_targets=()
  verify_completed_estate_target_hashes=()
  expected_count=$(jq -er \
    '.target_count | select(type == "number" and floor == . and . > 0)' \
    "$backup/estate/TRANSACTION.json") || \
    holdfast_die "completed recovery estate transaction target count is invalid"
  parsed_manifest="$verify_workspace/APPLIED-TARGETS.parsed"
  if ! python3 - "$verify_completed_manifest_copy" "$expected_count" \
    >"$parsed_manifest" <<'PY'
import re
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
expected_count = int(sys.argv[2])
try:
    raw = manifest.read_bytes()
    text = raw.decode("ascii")
except (OSError, UnicodeDecodeError) as error:
    raise SystemExit(f"applied-target manifest is not readable ASCII: {error}")
if not text or not text.endswith("\n"):
    raise SystemExit("applied-target manifest is empty or lacks its final newline")
seen: set[str] = set()
rows: list[tuple[str, str]] = []
for line in text[:-1].split("\n"):
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
    if match is None:
        raise SystemExit("applied-target manifest contains a malformed line")
    digest, relative = match.groups()
    components = relative.split("/")
    if relative.startswith("/") or any(part in {"", ".", ".."} for part in components):
        raise SystemExit(f"applied-target manifest contains an unsafe path: {relative}")
    if relative in seen:
        raise SystemExit(f"applied-target manifest repeats a path: {relative}")
    seen.add(relative)
    rows.append((digest, relative))
if len(rows) != expected_count:
    raise SystemExit("applied-target manifest target count differs")
for digest, relative in rows:
    print(f"{digest}\t{relative}")
PY
  then
    holdfast_die "completed recovery applied-target manifest is malformed or unsafe"
  fi
  chmod 0600 -- "$parsed_manifest"
  while IFS=$'\t' read -r digest relative; do
    IFS=/ read -r -a components <<<"$relative"
    for component in "${components[@]}"; do
      [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || \
        holdfast_die "completed recovery applied-target manifest contains an unsafe path"
    done
    [[ -z "${seen_targets[$relative]+x}" ]] || \
      holdfast_die "completed recovery applied-target manifest repeats a path"
    seen_targets["$relative"]=1
    verify_completed_estate_targets+=("$relative")
    verify_completed_estate_target_hashes["$relative"]=$digest

    ancestor=$estate_root
    for ((index = 0; index + 1 < ${#components[@]}; index++)); do
      ancestor+="/${components[$index]}"
      if [[ -z "${seen_ancestors[$ancestor]+x}" ]]; then
        seen_ancestors["$ancestor"]=1
        verify_completed_estate_ancestors+=("$ancestor")
      fi
    done
  done <"$parsed_manifest"
  ((${#verify_completed_estate_targets[@]} > 0)) || \
    holdfast_die "completed recovery applied-target manifest is empty"
  [[ "$expected_count" == "${#verify_completed_estate_targets[@]}" ]] || \
    holdfast_die "completed recovery estate transaction target count differs"
}

snapshot_verify_completed_estate_targets() {
  local output=$1 path relative metadata digest
  : >"$output"
  chmod 0600 -- "$output"
  require_root_file "$verify_completed_manifest"
  if [[ "$(holdfast_sha256 "$verify_completed_manifest")" == \
      "$verify_completed_manifest_sha" && \
    "$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- \
      "$verify_completed_manifest")" == "$verify_completed_manifest_identity" ]] && \
    cmp -s -- "$verify_completed_manifest" "$verify_completed_manifest_copy"; then
    :
  else
    holdfast_die "completed recovery applied-target manifest authority changed"
  fi

  for path in "${verify_completed_estate_ancestors[@]}"; do
    require_canonical_root_dir "$path"
    metadata=$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- "$path") || \
      holdfast_die "could not snapshot completed recovery target ancestor: $path"
    printf 'ancestor\t%q\t%s\n' "$path" "$metadata" >>"$output"
  done
  for relative in "${verify_completed_estate_targets[@]}"; do
    path="$estate_root/$relative"
    require_root_file "$path"
    metadata=$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- "$path") || \
      holdfast_die "could not snapshot completed recovery target: $path"
    digest=$(holdfast_sha256 "$path") || \
      holdfast_die "could not hash completed recovery target: $path"
    [[ "$digest" == "${verify_completed_estate_target_hashes[$relative]}" ]] || \
      holdfast_die "completed recovery target content differs from applied manifest: $relative"
    printf 'target\t%q\t%s\t%s\n' "$relative" "$metadata" "$digest" >>"$output"
  done
}

snapshot_verify_completed_estate() {
  local output=$1 part
  : >"$output"
  chmod 0600 -- "$output"
  for part in state backup predecessor estate; do
    printf 'root=%s\n' "$part" >>"$output"
    case "$part" in
      state) snapshot_verify_completed_tree "$state_dir" "$output.$part" ;;
      backup) snapshot_verify_completed_tree "$backup" "$output.$part" ;;
      predecessor) snapshot_verify_completed_tree "$predecessor_backup" "$output.$part" ;;
      estate) snapshot_verify_completed_estate_targets "$output.$part" ;;
    esac
    cat "$output.$part" >>"$output"
    rm -f -- "$output.$part"
  done
}

snapshot_verify_completed_inputs() {
  local output=$1 item label path metadata
  : >"$output"
  chmod 0600 -- "$output"
  validate_verify_completed_helper \
    "$runtime_verify" "$runtime_verify_helper_fence" "runtime verification"
  validate_verify_completed_helper \
    "$public_verify" "$public_verify_helper_fence" "public verification"
  validate_verify_completed_helper \
    "$completion_attestation_tool" "$completion_attestation_helper_fence" \
    "completion attestation"
  for item in \
    "current|$state_file" \
    "completion_archive|$completed_state_match" \
    "completion_receipt|$verify_completed_receipt" \
    "recovery_armed_receipt|$verify_completed_armed" \
    "prior_failure_receipt|$verify_prior_failure_receipt" \
    "apply_armed_receipt|$armed_receipt" \
    "predecessor_current|$predecessor_current_file" \
    "successor_armed|$successor_armed_receipt" \
    "control|$backup/CONTROL.sha256" \
    "release_env|$backup/release.env" \
    "release_evidence|$backup/RELEASE-EVIDENCE.json" \
    "transaction|$backup/estate/TRANSACTION.json" \
    "applied_targets|$backup/estate/APPLIED-TARGETS.sha256" \
    "runtime_receipt|$backup/runtime/BACKUP.receipt" \
    "runtime_manifest|$backup/runtime/SHA256SUMS" \
    "predecessor_control|$predecessor_backup/CONTROL.sha256" \
    "predecessor_apply|$predecessor_backup/APPLY.receipt" \
    "predecessor_release_evidence|$predecessor_backup/RELEASE-EVIDENCE.json" \
    "predecessor_runtime_receipt|$predecessor_backup/runtime/BACKUP.receipt" \
    "predecessor_runtime_manifest|$predecessor_backup/runtime/SHA256SUMS" \
    "runtime_verify_helper|$runtime_verify" \
    "public_verify_helper|$public_verify" \
    "completion_attestation_helper|$completion_attestation_tool"; do
    label=${item%%|*}
    path=${item#*|}
    require_root_file "$path"
    metadata=$(stat -c '%d|%i|%F|%a|%u|%g|%h|%s|%y|%z' -- "$path")
    printf '%s\t%s\t%s\n' "$label" "$metadata" "$(holdfast_sha256 "$path")" >>"$output"
  done
  validate_verify_completed_helper \
    "$runtime_verify" "$runtime_verify_helper_fence" "runtime verification"
  validate_verify_completed_helper \
    "$public_verify" "$public_verify_helper_fence" "public verification"
  validate_verify_completed_helper \
    "$completion_attestation_tool" "$completion_attestation_helper_fence" \
    "completion attestation"
}

require_verify_completed_utc() {
  local value=$1 label=$2 normalized
  [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    holdfast_die "completed recovery attestation $label is not UTC"
  normalized=$(date -u -d "$value" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || \
    holdfast_die "completed recovery attestation $label is invalid"
  [[ "$normalized" == "$value" ]] || \
    holdfast_die "completed recovery attestation $label is not canonical UTC"
}

prepare_verify_completed_ceremony() {
  local current_schema archive_schema receipt_name armed_name attempt
  local prior_failure_name prior_failure_sha
  [[ "$mode" == "resume" && "$runtime_schema" == "2" && \
    "$legacy_empty_strad" == "false" && "$quarantine_access_chain" == "false" ]] || \
    holdfast_die "completed recovery attestation only supports schema-v2 resume completion"
  [[ -n "$completed_state_match" ]] || \
    holdfast_die "completed recovery attestation requires one completion archive"
  [[ "$prior_state" == "applied_ingress_closed" && \
    "$successor_completed_pointer" == "false" && "$transaction_state" == "applied" && \
    "$legacy_orphan" == "false" ]] || \
    holdfast_die "completed recovery attestation requires the active completed resume state"
  [[ "$backup_expected_successor" == "true" && "$successor_recovery" == "true" && \
    "$predecessor_generation" == "2" && "$release_generation" == "3" ]] || \
    holdfast_die "completion attestation v1 requires current-production successor generation 2 -> 3"
  jq -se \
    'all(.[];
      .successor == true and
      .predecessor_release_generation == 2 and
      .release_generation == 3)' \
    "$state_file" "$completed_state_match" >/dev/null || \
    holdfast_die "completion attestation v1 requires current-production successor generation 2 -> 3"
  verify_completed_historical_apply_armed_structure "$armed_receipt"
  verify_completed_exact_json_schema "$state_file" "CURRENT" \
    "${verify_completed_current_keys[@]}"
  verify_completed_exact_json_schema "$completed_state_match" "archive" \
    "${verify_completed_archive_keys[@]}"
  [[ ! -e "$apply_receipt" && ! -L "$apply_receipt" && \
    ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]] || \
    holdfast_die "completed recovery attestation forbids APPLY finalization receipts"
  require_root_file "$state_file"
  current_schema=$(jq -er '.schema_version' "$state_file")
  archive_schema=$(jq -er '.schema_version' "$completed_state_match")
  [[ "$current_schema" == "2" && "$archive_schema" == "2" ]] || \
    holdfast_die "completed recovery attestation requires schema-v2 state"
  jq -se \
    'all(.[]; .recovery_prior_state == "apply_activation_failed")' \
    "$state_file" "$completed_state_match" >/dev/null || \
    holdfast_die "completion attestation v1 supports only direct apply_activation_failed -> first resume completion; recovery retries are unsupported"
  jq -e \
    --arg backup "$backup" --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "applied_ingress_closed" and
     .backup_dir == $backup and .estate_root == $estate and
     .services_activated == true and .runtime_verified == true and
     .ingress_opened == false' "$state_file" >/dev/null || \
    holdfast_die "active completed resume claims differ"
  jq -e \
    --arg backup "$backup" --arg estate "$estate_root" \
    '.schema_version == 2 and .state == "apply_recovered_resumed" and
     .backup_dir == $backup and .estate_root == $estate and
     .recovery_mode == "resume" and .ingress_opened == false' \
    "$completed_state_match" >/dev/null || \
    holdfast_die "immutable completed resume claims differ"
  receipt_name=$(jq -er '.recovery_receipt' "$completed_state_match")
  armed_name=$(jq -er '.recovery_armed_receipt' "$completed_state_match")
  [[ "$receipt_name" =~ ^APPLY-RECOVERY-COMPLETE-([0-9]{8}T[0-9]{6}Z-[0-9]+)\.receipt$ ]] || \
    holdfast_die "completed recovery attestation receipt identity is unsafe"
  attempt=${BASH_REMATCH[1]}
  [[ "$(basename -- "$completed_state_match")" == \
      "APPLY-RECOVERY-COMPLETE-${attempt}.json" && \
    "$armed_name" == "APPLY-RECOVERY-ARMED-${attempt}.receipt" && \
    "$(jq -er '.recovery_attempt_id' "$state_file")" == "$attempt" && \
    "$(jq -er '.recovery_attempt_id' "$completed_state_match")" == "$attempt" ]] || \
    holdfast_die "completed recovery attestation attempt linkage differs"
  verify_completed_attempt=$attempt
  verify_completed_receipt="$state_dir/$receipt_name"
  verify_completed_armed="$state_dir/$armed_name"
  require_root_file "$verify_completed_receipt"
  require_root_file "$verify_completed_armed"
  verify_completed_exact_receipt_schema \
    "$verify_completed_receipt" "completion receipt" \
    "${verify_completed_completion_keys[@]}"
  verify_completed_exact_receipt_schema \
    "$verify_completed_armed" "recovery arm receipt" \
    "${verify_completed_recovery_armed_keys[@]}"
  verify_recovery_armed_at=$(holdfast_receipt_value \
    "$verify_completed_armed" armed_at)
  verify_recovery_completed_at=$(holdfast_receipt_value \
    "$verify_completed_receipt" completed_at)
  require_verify_completed_utc "$verify_recovery_armed_at" "recovery armed time"
  require_verify_completed_utc "$verify_recovery_completed_at" "recovery completion time"
  if [[ "$verify_recovery_armed_at" > "$verify_recovery_completed_at" ]]; then
    holdfast_die "completed recovery attestation recovery timestamps are out of order"
  fi
  [[ "$(jq -er '.recovery_receipt_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$verify_completed_receipt")" && \
    "$(jq -er '.recovery_receipt_sha256' "$completed_state_match")" == \
      "$(holdfast_sha256 "$verify_completed_receipt")" && \
    "$(jq -er '.recovery_armed_receipt_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$verify_completed_armed")" && \
    "$(jq -er '.recovery_armed_receipt_sha256' "$completed_state_match")" == \
      "$(holdfast_sha256 "$verify_completed_armed")" ]] || \
    holdfast_die "completed recovery attestation immutable receipt linkage differs"
  prior_failure_name=$(jq -er '.apply_failure_receipt' "$state_file")
  [[ "$prior_failure_name" == "$(jq -er '.apply_failure_receipt' "$completed_state_match")" && \
    "$prior_failure_name" =~ ^APPLY-ACTIVATION-FAILED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ ]] || \
    holdfast_die "completion attestation v1 supports only direct apply_activation_failed -> first resume completion; recovery retries are unsupported"
  verify_prior_failure_receipt="$state_dir/$prior_failure_name"
  require_root_file "$verify_prior_failure_receipt"
  verify_completed_exact_receipt_schema \
    "$verify_prior_failure_receipt" "activation failure receipt" \
    "${verify_completed_activation_failure_keys[@]}"
  prior_failure_sha=$(holdfast_sha256 "$verify_prior_failure_receipt")
  [[ "$(jq -er '.apply_failure_receipt_sha256' "$state_file")" == \
      "$prior_failure_sha" && \
    "$(jq -er '.apply_failure_receipt_sha256' "$completed_state_match")" == \
      "$prior_failure_sha" ]] || \
    holdfast_die "completed recovery attestation prior failure receipt was replaced"
  verify_prior_failure_sha=$prior_failure_sha
  verify_apply_armed_at=$(holdfast_receipt_value "$armed_receipt" armed_at)
  require_verify_completed_utc "$verify_apply_armed_at" "apply armed time"

  require_canonical_root_dir "$release_root"
  [[ -z "$(find "$release_root" -maxdepth 0 -perm /077 -print -quit)" ]] || \
    holdfast_die "completion attestation release root must be private"
  for protected_root in "$state_dir" "$backup" "$predecessor_backup" "$estate_root"; do
    case "$release_root/" in
      "$protected_root/"*)
        holdfast_die "completion attestation release root must be disjoint from protected storage" ;;
    esac
    case "$protected_root/" in
      "$release_root/"*)
        holdfast_die "completion attestation release root must be disjoint from protected storage" ;;
    esac
  done
  require_root_file "$signing_key"
  require_root_file "$authority_public_key"
  [[ "$(stat -c '%a' -- "$signing_key")" == "600" ]] || \
    holdfast_die "completion attestation signing key must be mode 0600"
  authority_public_key_sha=$(holdfast_receipt_value \
    "$backup/release.env" AUTHORITY_PUBLIC_KEY_SHA256)
  [[ "$authority_public_key_sha" =~ ^[0-9a-f]{64}$ && \
    "$(holdfast_sha256 "$authority_public_key")" == "$authority_public_key_sha" ]] || \
    holdfast_die "completion attestation public key differs from the release pin"
  verify_workspace_base=/tmp
  require_canonical_root_dir "$verify_workspace_base"
  for protected_root in "$state_dir" "$backup" "$predecessor_backup" "$estate_root"; do
    case "$verify_workspace_base/" in
      "$protected_root/"*)
        holdfast_die "completion attestation workspace base must be outside protected storage" ;;
    esac
  done
  verify_workspace=$(mktemp -d \
    "$verify_workspace_base/holdfast-recovery-completion.XXXXXX")
  chmod 0700 -- "$verify_workspace"
  trap 'rm -rf -- "$verify_workspace"' EXIT
  verify_bundle_root="$verify_workspace/bundle"
  mkdir -- "$verify_bundle_root"
  chmod 0700 -- "$verify_bundle_root"
  prepare_verify_completed_estate_fence
  verify_tree_before="$verify_workspace/tree.before"
  verify_inputs_before="$verify_workspace/inputs.before"
  snapshot_verify_completed_estate "$verify_tree_before"
  snapshot_verify_completed_inputs "$verify_inputs_before"
}

validate_verify_completed_exact_semantics() {
  local expected key value archive_value current_value pointer
  local predecessor_generation_value release_generation_value
  local prior_failure_at prior_failure_step prior_failure_status
  [[ "$completed_mode" == "resume" && "$completed_receipt" == "$verify_completed_receipt" && \
    "$completed_armed" == "$verify_completed_armed" ]] || \
    holdfast_die "completed recovery attestation semantic verifier selected another completion"
  jq -se \
    'all(.[]; .recovery_prior_state == "apply_activation_failed")' \
    "$state_file" "$completed_state_match" >/dev/null || \
    holdfast_die "completed recovery attestation producer transition differs"
  cmp -s \
    <(jq -cS 'del(.state,.services_activated,.runtime_verified)' "$state_file") \
    <(jq -cS 'del(.state,.services_activated,.runtime_verified)' \
      "$completed_state_match") || \
    holdfast_die "completed recovery attestation CURRENT/archive projection differs"
  for expected in \
    "schema_version=1" "successor=true" \
    "successor_armed_receipt=SUCCESSOR-ARMED.receipt" \
    "successor_armed_receipt_sha256=$successor_armed_sha" \
    "predecessor_current_file=PREDECESSOR-CURRENT.json" \
    "predecessor_current_sha256=$predecessor_current_sha" \
    "predecessor_backup_dir=$predecessor_backup" \
    "predecessor_control_sha256=$predecessor_control_sha" \
    "predecessor_apply_receipt_sha256=$predecessor_apply_sha" \
    "predecessor_release_evidence_sha256=$predecessor_release_sha" \
    "predecessor_runtime_backup_receipt_sha256=$predecessor_runtime_receipt_sha" \
    "predecessor_runtime_backup_manifest_sha256=$predecessor_runtime_manifest_sha" \
    "predecessor_release_generation=2" "release_generation=3" \
    "runtime_backup_caller_armed_sha256=$(holdfast_sha256 "$runtime_caller_receipt")" \
    "runtime_backup_stop_authority_sha256=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "completed recovery attestation historical APPLY-ARMED claim differs: $key"
  done
  [[ "$(stat -c '%a' -- "$verify_prior_failure_receipt")" == "600" && \
    "$(wc -l <"$verify_prior_failure_receipt" | tr -d ' ')" == "10" ]] || \
    holdfast_die "completed recovery attestation prior failure receipt shape differs"
  for expected in \
    "phase=activation" "estate_root=$estate_root" "backup_dir=$backup" \
    "apply_armed_receipt_sha256=$armed_receipt_sha" \
    "control_sha256=$control_sha" "transaction_sha256=$transaction_sha" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$verify_prior_failure_receipt" "$key")" == \
      "$value" ]] || \
      holdfast_die "completed recovery attestation prior failure claim differs: $key"
  done
  prior_failure_step=$(holdfast_receipt_value \
    "$verify_prior_failure_receipt" activation_step)
  [[ "$prior_failure_step" == "compose_up" || \
    "$prior_failure_step" == "runtime_verify" ]] || \
    holdfast_die "completed recovery attestation activation failure step differs"
  prior_failure_status=$(holdfast_receipt_value \
    "$verify_prior_failure_receipt" status)
  if [[ ! "$prior_failure_status" =~ ^[1-9][0-9]{0,2}$ ]] || \
    ((10#$prior_failure_status > 255)); then
    holdfast_die "completed recovery attestation activation failure status differs"
  fi
  prior_failure_at=$(holdfast_receipt_value \
    "$verify_prior_failure_receipt" failed_at)
  require_verify_completed_utc "$prior_failure_at" "prior failure time"
  if [[ "$verify_apply_armed_at" > "$prior_failure_at" || \
    "$prior_failure_at" > "$verify_recovery_armed_at" ]]; then
    holdfast_die "completed recovery attestation producer timestamps are out of order"
  fi
  for expected in \
    "schema_version=2" "attempt_id=$verify_completed_attempt" "mode=resume" \
    "estate_root=$estate_root" "backup_dir=$backup" "control_sha256=$control_sha" \
    "original_estate_transaction_state=applied" \
    "original_estate_transaction_sha256=$transaction_sha" \
    "applied_targets_sha256=$applied_targets_sha" "legacy_empty_strad=false" \
    "recovery_armed_receipt_sha256=$completed_armed_sha" \
    "release_evidence_sha256=$release_evidence_sha" \
    "dry_run_receipt_sha256=$dry_receipt_sha" "runtime_verified=passed" \
    "runtime_restore_receipt_sha256=none" "estate_restore_state_sha256=none" \
    "pre_restored_retry=false" "pre_restored_source_attempt=none" \
    "pre_restored_superseded_attempt=none" \
    "pre_restored_superseded_failure_receipt_sha256=none" \
    "pre_restored_superseded_state_sha256=none" \
    "pre_restored_runtime_disposition=not-applicable" \
    "restore_running_writers_manifest=not-applicable" \
    "restore_running_writers_sha256=none" \
    "live_estate_disposition=applied" "route_state=absent" \
    "public_host=analyze.w33d.xyz" \
    "db_public_db_bracket=absent-404-absent" \
    "apply_receipt_created=false" "writer_set_reconciled=false" \
    "writer_set_source_attempt=none" \
    "writer_set_source_failure_receipt_sha256=none" \
    "writer_set_source_state_sha256=none" \
    "writer_set_source_manifest_sha256=none" \
    "writer_set_preimage_compose_sha256=none" "writer_set_quarantined=none" \
    "writers_reactivated=not-applicable" \
    "uncaptured_writers_inactive=not-applicable" \
    "quarantined_writers_inactive=not-applicable"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$completed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "completed recovery attestation completion claim differs: $key"
  done
  for expected in \
    "schema_version=2" "attempt_id=$verify_completed_attempt" "mode=resume" \
    "prior_state=$(jq -er '.recovery_prior_state' "$state_file")" \
    "legacy_orphan_adopted=false" "legacy_empty_strad=false" \
    "estate_root=$estate_root" "backup_dir=$backup" "control_sha256=$control_sha" \
    "runtime_backup_schema=2" "estate_transaction_state=applied" \
    "transaction_sha256=$transaction_sha" "applied_targets_sha256=$applied_targets_sha" \
    "apply_armed_receipt_sha256=$armed_receipt_sha" \
    "release_evidence_sha256=$release_evidence_sha" \
    "dry_run_receipt_sha256=$dry_receipt_sha" "live_disposition=applied" \
    "restore_running_writers_manifest=not-applicable" \
    "restore_running_writers_sha256=none" "writer_set_reconciled=false" \
    "writer_set_source_attempt=none" \
    "writer_set_source_failure_receipt_sha256=none" \
    "writer_set_source_state_sha256=none" \
    "writer_set_source_manifest_sha256=none" \
    "writer_set_preimage_compose_sha256=none" "writer_set_quarantined=none" \
    "pre_restored_retry=false" "pre_restored_source_attempt=none" \
    "pre_restored_runtime_snapshot_sha256=none" \
    "pre_restored_estate_snapshot_sha256=none" \
    "pre_restored_superseded_attempt=none" \
    "pre_restored_superseded_failure_receipt_sha256=none" \
    "pre_restored_superseded_state_sha256=none" \
    "pre_restored_runtime_disposition=not-applicable" \
    "route_state=absent" \
    "public_host=analyze.w33d.xyz" \
    "db_public_db_bracket=absent-404-absent"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$completed_armed" "$key")" == "$value" ]] || \
      holdfast_die "completed recovery attestation arm claim differs: $key"
  done
  for key in schema_version backup_dir estate_root recovery_mode recovery_attempt_id \
    recovery_armed_receipt recovery_armed_receipt_sha256 recovery_receipt \
    recovery_receipt_sha256 apply_armed_receipt_sha256 control_sha256 \
    release_evidence_sha256 dry_run_receipt_sha256 transaction_sha256 \
    applied_targets_sha256 ingress_opened; do
    archive_value=$(jq -er ".${key} | tostring" "$completed_state_match")
    current_value=$(jq -er ".${key} | tostring" "$state_file")
    [[ "$archive_value" == "$current_value" ]] || \
      holdfast_die "completed recovery attestation CURRENT/archive claim differs: $key"
  done
  for expected in \
    "apply_armed_at=$verify_apply_armed_at" \
    "dry_run_receipt_sha256=$dry_receipt_sha" \
    "runtime_backup_caller_armed_sha256=$(holdfast_sha256 "$runtime_caller_receipt")" \
    "runtime_backup_stop_authority_sha256=$(holdfast_sha256 "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt")" \
    "legacy_empty_strad=false" \
    "restore_running_writers_manifest=not-applicable" \
    "restore_running_writers_sha256=none" \
    "pre_restored_retry=false" "pre_restored_source_attempt=none" \
    "pre_restored_runtime_snapshot_sha256=none" \
    "pre_restored_estate_snapshot_sha256=none" \
    "pre_restored_superseded_attempt=none" \
    "pre_restored_superseded_failure_receipt_sha256=none" \
    "pre_restored_superseded_state_sha256=none" \
    "pre_restored_runtime_disposition=not-applicable"; do
    key=${expected%%=*}
    value=${expected#*=}
    for pointer in "$state_file" "$completed_state_match"; do
      [[ "$(jq -er ".${key} | tostring" "$pointer")" == "$value" ]] || \
      holdfast_die "completed recovery attestation historical state authority differs: $key"
    done
  done
  for key in legacy_empty_strad pre_restored_retry writer_set_reconciled; do
    for pointer in "$state_file" "$completed_state_match"; do
      jq -e ".${key} == false and (.${key} | type) == \"boolean\"" \
        "$pointer" >/dev/null || \
        holdfast_die "completed recovery attestation historical state authority differs: $key"
    done
  done
  predecessor_generation_value=2
  release_generation_value=3
  verify_predecessor_generation=$predecessor_generation_value
  verify_release_generation=$release_generation_value
}

if [[ "$verify_completed" == "true" ]]; then
  prepare_verify_completed_ceremony
fi

finalize_interrupted_apply="false"
if [[ -e "$apply_receipt" || -e "$pending_apply_receipt" || \
  "$prior_state" == "apply_finalizing_ingress_closed" ]]; then
  finalize_interrupted_apply="true"
fi
if [[ "$finalize_interrupted_apply" == "true" ]]; then
  [[ "$mode" == "resume" ]] || holdfast_die "interrupted apply finalization requires resume mode"
  [[ "$legacy_orphan" == "false" && "$early_bound_contract" == "true" && \
    "$transaction_state" == "applied" ]] || \
    holdfast_die "apply finalization lacks an applied release authority"
  [[ "$prior_state" == "apply_armed" || "$prior_state" == "apply_activation_armed" || \
    "$prior_state" == "apply_finalizing_ingress_closed" || \
    "$prior_state" == "applied_ingress_closed" ]] || \
    holdfast_die "apply finalization receipt is incompatible with current state $prior_state"
  [[ ! ( -e "$apply_receipt" && -e "$pending_apply_receipt" ) ]] || \
    holdfast_die "final and pending apply receipts coexist"
  if [[ -e "$pending_apply_receipt" ]]; then
    [[ "$prior_state" != "applied_ingress_closed" ]] || \
      holdfast_die "final apply state cannot point to a pending receipt"
    candidate_apply_receipt="$pending_apply_receipt"
  elif [[ -e "$apply_receipt" ]]; then
    [[ "$prior_state" == "apply_finalizing_ingress_closed" || \
      "$prior_state" == "applied_ingress_closed" ]] || \
      holdfast_die "final APPLY.receipt exists before durable finalization state"
    candidate_apply_receipt="$apply_receipt"
  else
    holdfast_die "apply finalization state lacks its exact receipt"
  fi
  require_root_file "$candidate_apply_receipt"
  candidate_apply_sha=$(holdfast_sha256 "$candidate_apply_receipt")
  if [[ "$prior_state" == "apply_finalizing_ingress_closed" ]]; then
    [[ "$(jq -er '.pending_apply_receipt' "$state_file")" == "APPLY-PENDING.receipt" ]] || \
      holdfast_die "apply finalization state points to another pending receipt"
    [[ "$(jq -er '.pending_apply_receipt_sha256' "$state_file")" == "$candidate_apply_sha" ]] || \
      holdfast_die "apply finalization receipt was replaced"
    [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$transaction_sha" && \
      "$(jq -er '.applied_targets_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" ]] || \
      holdfast_die "apply finalization transaction binding differs"
  elif [[ "$prior_state" == "applied_ingress_closed" ]]; then
    [[ "$(jq -er '.apply_receipt_sha256' "$state_file")" == "$candidate_apply_sha" ]] || \
      holdfast_die "final apply state receipt was replaced"
    [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$transaction_sha" && \
      "$(jq -er '.applied_targets_sha256' "$state_file")" == \
      "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" ]] || \
      holdfast_die "final apply state transaction binding differs"
  fi
  [[ "$(holdfast_receipt_value "$candidate_apply_receipt" schema_version)" == "2" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" completion_state)" == \
    "applied_ingress_closed" ]] || holdfast_die "apply finalization receipt schema differs"
  [[ "$(holdfast_receipt_value "$candidate_apply_receipt" estate_root)" == "$estate_root" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" backup_dir)" == "$backup" ]] || \
    holdfast_die "apply finalization receipt points to another estate or backup"
  [[ "$(holdfast_receipt_value "$candidate_apply_receipt" release_env_sha256)" == "$release_env_sha" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" release_evidence_sha256)" == \
    "$release_evidence_sha" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" render_inputs_sha256)" == \
    "$(holdfast_sha256 "$backup/RENDER-INPUTS.sha256")" ]] || \
    holdfast_die "apply finalization release binding differs"
  [[ "$(holdfast_receipt_value "$candidate_apply_receipt" apply_armed_receipt_sha256)" == \
    "$armed_receipt_sha" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" control_sha256)" == "$control_sha" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" transaction_sha256)" == "$transaction_sha" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" applied_targets_sha256)" == \
    "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" ]] || \
    holdfast_die "apply finalization authority binding differs"
  [[ "$(holdfast_receipt_value "$candidate_apply_receipt" cargo_gate)" == "passed" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" runtime_backup)" == "passed" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" closed_bracket)" == "passed" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" route_database_state)" == "absent" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" public_ipv4_ipv6_closed_status)" == "404" && \
    "$(holdfast_receipt_value "$candidate_apply_receipt" ingress_opened)" == "false" ]] || \
    holdfast_die "apply finalization closed-ingress proof differs"
  final_services_activated=$(holdfast_receipt_value "$candidate_apply_receipt" services_activated)
  final_runtime_verified=$(holdfast_receipt_value "$candidate_apply_receipt" runtime_verified)
  [[ ( "$final_services_activated" == "true" || "$final_services_activated" == "false" ) && \
    "$final_runtime_verified" == "$final_services_activated" ]] || \
    holdfast_die "apply finalization runtime state differs"
  validate_successor_lineage_receipt "$candidate_apply_receipt"
  if [[ "$prior_state" == "apply_armed" ]]; then
    [[ "$final_services_activated" == "false" ]] || \
      holdfast_die "apply-armed finalization cannot claim activated services"
  elif [[ "$prior_state" == "apply_activation_armed" ]]; then
    [[ "$final_services_activated" == "true" ]] || \
      holdfast_die "activation-armed finalization must prove activated services"
  fi
  if [[ "$prior_state" == "apply_finalizing_ingress_closed" || \
    "$prior_state" == "applied_ingress_closed" ]]; then
    [[ "$(jq -er '.services_activated | tostring' "$state_file")" == "$final_services_activated" && \
      "$(jq -er '.runtime_verified | tostring' "$state_file")" == "$final_runtime_verified" && \
      "$(jq -er '.route_database_state' "$state_file")" == "absent" && \
      "$(jq -er '.public_ipv4_ipv6_closed_status' "$state_file")" == "404" && \
      "$(jq -er '.ingress_opened | tostring' "$state_file")" == "false" ]] || \
      holdfast_die "apply finalization state claims differ"
  fi

  interrupted_current_sha="none"
  interrupted_candidate_sha="none"
  if [[ "$successor_recovery_v3" == "true" ]]; then
    interrupted_current_sha=$(holdfast_sha256 "$state_file")
    interrupted_candidate_sha=$(holdfast_sha256 "$candidate_apply_receipt")
  fi
  verify_live_disposition applied
  if [[ "$final_services_activated" == "true" ]]; then
    run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
  fi
  verify_closed_bracket
  verify_live_disposition applied
  if [[ "$successor_recovery_v3" == "true" ]]; then
    revalidate_v3_successor_authority "$state_file"
    require_root_file "$candidate_apply_receipt"
    require_root_file "$state_file"
    [[ "$(holdfast_sha256 "$candidate_apply_receipt")" == \
        "$interrupted_candidate_sha" && \
      "$(holdfast_sha256 "$state_file")" == "$interrupted_current_sha" ]] || \
      holdfast_die "schema-v3 interrupted apply authority changed during live verification"
    validate_successor_lineage_receipt "$candidate_apply_receipt"
    validate_runtime_stop_authority
    validate_runtime_backup_success_authority
    validate_runtime_compensation_authority
    [[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$transaction_sha" && \
      "$(jq -er '.schema_version == 1 and .state == "applied"' \
        "$backup/estate/TRANSACTION.json")" == "true" && \
      "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" == \
        "$applied_targets_sha" ]] || \
      holdfast_die "schema-v3 interrupted apply nested authority changed before finalization"
    if [[ "$final_services_activated" == "true" ]]; then
      run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
        --release-evidence "$backup/RELEASE-EVIDENCE.json"
    fi
    verify_live_disposition applied
    validate_v3_cached_control_authority
    (cd "$backup" && sha256sum --check CONTROL.sha256) >/dev/null
    [[ "$(holdfast_sha256 "$candidate_apply_receipt")" == \
        "$interrupted_candidate_sha" && \
      "$(holdfast_sha256 "$state_file")" == "$interrupted_current_sha" ]] || \
      holdfast_die "schema-v3 interrupted apply authority changed during revalidation"
  fi

  # If apply crashed before installing its finalization state, establish that
  # durable boundary before promoting the pending receipt.
  if [[ "$prior_state" != "apply_finalizing_ingress_closed" ]]; then
    finalizing_tmp="$state_dir/.CURRENT.json.$$"
    jq \
      --arg pending_sha "$candidate_apply_sha" --arg armed_sha "$armed_receipt_sha" \
      --arg control_sha "$control_sha" --arg release_sha "$release_evidence_sha" \
      --arg transaction_sha "$transaction_sha" \
      --arg targets_sha "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" \
      --arg closed_at "$(holdfast_receipt_value "$candidate_apply_receipt" closed_verified_at)" \
      --argjson activated "$final_services_activated" \
      '.state="apply_finalizing_ingress_closed" | .pending_apply_receipt="APPLY-PENDING.receipt" | .pending_apply_receipt_sha256=$pending_sha | .apply_armed_receipt_sha256=$armed_sha | .control_sha256=$control_sha | .release_evidence_sha256=$release_sha | .transaction_sha256=$transaction_sha | .applied_targets_sha256=$targets_sha | .closed_verified_at=$closed_at | .route_database_state="absent" | .public_ipv4_ipv6_closed_status=404 | .services_activated=$activated | .runtime_verified=$activated | .ingress_opened=false' \
      "$state_file" \
      >"$finalizing_tmp"
    chmod 0600 "$finalizing_tmp"
    mv -fT -- "$finalizing_tmp" "$state_file"
    sync -f "$state_file"
  fi
  if [[ "$candidate_apply_receipt" == "$pending_apply_receipt" ]]; then
    [[ ! -e "$apply_receipt" && ! -L "$apply_receipt" ]] || \
      holdfast_die "final APPLY.receipt appeared during recovery finalization"
    mv -fT -- "$pending_apply_receipt" "$apply_receipt"
    sync -f "$apply_receipt"
    sync -f "$backup"
  fi
  require_root_file "$apply_receipt"
  [[ "$(holdfast_sha256 "$apply_receipt")" == "$candidate_apply_sha" ]] || \
    holdfast_die "final APPLY.receipt differs from recovery authority"
  final_state_tmp="$state_dir/.CURRENT.json.$$"
  jq \
    --arg apply_sha "$candidate_apply_sha" \
    '.state="applied_ingress_closed" | .apply_receipt_sha256=$apply_sha | del(.pending_apply_receipt,.pending_apply_receipt_sha256)' \
    "$state_file" >"$final_state_tmp"
  chmod 0600 "$final_state_tmp"
  mv -fT -- "$final_state_tmp" "$state_file"
  sync -f "$state_file"
  sync -f "$state_dir"
  echo "interrupted apply finalization completed; ingress remains closed"
  exit 0
fi

[[ ! -e "$apply_receipt" && ! -L "$apply_receipt" && \
  ! -e "$pending_apply_receipt" && ! -L "$pending_apply_receipt" ]] || \
  holdfast_die "successful or pending apply receipt exists outside finalization"

if [[ "$mode" == "restore" && "$transaction_is_preimage" != "true" && \
  "$prior_state" == "restore_failed" ]]; then
  if qualify_pre_restored_retry; then transaction_is_preimage="true"; fi
fi

if [[ "$transaction_is_preimage" == "true" ]]; then
  verify_live_disposition preimage
elif [[ "$mode" == "resume" ]]; then
  verify_live_disposition applied
else
  verify_live_disposition mixed
fi
v3_initial_probe_current_sha=""
v3_initial_probe_current_identity=""
if [[ "$successor_recovery_v3" == "true" && -z "$completed_state_match" ]]; then
  require_root_file "$state_file"
  v3_initial_probe_current_sha=$(holdfast_sha256 "$state_file")
  v3_initial_probe_current_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")
fi
snapshot_v3_completed_terminal_authority
verify_closed_bracket
# Close the TOCTOU window between the external probe and the durable recovery arm.
if [[ "$pre_restored_retry" == "true" ]]; then
  verify_legacy_pre_restored_runtime_disposition || \
    holdfast_die "legacy runtime disposition changed before the pre-restored recovery arm"
fi
if [[ "$transaction_is_preimage" == "true" ]]; then
  verify_live_disposition preimage
elif [[ "$mode" == "resume" ]]; then
  verify_live_disposition applied
else
  verify_live_disposition mixed
fi
if [[ "$successor_recovery_v3" == "true" && -z "$completed_state_match" ]]; then
  revalidate_v3_successor_authority "$state_file"
  require_root_file "$state_file"
  [[ "$(holdfast_sha256 "$state_file")" == "$v3_initial_probe_current_sha" && \
    "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == \
      "$v3_initial_probe_current_identity" ]] || \
    holdfast_die "schema-v3 recovery CURRENT changed during initial closed-bracket verification"
fi

# A crash after the immutable completion state was installed but before the
# active pointer was committed must converge by finalizing that same receipt,
# not by starting a second recovery attempt.
if [[ -n "$completed_state_match" ]]; then
  completed_kind=$(jq -er '.state' "$completed_state_match")
  if [[ "$completed_kind" == "apply_recovered_restored" ]]; then
    completed_mode="restore"
  else
    completed_mode="resume"
  fi
  [[ "$completed_mode" == "$mode" ]] || holdfast_die "completed recovery mode differs"
  completed_receipt_name=$(jq -er '.recovery_receipt' "$completed_state_match")
  [[ "$completed_receipt_name" =~ ^APPLY-RECOVERY-COMPLETE-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ ]] || \
    holdfast_die "completed recovery receipt name is unsafe"
  completed_receipt="$state_dir/$completed_receipt_name"
  require_root_file "$completed_receipt"
  completed_receipt_sha=$(holdfast_sha256 "$completed_receipt")
  [[ "$(jq -er '.recovery_receipt_sha256' "$completed_state_match")" == "$completed_receipt_sha" ]] || \
    holdfast_die "completed recovery receipt was replaced"
  [[ "$(holdfast_receipt_value "$completed_receipt" mode)" == "$mode" ]] || \
    holdfast_die "completed recovery receipt mode differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" backup_dir)" == "$backup" ]] || \
    holdfast_die "completed recovery receipt points to another backup"
  [[ "$(holdfast_receipt_value "$completed_receipt" control_sha256)" == "$control_sha" ]] || \
    holdfast_die "completed recovery receipt CONTROL differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" estate_root)" == "$estate_root" ]] || \
    holdfast_die "completed recovery receipt points to another estate"
  validate_successor_lineage_receipt "$completed_receipt"
  [[ "$(holdfast_receipt_value "$completed_receipt" original_estate_transaction_state)" == \
    "$transaction_state" ]] || holdfast_die "completed recovery transaction state differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" original_estate_transaction_sha256)" == \
    "$transaction_sha" ]] || holdfast_die "completed recovery transaction differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" applied_targets_sha256)" == \
    "$applied_targets_sha" ]] || holdfast_die "completed recovery applied-target authority differs"
  [[ "$(jq -er '.transaction_sha256' "$completed_state_match")" == "$transaction_sha" && \
    "$(jq -er '.applied_targets_sha256' "$completed_state_match")" == \
    "$applied_targets_sha" ]] || holdfast_die "completed recovery state rollback authority differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" legacy_empty_strad)" == \
    "$legacy_empty_strad" ]] || holdfast_die "completed recovery legacy policy differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" release_evidence_sha256)" == \
    "$release_evidence_sha" ]] || holdfast_die "completed recovery release evidence differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" dry_run_receipt_sha256)" == \
    "$dry_receipt_sha" ]] || holdfast_die "completed recovery dry-run receipt differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" live_estate_disposition)" == \
    "$([[ "$mode" == "resume" ]] && printf applied || printf preimage)" ]] || \
    holdfast_die "completed recovery live disposition differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" route_state)" == "absent" && \
    "$(holdfast_receipt_value "$completed_receipt" db_public_db_bracket)" == "absent-404-absent" && \
    "$(holdfast_receipt_value "$completed_receipt" apply_receipt_created)" == "false" ]] || \
    holdfast_die "completed recovery closed-ingress evidence differs"
  validate_recovery_route_contract \
    "$completed_receipt" "completed recovery receipt"
  completed_armed_name=$(jq -er '.recovery_armed_receipt' "$completed_state_match")
  [[ "$completed_armed_name" =~ ^APPLY-RECOVERY-ARMED-[0-9]{8}T[0-9]{6}Z-[0-9]+\.receipt$ ]] || \
    holdfast_die "completed recovery armed receipt name is unsafe"
  completed_armed="$state_dir/$completed_armed_name"
  require_root_file "$completed_armed"
  completed_armed_sha=$(holdfast_sha256 "$completed_armed")
  [[ "$(jq -er '.recovery_armed_receipt_sha256' "$completed_state_match")" == "$completed_armed_sha" ]] || \
    holdfast_die "completed recovery armed receipt was replaced"
  [[ "$(holdfast_receipt_value "$completed_receipt" recovery_armed_receipt_sha256)" == "$completed_armed_sha" ]] || \
    holdfast_die "completed receipt points to another recovery arm"
  validate_successor_lineage_receipt "$completed_armed"
  [[ "$(holdfast_receipt_value "$completed_armed" transaction_sha256)" == \
    "$transaction_sha" && \
    "$(holdfast_receipt_value "$completed_armed" applied_targets_sha256)" == \
    "$applied_targets_sha" ]] || holdfast_die "completed recovery arm rollback authority differs"
  completed_writer_reconciled=$(holdfast_receipt_value "$completed_receipt" writer_set_reconciled 2>/dev/null || printf legacy-absent)
  completed_writer_source_attempt=$(holdfast_receipt_value "$completed_receipt" writer_set_source_attempt 2>/dev/null || printf legacy-absent)
  completed_writer_source_failure=$(holdfast_receipt_value "$completed_receipt" writer_set_source_failure_receipt_sha256 2>/dev/null || printf legacy-absent)
  completed_writer_source_state=$(holdfast_receipt_value "$completed_receipt" writer_set_source_state_sha256 2>/dev/null || printf legacy-absent)
  completed_writer_source_manifest=$(holdfast_receipt_value "$completed_receipt" writer_set_source_manifest_sha256 2>/dev/null || printf legacy-absent)
  completed_writer_preimage=$(holdfast_receipt_value "$completed_receipt" writer_set_preimage_compose_sha256 2>/dev/null || printf legacy-absent)
  completed_writer_quarantined=$(holdfast_receipt_value "$completed_receipt" writer_set_quarantined 2>/dev/null || printf none)
  [[ "$completed_writer_quarantined" == \
      "$(holdfast_receipt_value "$completed_armed" writer_set_quarantined 2>/dev/null || printf none)" && \
    "$completed_writer_quarantined" == \
      "$(jq -er '.writer_set_quarantined // "none"' "$completed_state_match")" ]] || \
    holdfast_die "completed writer quarantine authority differs"
  writer_set_quarantined=$completed_writer_quarantined
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    [[ "$quarantine_access_chain" == "true" ]] || \
      holdfast_die "completed access-chain quarantine requires its explicit flag"
    [[ "$(holdfast_receipt_value "$completed_receipt" quarantined_writers_inactive)" == \
      "passed" ]] || holdfast_die "completed access-chain quarantine lacks inactive proof"
  else
    [[ "$writer_set_quarantined" == "none" ]] || \
      holdfast_die "completed recovery carries an unknown writer quarantine set"
    [[ "$quarantine_access_chain" == "false" ]] || \
      holdfast_die "completed recovery does not carry access-chain quarantine"
  fi
  if [[ "$completed_writer_reconciled" == "legacy-absent" && \
    "$completed_writer_source_attempt" == "legacy-absent" && \
    "$completed_writer_source_failure" == "legacy-absent" && \
    "$completed_writer_source_state" == "legacy-absent" && \
    "$completed_writer_source_manifest" == "legacy-absent" && \
    "$completed_writer_preimage" == "legacy-absent" ]]; then
    for key in writer_set_reconciled writer_set_source_attempt \
      writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256 \
      writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256; do
      [[ "$(holdfast_receipt_value "$completed_armed" "$key" 2>/dev/null || printf legacy-absent)" == \
        "legacy-absent" ]] || holdfast_die "legacy completed arm carries writer reconciliation"
    done
    jq -e \
      '(.writer_set_reconciled // false) == false and
       (.writer_set_source_attempt // "none") == "none" and
       (.writer_set_source_failure_receipt_sha256 // "none") == "none" and
       (.writer_set_source_state_sha256 // "none") == "none" and
       (.writer_set_source_manifest_sha256 // "none") == "none" and
       (.writer_set_preimage_compose_sha256 // "none") == "none"' \
      "$completed_state_match" >/dev/null || \
      holdfast_die "legacy completed state carries writer reconciliation"
  else
    [[ "$completed_writer_reconciled" == "true" || \
      "$completed_writer_reconciled" == "false" ]] || \
      holdfast_die "completed writer reconciliation flag differs"
    writer_set_reconciled=$completed_writer_reconciled
    writer_set_source_attempt=$completed_writer_source_attempt
    writer_set_source_failure_sha=$completed_writer_source_failure
    writer_set_source_state_sha=$completed_writer_source_state
    writer_set_source_manifest_sha=$completed_writer_source_manifest
    writer_set_preimage_compose_sha=$completed_writer_preimage
    for key in writer_set_reconciled writer_set_source_attempt \
      writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256 \
      writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256; do
      [[ "$(holdfast_receipt_value "$completed_receipt" "$key")" == \
          "$(holdfast_receipt_value "$completed_armed" "$key")" && \
        "$(holdfast_receipt_value "$completed_armed" "$key")" == \
          "$(jq -er ".${key} | tostring" "$completed_state_match")" ]] || \
        holdfast_die "completed writer reconciliation authority differs: $key"
    done
    if [[ "$mode" == "restore" ]]; then
      load_preimage_compose_authority
      [[ "$writer_set_preimage_compose_sha" == "$preimage_compose_sha" ]] || \
        holdfast_die "completed writer reconciliation preimage Compose differs"
      completed_attempt=$(holdfast_receipt_value "$completed_receipt" attempt_id)
      completed_writers_name=$(holdfast_receipt_value "$completed_receipt" restore_running_writers_manifest)
      completed_writers_sha=$(holdfast_receipt_value "$completed_receipt" restore_running_writers_sha256)
      [[ "$completed_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
        "$completed_writers_name" == "RESTORE-RUNNING-WRITERS-${completed_attempt}.txt" && \
        "$completed_writers_sha" =~ ^[0-9a-f]{64}$ && \
        "$(jq -er '.restore_running_writers_manifest' "$completed_state_match")" == \
          "$completed_writers_name" && \
        "$(jq -er '.restore_running_writers_sha256' "$completed_state_match")" == \
          "$completed_writers_sha" && \
        "$(holdfast_receipt_value "$completed_armed" restore_running_writers_manifest)" == \
          "$completed_writers_name" && \
        "$(holdfast_receipt_value "$completed_armed" restore_running_writers_sha256)" == \
          "$completed_writers_sha" ]] || \
        holdfast_die "completed recovery writer manifest authority differs"
      restore_writers_manifest="$state_dir/$completed_writers_name"
      require_root_file "$restore_writers_manifest"
      [[ "$(holdfast_sha256 "$restore_writers_manifest")" == "$completed_writers_sha" ]] || \
        holdfast_die "completed recovery writer manifest was replaced"
      mapfile -t restore_running_writers <"$restore_writers_manifest"
      validate_restore_writer_set
    else
      [[ "$writer_set_preimage_compose_sha" == "none" ]] || \
        holdfast_die "completed resume carries writer preimage authority"
      restore_running_writers=()
    fi
    if [[ "$writer_set_reconciled" == "true" ]]; then
      [[ "$mode" == "restore" && \
        "$writer_set_source_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
        "$writer_set_source_failure_sha" =~ ^[0-9a-f]{64}$ && \
        "$writer_set_source_state_sha" =~ ^[0-9a-f]{64}$ && \
        "$writer_set_source_manifest_sha" =~ ^[0-9a-f]{64}$ ]] || \
        holdfast_die "completed writer reconciliation evidence is invalid"
      validate_writer_reconciliation_source
    else
      [[ "$writer_set_source_attempt" == "none" && \
        "$writer_set_source_failure_sha" == "none" && \
        "$writer_set_source_state_sha" == "none" && \
        "$writer_set_source_manifest_sha" == "none" ]] || \
        holdfast_die "completed inactive writer reconciliation carries source evidence"
    fi
  fi
  if [[ "$writer_set_quarantined" == "access-governance,newapi" && \
    "$writer_set_reconciled" != "true" ]]; then
    holdfast_die "completed access-chain quarantine lacks reconciliation authority"
  fi
  validate_v3_completed_terminal_authority \
    "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
  if [[ "$verify_completed" == "true" ]]; then
    validate_verify_completed_exact_semantics
    verify_live_disposition applied
    run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
    verify_closed_bracket
    verify_live_disposition applied

    verify_inputs_after_probes="$verify_workspace/inputs.after-probes"
    verify_tree_after_probes="$verify_workspace/tree.after-probes"
    snapshot_verify_completed_inputs "$verify_inputs_after_probes"
    cmp -s -- "$verify_inputs_before" "$verify_inputs_after_probes" || \
      holdfast_die "completed recovery inputs changed during live verification"
    snapshot_verify_completed_estate "$verify_tree_after_probes"
    cmp -s -- "$verify_tree_before" "$verify_tree_after_probes" || \
      holdfast_die "completed recovery live verification modified protected storage"

    run_python_tool "$completion_attestation_tool" \
      "$script_dir/recovery_completion_attestation.py" issue \
      --release-root "$verify_bundle_root" \
      --private-key "$signing_key" \
      --source-public-key "$authority_public_key" \
      --public-key-sha256 "$authority_public_key_sha" \
      --recovery-attempt-id "$verify_completed_attempt" \
      --prior-failure-receipt "$(basename -- "$verify_prior_failure_receipt")" \
      --prior-failure-receipt-sha256 "$verify_prior_failure_sha" \
      --apply-armed-at "$verify_apply_armed_at" \
      --recovery-armed-at "$verify_recovery_armed_at" \
      --recovery-completed-at "$verify_recovery_completed_at" \
      --estate-root "$estate_root" \
      --backup-dir "$backup" \
      --current-sha256 "$(holdfast_sha256 "$state_file")" \
      --completion-receipt "$(basename -- "$completed_receipt")" \
      --completion-receipt-sha256 "$completed_receipt_sha" \
      --completion-archive "$(basename -- "$completed_state_match")" \
      --completion-archive-sha256 "$(holdfast_sha256 "$completed_state_match")" \
      --recovery-armed-receipt "$(basename -- "$completed_armed")" \
      --recovery-armed-receipt-sha256 "$completed_armed_sha" \
      --control-sha256 "$control_sha" \
      --release-env-sha256 "$release_env_sha" \
      --release-evidence-sha256 "$release_evidence_sha" \
      --transaction-sha256 "$transaction_sha" \
      --applied-targets-sha256 "$applied_targets_sha" \
      --runtime-receipt-sha256 "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" \
      --runtime-manifest-sha256 "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" \
      --predecessor-release-generation "$verify_predecessor_generation" \
      --release-generation "$verify_release_generation" >/dev/null
    run_python_tool "$completion_attestation_tool" \
      "$script_dir/recovery_completion_attestation.py" verify \
      --attestation "$verify_bundle_root/RECOVERY-COMPLETION-ATTESTATION.json" \
      --signature "$verify_bundle_root/RECOVERY-COMPLETION-ATTESTATION.sig" \
      --public-key "$verify_bundle_root/RECOVERY-COMPLETION-ATTESTATION.pub" \
      --public-key-sha256 "$authority_public_key_sha" >/dev/null

    verify_inputs_final="$verify_workspace/inputs.final"
    verify_tree_final="$verify_workspace/tree.final"
    snapshot_verify_completed_inputs "$verify_inputs_final"
    cmp -s -- "$verify_inputs_before" "$verify_inputs_final" || \
      holdfast_die "completed recovery inputs changed before attestation publication"
    snapshot_verify_completed_estate "$verify_tree_final"
    cmp -s -- "$verify_tree_before" "$verify_tree_final" || \
      holdfast_die "completed recovery protected storage changed before attestation publication"

    run_python_tool "$completion_attestation_tool" \
      "$script_dir/recovery_completion_attestation.py" publish \
      --source-root "$verify_bundle_root" \
      --release-root "$release_root" \
      --public-key-sha256 "$authority_public_key_sha" >/dev/null
    echo "completed resume recovery verified and attested; ingress remains closed"
    exit 0
  fi
  if [[ "$mode" == "restore" ]]; then
    verify_live_disposition preimage
    verify_live_quarantine_absence
    finalized_attempt=$(holdfast_receipt_value "$completed_receipt" attempt_id)
    [[ "$finalized_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
      holdfast_die "completed recovery attempt identity is unsafe"
    finalized_archive="$state_dir/APPLY-RECOVERY-FINALIZED-STATE-${finalized_attempt}.json"
    validate_v3_completed_terminal_authority \
      "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
    verify_live_disposition preimage
    verify_restore_writer_runtime_disposition
    validate_v3_completed_terminal_local_fence \
      "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
    if [[ "$successor_recovery" == "true" ]]; then
      restore_immediate_predecessor_current "$finalized_archive"
    elif [[ -f "$state_file" && ! -L "$state_file" ]]; then
      [[ ! -e "$finalized_archive" && ! -L "$finalized_archive" ]] || \
        holdfast_die "completed recovery state archive already exists"
      mv -- "$state_file" "$finalized_archive"
      sync -f "$state_dir"
    else
      [[ ! -e "$state_file" && ! -L "$state_file" ]] || holdfast_die "unsafe active state path"
    fi
  else
    verify_live_disposition applied
    run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
    validate_v3_completed_terminal_authority \
      "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
    if [[ "$v3_completed_terminal_snapshot_active" == "true" ]]; then
      run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
        --release-evidence "$backup/RELEASE-EVIDENCE.json"
      verify_live_disposition applied
      validate_v3_completed_terminal_local_fence \
        "$v3_completed_terminal_current_sha" "$v3_completed_terminal_current_identity"
    fi
    if [[ -f "$state_file" && ! -L "$state_file" && "$prior_state" == "applied_ingress_closed" ]]; then
      [[ "$(jq -er '.recovery_receipt_sha256' "$state_file")" == "$completed_receipt_sha" ]] || \
        holdfast_die "active completed recovery receipt differs"
      [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$transaction_sha" && \
        "$(jq -er '.applied_targets_sha256' "$state_file")" == \
        "$applied_targets_sha" ]] || holdfast_die "active completed recovery rollback authority differs"
    else
      completed_pointer_tmp="$state_dir/.CURRENT.json.$$"
      jq \
        --arg transaction "$transaction_sha" --arg applied_targets "$applied_targets_sha" \
        '.state="applied_ingress_closed" | .services_activated=true | .runtime_verified=true | .transaction_sha256=$transaction | .applied_targets_sha256=$applied_targets' \
        "$completed_state_match" >"$completed_pointer_tmp"
      chmod 0600 "$completed_pointer_tmp"
      mv -fT -- "$completed_pointer_tmp" "$state_file"
      sync -f "$state_file"
    fi
  fi
  v3_completed_terminal_final_current_sha=""
  v3_completed_terminal_final_current_identity=""
  v3_completed_terminal_finalized_archive_sha="none"
  v3_completed_terminal_finalized_archive_identity="none"
  if [[ "$v3_completed_terminal_snapshot_active" == "true" ]]; then
    require_root_file "$state_file"
    v3_completed_terminal_final_current_sha=$(holdfast_sha256 "$state_file")
    v3_completed_terminal_final_current_identity=$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")
    if [[ "$mode" == "restore" && ( -e "$finalized_archive" || -L "$finalized_archive" ) ]]; then
      require_root_file "$finalized_archive"
      v3_completed_terminal_finalized_archive_sha=$(holdfast_sha256 "$finalized_archive")
      v3_completed_terminal_finalized_archive_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
        "$finalized_archive")
    fi
  fi
  verify_closed_bracket
  validate_v3_completed_terminal_authority \
    "$v3_completed_terminal_final_current_sha" \
    "$v3_completed_terminal_final_current_identity"
  if [[ "$v3_completed_terminal_snapshot_active" == "true" ]]; then
    if [[ "$mode" == "restore" ]]; then
      verify_live_disposition preimage
      verify_restore_writer_runtime_disposition
    else
      run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
        --release-evidence "$backup/RELEASE-EVIDENCE.json"
      verify_live_disposition applied
    fi
    validate_v3_completed_terminal_local_fence \
      "$v3_completed_terminal_final_current_sha" \
      "$v3_completed_terminal_final_current_identity"
  fi
  if [[ "$v3_completed_terminal_snapshot_active" == "true" && \
    "$v3_completed_terminal_finalized_archive_sha" != "none" ]]; then
    require_root_file "$finalized_archive"
    [[ "$(holdfast_sha256 "$finalized_archive")" == \
        "$v3_completed_terminal_finalized_archive_sha" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$finalized_archive")" == \
        "$v3_completed_terminal_finalized_archive_identity" ]] || \
      holdfast_die "schema-v3 completed recovery finalized archive changed during external verification"
  fi
  echo "previously completed apply recovery finalized in $mode mode; ingress remains closed"
  exit 0
fi

if [[ "$prior_state" != "apply_recovery_armed" && "$mode" == "restore" && \
  "$transaction_is_preimage" != "true" && "$legacy_orphan" == "false" ]]; then
  validate_recovery_stage_authority
fi

restore_running_writers=()
restore_writers_manifest="none"
restore_writers_sha="none"
writer_set_reconciled="false"
writer_set_source_attempt="none"
writer_set_source_failure_sha="none"
writer_set_source_state_sha="none"
writer_set_source_manifest_sha="none"
writer_set_preimage_compose_sha="none"
if [[ "$mode" == "restore" ]]; then
  load_preimage_compose_authority
  writer_set_preimage_compose_sha=$preimage_compose_sha
fi
if [[ "$prior_state" == "apply_recovery_armed" ]]; then
  attempt_id=$(jq -er '.recovery_attempt_id' "$state_file")
  [[ "$attempt_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || holdfast_die "armed recovery attempt identity is unsafe"
  [[ "$(jq -er '.recovery_mode' "$state_file")" == "$mode" ]] || holdfast_die "armed recovery mode differs"
  recovery_armed_name=$(jq -er '.recovery_armed_receipt' "$state_file")
  [[ "$recovery_armed_name" == "APPLY-RECOVERY-ARMED-${attempt_id}.receipt" ]] || \
    holdfast_die "armed recovery receipt name differs"
  recovery_armed_receipt="$state_dir/$recovery_armed_name"
  require_root_file "$recovery_armed_receipt"
  validate_recovery_route_contract \
    "$recovery_armed_receipt" "armed recovery receipt"
  recovery_armed_sha=$(holdfast_sha256 "$recovery_armed_receipt")
  [[ "$(jq -er '.recovery_armed_receipt_sha256' "$state_file")" == "$recovery_armed_sha" ]] || \
    holdfast_die "armed recovery receipt was replaced"
  [[ "$(holdfast_receipt_value "$recovery_armed_receipt" mode)" == "$mode" ]] || holdfast_die "armed recovery receipt mode differs"
  [[ "$(holdfast_receipt_value "$recovery_armed_receipt" control_sha256)" == "$control_sha" ]] || holdfast_die "armed recovery CONTROL differs"
  [[ "$(holdfast_receipt_value "$recovery_armed_receipt" transaction_sha256)" == "$transaction_sha" ]] || holdfast_die "armed recovery transaction differs"
  [[ "$(holdfast_receipt_value "$recovery_armed_receipt" applied_targets_sha256)" == \
    "$applied_targets_sha" ]] || holdfast_die "armed recovery applied-target authority differs"
  [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$transaction_sha" && \
    "$(jq -er '.applied_targets_sha256' "$state_file")" == "$applied_targets_sha" ]] || \
    holdfast_die "armed recovery state rollback authority differs"
  [[ "$(holdfast_receipt_value "$recovery_armed_receipt" legacy_empty_strad)" == "$legacy_empty_strad" ]] || holdfast_die "armed legacy recovery policy differs"
  armed_pre_restored=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_retry 2>/dev/null || printf legacy-absent)
  armed_pre_restored_attempt=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_source_attempt 2>/dev/null || printf legacy-absent)
  armed_pre_restored_runtime=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_runtime_snapshot_sha256 2>/dev/null || printf legacy-absent)
  armed_pre_restored_estate=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_estate_snapshot_sha256 2>/dev/null || printf legacy-absent)
  armed_pre_restored_superseded_attempt=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_superseded_attempt 2>/dev/null || printf legacy-absent)
  armed_pre_restored_superseded_failure=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_superseded_failure_receipt_sha256 2>/dev/null || printf legacy-absent)
  armed_pre_restored_superseded_state=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_superseded_state_sha256 2>/dev/null || printf legacy-absent)
  armed_pre_restored_disposition=$(holdfast_receipt_value "$recovery_armed_receipt" pre_restored_runtime_disposition 2>/dev/null || printf legacy-absent)
  if [[ "$armed_pre_restored" == "legacy-absent" && \
    "$armed_pre_restored_attempt" == "legacy-absent" && \
    "$armed_pre_restored_runtime" == "legacy-absent" && \
    "$armed_pre_restored_estate" == "legacy-absent" && \
    "$armed_pre_restored_superseded_attempt" == "legacy-absent" && \
    "$armed_pre_restored_superseded_failure" == "legacy-absent" && \
    "$armed_pre_restored_superseded_state" == "legacy-absent" && \
    "$armed_pre_restored_disposition" == "legacy-absent" ]]; then
    [[ "$pre_restored_retry" == "false" && \
      "$(jq -er '(.pre_restored_retry // false) | tostring' "$state_file")" == "false" && \
      "$(jq -er '.pre_restored_source_attempt // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_runtime_snapshot_sha256 // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_estate_snapshot_sha256 // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_superseded_attempt // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_superseded_failure_receipt_sha256 // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_superseded_state_sha256 // "none"' "$state_file")" == "none" && \
      "$(jq -er '.pre_restored_runtime_disposition // "not-applicable"' "$state_file")" == \
        "not-applicable" ]] || \
      holdfast_die "legacy armed recovery cannot claim a pre-restored retry"
  else
    [[ "$armed_pre_restored" == "true" || "$armed_pre_restored" == "false" ]] || \
      holdfast_die "armed pre-restored retry flag differs"
    if [[ "$armed_pre_restored" == "true" ]]; then
      [[ "$armed_pre_restored_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
        "$armed_pre_restored_runtime" =~ ^[0-9a-f]{64}$ && \
        "$armed_pre_restored_estate" =~ ^[0-9a-f]{64}$ && \
        "$armed_pre_restored_superseded_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
        "$armed_pre_restored_superseded_failure" =~ ^[0-9a-f]{64}$ && \
        "$armed_pre_restored_superseded_state" =~ ^[0-9a-f]{64}$ && \
        "$armed_pre_restored_disposition" == \
          "legacy-empty-strad+six-volumes-absent+runtime-writers-inactive" ]] || \
        holdfast_die "armed pre-restored retry evidence is invalid"
      qualify_pre_restored_retry "$armed_pre_restored_attempt" || \
        holdfast_die "armed pre-restored retry evidence no longer qualifies"
      [[ "$pre_restored_source_attempt" == "$armed_pre_restored_attempt" && \
        "$pre_restored_runtime_snapshot" == "$armed_pre_restored_runtime" && \
        "$pre_restored_estate_snapshot" == "$armed_pre_restored_estate" ]] || \
        holdfast_die "armed pre-restored retry source differs"
      pre_restored_superseded_attempt="$armed_pre_restored_superseded_attempt"
      pre_restored_superseded_failure_sha="$armed_pre_restored_superseded_failure"
      pre_restored_superseded_state_sha="$armed_pre_restored_superseded_state"
      pre_restored_runtime_disposition="$armed_pre_restored_disposition"
      transaction_is_preimage="true"
    else
      [[ "$armed_pre_restored_attempt" == "none" && \
        "$armed_pre_restored_runtime" == "none" && \
        "$armed_pre_restored_estate" == "none" && \
        "$armed_pre_restored_superseded_attempt" == "none" && \
        "$armed_pre_restored_superseded_failure" == "none" && \
        "$armed_pre_restored_superseded_state" == "none" && \
        "$armed_pre_restored_disposition" == "not-applicable" ]] || \
        holdfast_die "inactive pre-restored retry carries evidence"
    fi
    [[ "$(jq -er '.pre_restored_retry | tostring' "$state_file")" == "$pre_restored_retry" && \
      "$(jq -er '.pre_restored_source_attempt' "$state_file")" == \
        "$pre_restored_source_attempt" && \
      "$(jq -er '.pre_restored_runtime_snapshot_sha256' "$state_file")" == \
        "$pre_restored_runtime_snapshot" && \
      "$(jq -er '.pre_restored_estate_snapshot_sha256' "$state_file")" == \
        "$pre_restored_estate_snapshot" && \
      "$(jq -er '.pre_restored_superseded_attempt' "$state_file")" == \
        "$pre_restored_superseded_attempt" && \
      "$(jq -er '.pre_restored_superseded_failure_receipt_sha256' "$state_file")" == \
        "$pre_restored_superseded_failure_sha" && \
      "$(jq -er '.pre_restored_superseded_state_sha256' "$state_file")" == \
        "$pre_restored_superseded_state_sha" && \
      "$(jq -er '.pre_restored_runtime_disposition' "$state_file")" == \
        "$pre_restored_runtime_disposition" ]] || holdfast_die "armed pre-restored retry state differs"
  fi
  armed_writer_set_reconciled=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_reconciled 2>/dev/null || printf legacy-absent)
  armed_writer_set_source_attempt=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_source_attempt 2>/dev/null || printf legacy-absent)
  armed_writer_set_source_failure=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_source_failure_receipt_sha256 2>/dev/null || printf legacy-absent)
  armed_writer_set_source_state=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_source_state_sha256 2>/dev/null || printf legacy-absent)
  armed_writer_set_source_manifest=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_source_manifest_sha256 2>/dev/null || printf legacy-absent)
  armed_writer_set_preimage_compose=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_preimage_compose_sha256 2>/dev/null || printf legacy-absent)
  armed_writer_set_quarantined=$(holdfast_receipt_value "$recovery_armed_receipt" writer_set_quarantined 2>/dev/null || printf none)
  [[ "$armed_writer_set_quarantined" == \
    "$(jq -er '.writer_set_quarantined // "none"' "$state_file")" ]] || \
    holdfast_die "armed writer quarantine authority differs"
  writer_set_quarantined=$armed_writer_set_quarantined
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    [[ "$quarantine_access_chain" == "true" ]] || \
      holdfast_die "armed access-chain quarantine requires its explicit flag"
  else
    [[ "$writer_set_quarantined" == "none" ]] || \
      holdfast_die "armed recovery carries an unknown writer quarantine set"
    [[ "$quarantine_access_chain" == "false" ]] || \
      holdfast_die "armed recovery does not carry access-chain quarantine"
  fi
  if [[ "$armed_writer_set_reconciled" == "legacy-absent" && \
    "$armed_writer_set_source_attempt" == "legacy-absent" && \
    "$armed_writer_set_source_failure" == "legacy-absent" && \
    "$armed_writer_set_source_state" == "legacy-absent" && \
    "$armed_writer_set_source_manifest" == "legacy-absent" && \
    "$armed_writer_set_preimage_compose" == "legacy-absent" ]]; then
    jq -e \
      '(.writer_set_reconciled // false) == false and
       (.writer_set_source_attempt // "none") == "none" and
       (.writer_set_source_failure_receipt_sha256 // "none") == "none" and
       (.writer_set_source_state_sha256 // "none") == "none" and
       (.writer_set_source_manifest_sha256 // "none") == "none" and
       (.writer_set_preimage_compose_sha256 // "none") == "none"' \
      "$state_file" >/dev/null || \
      holdfast_die "legacy armed recovery cannot claim writer reconciliation"
    writer_set_preimage_compose_sha="none"
  else
    [[ "$armed_writer_set_reconciled" == "true" || \
      "$armed_writer_set_reconciled" == "false" ]] || \
      holdfast_die "armed writer reconciliation flag differs"
    writer_set_reconciled=$armed_writer_set_reconciled
    writer_set_source_attempt=$armed_writer_set_source_attempt
    writer_set_source_failure_sha=$armed_writer_set_source_failure
    writer_set_source_state_sha=$armed_writer_set_source_state
    writer_set_source_manifest_sha=$armed_writer_set_source_manifest
    writer_set_preimage_compose_sha=$armed_writer_set_preimage_compose
    if [[ "$mode" == "restore" ]]; then
      [[ "$writer_set_preimage_compose_sha" == "$preimage_compose_sha" ]] || \
        holdfast_die "armed writer reconciliation preimage Compose differs"
    else
      [[ "$writer_set_preimage_compose_sha" == "none" ]] || \
        holdfast_die "resume arm carries writer preimage authority"
    fi
    if [[ "$writer_set_reconciled" == "true" ]]; then
      [[ "$mode" == "restore" && \
        "$writer_set_source_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
        "$writer_set_source_failure_sha" =~ ^[0-9a-f]{64}$ && \
        "$writer_set_source_state_sha" =~ ^[0-9a-f]{64}$ && \
        "$writer_set_source_manifest_sha" =~ ^[0-9a-f]{64}$ ]] || \
        holdfast_die "armed writer reconciliation evidence is invalid"
    else
      [[ "$writer_set_source_attempt" == "none" && \
        "$writer_set_source_failure_sha" == "none" && \
        "$writer_set_source_state_sha" == "none" && \
        "$writer_set_source_manifest_sha" == "none" ]] || \
        holdfast_die "inactive writer reconciliation carries source evidence"
    fi
    [[ "$(jq -er '.writer_set_reconciled | tostring' "$state_file")" == \
        "$writer_set_reconciled" && \
      "$(jq -er '.writer_set_source_attempt' "$state_file")" == \
        "$writer_set_source_attempt" && \
      "$(jq -er '.writer_set_source_failure_receipt_sha256' "$state_file")" == \
        "$writer_set_source_failure_sha" && \
      "$(jq -er '.writer_set_source_state_sha256' "$state_file")" == \
        "$writer_set_source_state_sha" && \
      "$(jq -er '.writer_set_source_manifest_sha256' "$state_file")" == \
        "$writer_set_source_manifest_sha" && \
      "$(jq -er '.writer_set_preimage_compose_sha256' "$state_file")" == \
        "$writer_set_preimage_compose_sha" ]] || \
      holdfast_die "armed writer reconciliation state differs"
  fi
  if [[ "$writer_set_quarantined" == "access-governance,newapi" && \
    "$writer_set_reconciled" != "true" ]]; then
    holdfast_die "armed access-chain quarantine lacks reconciliation authority"
  fi
  if [[ "$mode" == "restore" ]]; then
    restore_writers_name=$(jq -er '.restore_running_writers_manifest' "$state_file")
    [[ "$restore_writers_name" == "RESTORE-RUNNING-WRITERS-${attempt_id}.txt" ]] || \
      holdfast_die "armed recovery writer manifest name differs"
    restore_writers_manifest="$state_dir/$restore_writers_name"
    require_root_file "$restore_writers_manifest"
    restore_writers_sha=$(holdfast_sha256 "$restore_writers_manifest")
    [[ "$(jq -er '.restore_running_writers_sha256' "$state_file")" == "$restore_writers_sha" ]] || \
      holdfast_die "armed recovery writer manifest was replaced"
    mapfile -t restore_running_writers <"$restore_writers_manifest"
    validate_restore_writer_set
    if [[ "$writer_set_reconciled" == "true" ]]; then
      validate_writer_reconciliation_source
    fi
  fi
else
  attempt_stamp=$(date -u +%Y%m%dT%H%M%SZ)
  attempt_id="${attempt_stamp}-$$"
  if [[ "$mode" == "restore" ]]; then
    if [[ "$prior_state" == "restore_failed" ]]; then
      prior_writers_name=$(jq -er '.restore_running_writers_manifest' "$state_file")
      [[ "$prior_writers_name" =~ ^RESTORE-RUNNING-WRITERS-[0-9]{8}T[0-9]{6}Z-[0-9]+\.txt$ ]] || \
        holdfast_die "restore-failed state has an unsafe writer manifest"
      prior_writers_manifest="$state_dir/$prior_writers_name"
      require_root_file "$prior_writers_manifest"
      [[ "$(jq -er '.restore_running_writers_sha256' "$state_file")" == "$(holdfast_sha256 "$prior_writers_manifest")" ]] || \
        holdfast_die "restore-failed writer manifest was replaced"
      mapfile -t restore_running_writers <"$prior_writers_manifest"
      validate_restore_writer_set
      source_writer_count=${#restore_running_writers[@]}
      reconciled_writers=()
      for service in "${restore_running_writers[@]}"; do
        if [[ -n "${preimage_compose_services[$service]:-}" ]]; then
          reconciled_writers+=("$service")
        fi
      done
      prior_writer_set_reconciled=$(jq -er '(.writer_set_reconciled // false) | tostring' "$state_file")
      prior_writer_set_quarantined=$(jq -er '.writer_set_quarantined // "none"' "$state_file")
      [[ "$prior_writer_set_quarantined" == "none" || \
        "$prior_writer_set_quarantined" == "access-governance,newapi" ]] || \
        holdfast_die "restore-failed state carries an unknown writer quarantine set"
      if [[ "$prior_writer_set_quarantined" == "access-governance,newapi" ]]; then
        [[ "$quarantine_access_chain" == "true" ]] || \
          holdfast_die "access-chain quarantine retry requires its explicit flag"
      elif [[ "$prior_writer_set_reconciled" == "true" && \
        "$quarantine_access_chain" == "true" ]]; then
        holdfast_die "writer reconciliation retry does not carry access-chain quarantine"
      fi
      if [[ "$prior_writer_set_reconciled" == "true" ]]; then
        ((${#reconciled_writers[@]} == source_writer_count)) || \
          holdfast_die "previously reconciled writer set differs from estate preimage"
        writer_set_reconciled="true"
        writer_set_source_attempt=$(jq -er '.writer_set_source_attempt' "$state_file")
        writer_set_source_failure_sha=$(jq -er '.writer_set_source_failure_receipt_sha256' "$state_file")
        writer_set_source_state_sha=$(jq -er '.writer_set_source_state_sha256' "$state_file")
        writer_set_source_manifest_sha=$(jq -er '.writer_set_source_manifest_sha256' "$state_file")
        writer_set_preimage_compose_sha=$(jq -er '.writer_set_preimage_compose_sha256' "$state_file")
        writer_set_quarantined=$prior_writer_set_quarantined
        [[ "$writer_set_source_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
          "$writer_set_source_failure_sha" =~ ^[0-9a-f]{64}$ && \
          "$writer_set_source_state_sha" =~ ^[0-9a-f]{64}$ && \
          "$writer_set_source_manifest_sha" =~ ^[0-9a-f]{64}$ && \
          "$writer_set_preimage_compose_sha" == "$preimage_compose_sha" ]] || \
          holdfast_die "inherited writer reconciliation evidence is invalid"
        current_attempt=$(jq -er '.recovery_attempt_id' "$state_file")
        [[ "$current_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
          holdfast_die "inherited writer reconciliation attempt is unsafe"
        current_failed_state="$state_dir/APPLY-RECOVERY-FAILED-${current_attempt}.json"
        require_root_file "$current_failed_state"
        [[ "$(holdfast_sha256 "$current_failed_state")" == "$(holdfast_sha256 "$state_file")" ]] || \
          holdfast_die "inherited writer reconciliation CURRENT differs from immutable state"
        current_failure_name=$(jq -er '.apply_failure_receipt' "$state_file")
        current_arm_name=$(jq -er '.recovery_armed_receipt' "$state_file")
        [[ "$current_failure_name" =~ ^APPLY-RECOVERY-FAILED-${current_attempt}(-retry-[0-9]+)?\.receipt$ && \
          "$current_arm_name" == "APPLY-RECOVERY-ARMED-${current_attempt}.receipt" ]] || \
          holdfast_die "inherited writer reconciliation evidence identity is unsafe"
        current_failure="$state_dir/$current_failure_name"
        current_arm="$state_dir/$current_arm_name"
        require_root_file "$current_failure"
        require_root_file "$current_arm"
        [[ "$(holdfast_sha256 "$current_arm")" == \
            "$(jq -er '.recovery_armed_receipt_sha256' "$state_file")" && \
          "$(holdfast_sha256 "$current_arm")" == \
            "$(holdfast_receipt_value "$current_failure" recovery_armed_receipt_sha256)" ]] || \
          holdfast_die "inherited writer reconciliation arm was replaced"
        for key in writer_set_reconciled writer_set_source_attempt \
          writer_set_source_failure_receipt_sha256 writer_set_source_state_sha256 \
          writer_set_source_manifest_sha256 writer_set_preimage_compose_sha256; do
          [[ "$(holdfast_receipt_value "$current_failure" "$key")" == \
              "$(holdfast_receipt_value "$current_arm" "$key")" && \
            "$(holdfast_receipt_value "$current_arm" "$key")" == \
              "$(jq -er ".${key} | tostring" "$state_file")" ]] || \
            holdfast_die "inherited writer reconciliation authority differs: $key"
        done
        [[ "$(holdfast_receipt_value "$current_failure" writer_set_quarantined 2>/dev/null || printf none)" == \
            "$writer_set_quarantined" && \
          "$(holdfast_receipt_value "$current_arm" writer_set_quarantined 2>/dev/null || printf none)" == \
            "$writer_set_quarantined" ]] || \
          holdfast_die "inherited writer quarantine authority differs"
        validate_writer_reconciliation_source
      elif [[ "$quarantine_access_chain" == "true" ]]; then
        [[ "$prior_writer_set_quarantined" == "none" ]] || \
          holdfast_die "inactive reconciliation carries writer quarantine evidence"
        validate_access_chain_live_failure
        writer_set_source_attempt=$(jq -er '.recovery_attempt_id' "$state_file")
        [[ "$writer_set_source_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
          holdfast_die "access-chain quarantine source attempt is unsafe"
        writer_set_source_failure_sha=$(jq -er '.apply_failure_receipt_sha256' "$state_file")
        writer_set_source_manifest_sha=$(holdfast_sha256 "$prior_writers_manifest")
        writer_set_source_state_sha=$(holdfast_sha256 "$state_file")
        source_failed_state="$state_dir/APPLY-RECOVERY-FAILED-${writer_set_source_attempt}.json"
        require_root_file "$source_failed_state"
        [[ "$(holdfast_sha256 "$source_failed_state")" == "$writer_set_source_state_sha" ]] || \
          holdfast_die "access-chain quarantine CURRENT differs from immutable failure state"
        writer_set_reconciled="true"
        writer_set_quarantined="access-governance,newapi"
        restore_running_writers=()
        for service in "${reconciled_writers[@]}"; do
          if [[ "$service" != "access-governance" && "$service" != "newapi" ]]; then
            restore_running_writers+=("$service")
          fi
        done
        validate_writer_reconciliation_source
      elif ((${#reconciled_writers[@]} != source_writer_count)); then
        [[ "$runtime_schema" == "2" && \
          "$(jq -er '.recovery_failure_stage' "$state_file")" == \
            "restore_prior_running_writers" && \
          "$(jq -er '.recovery_route_database_state' "$state_file")" == "absent" && \
          "$(jq -er '.ingress_opened | tostring' "$state_file")" == "false" ]] || \
          holdfast_die "restore-failed writer reconciliation lacks closed schema-v2 authority"
        writer_set_source_attempt=$(jq -er '.recovery_attempt_id' "$state_file")
        [[ "$writer_set_source_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
          holdfast_die "writer reconciliation source attempt is unsafe"
        writer_set_source_failure_sha=$(jq -er '.apply_failure_receipt_sha256' "$state_file")
        writer_set_source_manifest_sha=$(holdfast_sha256 "$prior_writers_manifest")
        writer_set_source_state_sha=$(holdfast_sha256 "$state_file")
        source_failed_state="$state_dir/APPLY-RECOVERY-FAILED-${writer_set_source_attempt}.json"
        require_root_file "$source_failed_state"
        [[ "$(holdfast_sha256 "$source_failed_state")" == "$writer_set_source_state_sha" ]] || \
          holdfast_die "restore-failed CURRENT differs from its immutable failure state"
        writer_set_reconciled="true"
        restore_running_writers=("${reconciled_writers[@]}")
        validate_writer_reconciliation_source
      fi
    else
      declare -A restore_needed=()
      for service in "${application_writers[@]}"; do
        writer_ids=()
        writer_output=$(service_container_ids "$service") || \
          holdfast_die "could not inspect application writer before restore: $service"
        if [[ -n "$writer_output" ]]; then mapfile -t writer_ids <<<"$writer_output"; fi
        ((${#writer_ids[@]} <= 1)) || holdfast_die "multiple containers exist for application writer: $service"
        if ((${#writer_ids[@]} == 1)); then
          writer_state=$("$docker_bin" inspect -f '{{.State.Status}}' "${writer_ids[0]}")
          if [[ "$writer_state" == "running" ]]; then restore_needed["$service"]=1; fi
        fi
      done
      for service in "${runtime_prior_services[@]}"; do restore_needed["$service"]=1; done
      for service in "${application_writers[@]}"; do
        if [[ "${restore_needed[$service]:-0}" == "1" && \
          -n "${preimage_compose_services[$service]:-}" ]]; then
          restore_running_writers+=("$service")
        fi
      done
    fi
    validate_restore_writer_set
    restore_writers_manifest="$state_dir/RESTORE-RUNNING-WRITERS-${attempt_id}.txt"
    restore_writers_tmp="$state_dir/.RESTORE-RUNNING-WRITERS.$$"
    [[ ! -e "$restore_writers_manifest" && ! -L "$restore_writers_manifest" && ! -e "$restore_writers_tmp" && ! -L "$restore_writers_tmp" ]] || \
      holdfast_die "restore writer manifest path already exists"
    : >"$restore_writers_tmp"
    if ((${#restore_running_writers[@]})); then printf '%s\n' "${restore_running_writers[@]}" >"$restore_writers_tmp"; fi
    chmod 0600 "$restore_writers_tmp"
    if [[ "$successor_recovery_v3" != "true" ]]; then
      mv -fT -- "$restore_writers_tmp" "$restore_writers_manifest"
      sync -f "$restore_writers_manifest"
      restore_writers_sha=$(holdfast_sha256 "$restore_writers_manifest")
    fi
  fi
  revalidate_v3_successor_authority "$state_file"
  validate_v3_recovery_mutation_authority
  if [[ "$successor_recovery_v3" == "true" ]]; then
    require_root_file "$state_file"
    [[ "$(holdfast_sha256 "$state_file")" == "$v3_initial_probe_current_sha" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$state_file")" == \
        "$v3_initial_probe_current_identity" ]] || \
      holdfast_die "schema-v3 recovery CURRENT changed before its durable arm"
    if [[ "$mode" == "restore" && "$prior_state" != "apply_recovery_armed" ]]; then
      [[ ! -e "$restore_writers_manifest" && ! -L "$restore_writers_manifest" ]] || \
        holdfast_die "schema-v3 recovery writer manifest appeared before its mutation fence"
      mv -fT -- "$restore_writers_tmp" "$restore_writers_manifest"
      sync -f "$restore_writers_manifest"
      restore_writers_sha=$(holdfast_sha256 "$restore_writers_manifest")
    fi
  fi
  recovery_armed_receipt="$state_dir/APPLY-RECOVERY-ARMED-${attempt_id}.receipt"
  recovery_armed_tmp="$state_dir/.APPLY-RECOVERY-ARMED.$$"
  [[ ! -e "$recovery_armed_receipt" && ! -L "$recovery_armed_receipt" && ! -e "$recovery_armed_tmp" && ! -L "$recovery_armed_tmp" ]] || \
    holdfast_die "recovery arm receipt path already exists"
  {
    printf 'schema_version=%s\n' "$(recovery_receipt_schema_version)"
    printf 'armed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'attempt_id=%s\n' "$attempt_id"
    printf 'mode=%s\n' "$mode"
    printf 'prior_state=%s\n' "$prior_state"
    printf 'legacy_orphan_adopted=%s\n' "$legacy_orphan"
    printf 'legacy_empty_strad=%s\n' "$legacy_empty_strad"
    printf 'runtime_backup_schema=%s\n' "$runtime_schema"
    printf 'estate_transaction_state=%s\n' "$transaction_state"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'transaction_sha256=%s\n' "$transaction_sha"
    printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
    printf 'apply_armed_receipt_sha256=%s\n' "$armed_receipt_sha"
    printf 'release_evidence_sha256=%s\n' "$release_evidence_sha"
    printf 'dry_run_receipt_sha256=%s\n' "$dry_receipt_sha"
    if [[ "$transaction_is_preimage" == "true" ]]; then
      printf 'live_disposition=preimage\n'
    else
      printf 'live_disposition=%s\n' "$([[ "$mode" == "resume" ]] && printf applied || printf mixed)"
    fi
    printf 'restore_running_writers_manifest=%s\n' "$([[ "$mode" == "restore" ]] && basename -- "$restore_writers_manifest" || printf not-applicable)"
    printf 'restore_running_writers_sha256=%s\n' "$restore_writers_sha"
    printf 'writer_set_reconciled=%s\n' "$writer_set_reconciled"
    printf 'writer_set_source_attempt=%s\n' "$writer_set_source_attempt"
    printf 'writer_set_source_failure_receipt_sha256=%s\n' "$writer_set_source_failure_sha"
    printf 'writer_set_source_state_sha256=%s\n' "$writer_set_source_state_sha"
    printf 'writer_set_source_manifest_sha256=%s\n' "$writer_set_source_manifest_sha"
    printf 'writer_set_preimage_compose_sha256=%s\n' "$writer_set_preimage_compose_sha"
    printf 'writer_set_quarantined=%s\n' "$writer_set_quarantined"
    printf 'pre_restored_retry=%s\n' "$pre_restored_retry"
    printf 'pre_restored_source_attempt=%s\n' "$pre_restored_source_attempt"
    printf 'pre_restored_runtime_snapshot_sha256=%s\n' "$pre_restored_runtime_snapshot"
    printf 'pre_restored_estate_snapshot_sha256=%s\n' "$pre_restored_estate_snapshot"
    printf 'pre_restored_superseded_attempt=%s\n' "$pre_restored_superseded_attempt"
    printf 'pre_restored_superseded_failure_receipt_sha256=%s\n' "$pre_restored_superseded_failure_sha"
    printf 'pre_restored_superseded_state_sha256=%s\n' "$pre_restored_superseded_state_sha"
    printf 'pre_restored_runtime_disposition=%s\n' "$pre_restored_runtime_disposition"
    append_recovery_route_contract_fields
    append_successor_lineage_receipt_fields
  } >"$recovery_armed_tmp"
  chmod 0600 "$recovery_armed_tmp"
  mv -fT -- "$recovery_armed_tmp" "$recovery_armed_receipt"
  sync -f "$recovery_armed_receipt"
  validate_recovery_route_contract \
    "$recovery_armed_receipt" "new recovery arm receipt"
  recovery_armed_sha=$(holdfast_sha256 "$recovery_armed_receipt")

  state_tmp="$state_dir/.CURRENT.json.$$"
  if [[ -f "$state_file" ]]; then
    jq \
      --arg prior "$prior_state" --arg mode "$mode" --arg attempt "$attempt_id" \
      --arg armed "$(basename -- "$recovery_armed_receipt")" --arg armed_sha "$recovery_armed_sha" \
      --arg writers "$([[ "$mode" == "restore" ]] && basename -- "$restore_writers_manifest" || printf not-applicable)" \
      --arg writers_sha "$restore_writers_sha" --arg legacy_empty "$legacy_empty_strad" \
      --arg pre_restored "$pre_restored_retry" --arg pre_restored_attempt "$pre_restored_source_attempt" \
      --arg pre_restored_runtime "$pre_restored_runtime_snapshot" \
      --arg pre_restored_estate "$pre_restored_estate_snapshot" \
      --arg pre_restored_superseded_attempt "$pre_restored_superseded_attempt" \
      --arg pre_restored_superseded_failure "$pre_restored_superseded_failure_sha" \
      --arg pre_restored_superseded_state "$pre_restored_superseded_state_sha" \
      --arg pre_restored_disposition "$pre_restored_runtime_disposition" \
      --arg writer_reconciled "$writer_set_reconciled" \
      --arg writer_source_attempt "$writer_set_source_attempt" \
      --arg writer_source_failure "$writer_set_source_failure_sha" \
      --arg writer_source_state "$writer_set_source_state_sha" \
      --arg writer_source_manifest "$writer_set_source_manifest_sha" \
      --arg writer_preimage_compose "$writer_set_preimage_compose_sha" \
      --arg writer_quarantined "$writer_set_quarantined" \
      --arg transaction "$transaction_sha" --arg applied_targets "$applied_targets_sha" \
      '.state="apply_recovery_armed" | .recovery_prior_state=$prior | .recovery_mode=$mode | .recovery_attempt_id=$attempt | .recovery_armed_receipt=$armed | .recovery_armed_receipt_sha256=$armed_sha | .restore_running_writers_manifest=$writers | .restore_running_writers_sha256=$writers_sha | .legacy_empty_strad=($legacy_empty == "true") | .pre_restored_retry=($pre_restored == "true") | .pre_restored_source_attempt=$pre_restored_attempt | .pre_restored_runtime_snapshot_sha256=$pre_restored_runtime | .pre_restored_estate_snapshot_sha256=$pre_restored_estate | .pre_restored_superseded_attempt=$pre_restored_superseded_attempt | .pre_restored_superseded_failure_receipt_sha256=$pre_restored_superseded_failure | .pre_restored_superseded_state_sha256=$pre_restored_superseded_state | .pre_restored_runtime_disposition=$pre_restored_disposition | .writer_set_reconciled=($writer_reconciled == "true") | .writer_set_source_attempt=$writer_source_attempt | .writer_set_source_failure_receipt_sha256=$writer_source_failure | .writer_set_source_state_sha256=$writer_source_state | .writer_set_source_manifest_sha256=$writer_source_manifest | .writer_set_preimage_compose_sha256=$writer_preimage_compose | .writer_set_quarantined=$writer_quarantined | .transaction_sha256=$transaction | .applied_targets_sha256=$applied_targets' \
      "$state_file" >"$state_tmp"
  else
    jq -n \
      --arg estate "$estate_root" --arg backup "$backup" --arg release "$release_evidence_sha" \
      --arg dry "$dry_receipt_sha" --arg control "$control_sha" --arg prior "$prior_state" \
      --arg mode "$mode" --arg attempt "$attempt_id" --arg armed "$(basename -- "$recovery_armed_receipt")" \
      --arg armed_sha "$recovery_armed_sha" --arg apply_armed_sha "$armed_receipt_sha" \
      --arg writers "$([[ "$mode" == "restore" ]] && basename -- "$restore_writers_manifest" || printf not-applicable)" \
      --arg writers_sha "$restore_writers_sha" --arg legacy_empty "$legacy_empty_strad" \
      --arg legacy_adopted "$legacy_orphan" --arg armed_pointer_missing "$armed_pointer_missing" \
      --arg pre_restored "$pre_restored_retry" --arg pre_restored_attempt "$pre_restored_source_attempt" \
      --arg pre_restored_runtime "$pre_restored_runtime_snapshot" \
      --arg pre_restored_estate "$pre_restored_estate_snapshot" \
      --arg pre_restored_superseded_attempt "$pre_restored_superseded_attempt" \
      --arg pre_restored_superseded_failure "$pre_restored_superseded_failure_sha" \
      --arg pre_restored_superseded_state "$pre_restored_superseded_state_sha" \
      --arg pre_restored_disposition "$pre_restored_runtime_disposition" \
      --arg writer_reconciled "$writer_set_reconciled" \
      --arg writer_source_attempt "$writer_set_source_attempt" \
      --arg writer_source_failure "$writer_set_source_failure_sha" \
      --arg writer_source_state "$writer_set_source_state_sha" \
      --arg writer_source_manifest "$writer_set_source_manifest_sha" \
      --arg writer_preimage_compose "$writer_set_preimage_compose_sha" \
      --arg writer_quarantined "$writer_set_quarantined" \
      --arg transaction "$transaction_sha" --arg applied_targets "$applied_targets_sha" \
      '{schema_version:2,state:"apply_recovery_armed",estate_root:$estate,backup_dir:$backup,apply_armed_receipt_sha256:$apply_armed_sha,release_evidence_sha256:$release,dry_run_receipt_sha256:$dry,control_sha256:$control,transaction_sha256:$transaction,applied_targets_sha256:$applied_targets,recovery_prior_state:$prior,recovery_mode:$mode,recovery_attempt_id:$attempt,recovery_armed_receipt:$armed,recovery_armed_receipt_sha256:$armed_sha,restore_running_writers_manifest:$writers,restore_running_writers_sha256:$writers_sha,legacy_orphan_adopted:($legacy_adopted == "true"),apply_armed_pointer_was_missing:($armed_pointer_missing == "true"),legacy_empty_strad:($legacy_empty == "true"),pre_restored_retry:($pre_restored == "true"),pre_restored_source_attempt:$pre_restored_attempt,pre_restored_runtime_snapshot_sha256:$pre_restored_runtime,pre_restored_estate_snapshot_sha256:$pre_restored_estate,pre_restored_superseded_attempt:$pre_restored_superseded_attempt,pre_restored_superseded_failure_receipt_sha256:$pre_restored_superseded_failure,pre_restored_superseded_state_sha256:$pre_restored_superseded_state,pre_restored_runtime_disposition:$pre_restored_disposition,writer_set_reconciled:($writer_reconciled == "true"),writer_set_source_attempt:$writer_source_attempt,writer_set_source_failure_receipt_sha256:$writer_source_failure,writer_set_source_state_sha256:$writer_source_state,writer_set_source_manifest_sha256:$writer_source_manifest,writer_set_preimage_compose_sha256:$writer_preimage_compose,writer_set_quarantined:$writer_quarantined,ingress_opened:false}' \
      >"$state_tmp"
  fi
  chmod 0600 "$state_tmp"
  state_tmp_sha=$(holdfast_sha256 "$state_tmp")
  revalidate_v3_successor_authority "$state_file"
  validate_v3_recovery_mutation_authority
  if [[ "$successor_recovery_v3" == "true" ]]; then
    require_root_file "$recovery_armed_receipt"
    [[ "$(holdfast_sha256 "$recovery_armed_receipt")" == "$recovery_armed_sha" ]] || \
      holdfast_die "schema-v3 recovery arm changed before CURRENT commit"
    validate_successor_lineage_receipt "$recovery_armed_receipt"
    [[ "$(holdfast_sha256 "$state_tmp")" == "$state_tmp_sha" ]] || \
      holdfast_die "schema-v3 recovery CURRENT candidate changed before commit"
  fi
  mv -fT -- "$state_tmp" "$state_file"
  sync -f "$state_file"
fi

validate_successor_lineage_receipt "$recovery_armed_receipt"

if [[ "$prior_state" == "apply_recovery_armed" && "$mode" == "restore" && \
  "$transaction_is_preimage" != "true" && "$legacy_orphan" == "false" ]]; then
  validate_recovery_stage_authority
fi

v3_failure_fence_files=()
declare -A v3_failure_fence_hashes=() v3_failure_fence_identities=()
snapshot_v3_failure_fence() {
  local line relative file
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  v3_failure_fence_files=("$state_file" "$recovery_armed_receipt" "$backup/CONTROL.sha256")
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]] || \
      holdfast_die "schema-v3 failure fence encountered an invalid CONTROL line"
    relative=${BASH_REMATCH[1]}
    v3_failure_fence_files+=("$backup/$relative")
  done <"$backup/CONTROL.sha256"
  if [[ "$mode" == "restore" ]]; then
    v3_failure_fence_files+=("$restore_writers_manifest")
  fi
  v3_failure_fence_hashes=()
  v3_failure_fence_identities=()
  for file in "${v3_failure_fence_files[@]}"; do
    require_root_file "$file"
    v3_failure_fence_hashes["$file"]=$(holdfast_sha256 "$file")
    v3_failure_fence_identities["$file"]=$(stat -c '%d:%i:%u:%h:%f' -- "$file")
  done
}

validate_v3_failure_fence() {
  local file
  [[ "$successor_recovery_v3" == "true" ]] || return 0
  for file in "${v3_failure_fence_files[@]}"; do
    require_root_file "$file"
    [[ "$(holdfast_sha256 "$file")" == "${v3_failure_fence_hashes[$file]}" && \
      "$(stat -c '%d:%i:%u:%h:%f' -- "$file")" == \
        "${v3_failure_fence_identities[$file]}" ]] || \
      holdfast_die "schema-v3 recovery authority changed before failure evidence: $file"
  done
  validate_v3_cached_control_authority
}

recovery_complete="false"
failure_stage="recovery_armed"
snapshot_v3_failure_fence
record_recovery_failure() {
  local status=$1
  local failed_at failed_receipt failed_tmp failed_state failed_state_tmp route_database_state
  trap - EXIT INT TERM
  set +e
  validate_v3_failure_fence
  route_database_state="unverified"
  if verify_database_absent; then route_database_state="absent"; fi
  validate_v3_failure_fence
  failed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  failed_receipt="$state_dir/APPLY-RECOVERY-FAILED-${attempt_id}.receipt"
  if [[ -e "$failed_receipt" || -L "$failed_receipt" ]]; then
    failed_receipt="$state_dir/APPLY-RECOVERY-FAILED-${attempt_id}-retry-$(date -u +%s).receipt"
  fi
  failed_tmp="$state_dir/.APPLY-RECOVERY-FAILED.$$"
  {
    printf 'failed_at=%s\n' "$failed_at"
    printf 'attempt_id=%s\n' "$attempt_id"
    printf 'mode=%s\n' "$mode"
    printf 'stage=%s\n' "$failure_stage"
    printf 'status=%s\n' "$status"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'transaction_sha256=%s\n' "$transaction_sha"
    printf 'recovery_armed_receipt_sha256=%s\n' "$recovery_armed_sha"
    printf 'restore_running_writers_sha256=%s\n' "$restore_writers_sha"
    printf 'writer_set_reconciled=%s\n' "$writer_set_reconciled"
    printf 'writer_set_source_attempt=%s\n' "$writer_set_source_attempt"
    printf 'writer_set_source_failure_receipt_sha256=%s\n' "$writer_set_source_failure_sha"
    printf 'writer_set_source_state_sha256=%s\n' "$writer_set_source_state_sha"
    printf 'writer_set_source_manifest_sha256=%s\n' "$writer_set_source_manifest_sha"
    printf 'writer_set_preimage_compose_sha256=%s\n' "$writer_set_preimage_compose_sha"
    printf 'writer_set_quarantined=%s\n' "$writer_set_quarantined"
    printf 'pre_restored_retry=%s\n' "$pre_restored_retry"
    printf 'pre_restored_source_attempt=%s\n' "$pre_restored_source_attempt"
    printf 'pre_restored_runtime_snapshot_sha256=%s\n' "$pre_restored_runtime_snapshot"
    printf 'pre_restored_estate_snapshot_sha256=%s\n' "$pre_restored_estate_snapshot"
    printf 'pre_restored_superseded_attempt=%s\n' "$pre_restored_superseded_attempt"
    printf 'pre_restored_superseded_failure_receipt_sha256=%s\n' "$pre_restored_superseded_failure_sha"
    printf 'pre_restored_superseded_state_sha256=%s\n' "$pre_restored_superseded_state_sha"
    printf 'pre_restored_runtime_disposition=%s\n' "$pre_restored_runtime_disposition"
    printf 'route_database_state=%s\n' "$route_database_state"
    printf 'ingress_opened=false\n'
    if [[ "$successor_recovery_v3" == "true" ]]; then
      append_successor_lineage_receipt_fields
    fi
  } >"$failed_tmp" && chmod 0600 "$failed_tmp" && mv -fT -- "$failed_tmp" "$failed_receipt" && sync -f "$failed_receipt"
  failed_state="$state_dir/APPLY-RECOVERY-FAILED-${attempt_id}.json"
  failed_state_tmp="$state_dir/.APPLY-RECOVERY-FAILED-STATE.$$"
  if [[ -f "$state_file" && ! -L "$state_file" && -f "$failed_receipt" ]]; then
    [[ ! -e "$failed_state" && ! -L "$failed_state" ]] || {
      echo "holdfast: immutable failed recovery state already exists: $failed_state" >&2
      exit "$status"
    }
    failed_state_name="apply_recovery_failed"
    if [[ "$mode" == "restore" ]]; then failed_state_name="restore_failed"; fi
    jq \
      --arg failed_state "$failed_state_name" \
      --arg route_database_state "$route_database_state" \
      --arg stage "$failure_stage" --arg receipt "$(basename -- "$failed_receipt")" \
      --arg receipt_sha "$(holdfast_sha256 "$failed_receipt")" \
      '.state=$failed_state | .recovery_failure_stage=$stage | .recovery_route_database_state=$route_database_state | .apply_failure_receipt=$receipt | .apply_failure_receipt_sha256=$receipt_sha' \
      "$state_file" >"$failed_state_tmp" && chmod 0600 "$failed_state_tmp" && \
      install -o 0 -g 0 -m 0600 -- "$failed_state_tmp" "$failed_state" && \
      mv -fT -- "$failed_state_tmp" "$state_file" && sync -f "$state_file"
  fi
  echo "holdfast: apply recovery failed at $failure_stage; immutable failure evidence: $failed_receipt" >&2
  exit "$status"
}
on_recovery_exit() {
  local status=$?
  if [[ "$recovery_complete" != "true" ]]; then
    [[ $status -ne 0 ]] || status=1
    record_recovery_failure "$status"
  fi
}
trap on_recovery_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

runtime_restore_snapshot="none"
estate_restore_state="none"
writers_reactivated="not-applicable"
uncaptured_writers_inactive="not-applicable"
quarantined_writers_inactive="not-applicable"
if [[ "$mode" == "restore" ]]; then
  failure_stage="quiesce_release_services"
  revalidate_v3_successor_authority "$state_file"
  validate_v3_active_recovery_arm_authority
  validate_v3_recovery_mutation_authority
  for service in "${application_writers[@]}"; do
    quiesced_ids=()
    quiesced_output=$(service_container_ids "$service") || \
      holdfast_die "could not inspect release service after quiesce: $service"
    if [[ -n "$quiesced_output" ]]; then mapfile -t quiesced_ids <<<"$quiesced_output"; fi
    ((${#quiesced_ids[@]} <= 1)) || holdfast_die "multiple containers exist after quiesce: $service"
    if ((${#quiesced_ids[@]})); then "$docker_bin" stop -t 120 "${quiesced_ids[@]}" >/dev/null; fi
    for container_id in "${quiesced_ids[@]}"; do
      quiesced_state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$quiesced_state" != "running" && "$quiesced_state" != "restarting" && "$quiesced_state" != "paused" ]] || \
        holdfast_die "release service remains active after quiesce: $service"
    done
  done

  if [[ "$transaction_is_preimage" == "true" ]]; then
    if [[ "$pre_restored_retry" == "true" ]]; then
      verify_legacy_pre_restored_runtime_disposition || \
        holdfast_die "legacy runtime disposition changed before pre-restored writer recovery"
      runtime_restore_snapshot="$pre_restored_runtime_snapshot"
      estate_restore_state="$pre_restored_estate_snapshot"
    else
      runtime_restore_snapshot="not-required"
      estate_restore_state="not-required"
    fi
    verify_live_disposition preimage
  else
    failure_stage="runtime_restore_after_writer_stop"
    runtime_restore_args=(--execute --compose-root "$recovery_compose_root" --backup-dir "$backup/runtime")
    if [[ "$legacy_empty_strad" == "true" ]]; then runtime_restore_args+=(--legacy-empty-strad); fi
    revalidate_v3_successor_authority "$state_file"
    validate_v3_active_recovery_arm_authority
    validate_v3_recovery_mutation_authority
    validate_v3_recovery_stage_snapshot
    "$runtime_restore" "${runtime_restore_args[@]}"
    require_root_file "$backup/runtime/RESTORE.receipt"
    [[ "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" schema_version)" == "2" ]] || \
      holdfast_die "runtime restore receipt schema differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" database_identity)" == \
      "postgres:5432/strad" ]] || holdfast_die "runtime restore receipt database identity differs"
    expected_database_restore="restored"
    expected_restore_mode="schema-v2"
    if [[ "$legacy_empty_strad" == "true" ]]; then
      expected_database_restore="skipped_proven_empty"
      expected_restore_mode="legacy-empty-strad"
    fi
    [[ "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" restore_mode)" == \
      "$expected_restore_mode" ]] || holdfast_die "runtime restore receipt mode differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" database_restore)" == \
      "$expected_database_restore" ]] || holdfast_die "runtime restore database disposition differs"
    [[ "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" runtime_writers_removed)" == "passed" && \
      "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" postgres_container_attestation)" == "passed" && \
      "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" postgres_pgdata_mount)" == "passed" && \
      "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" postgres_runtime_epoch_attestation)" == "passed" && \
      "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" volume_mount_release)" == "passed" && \
      "$(holdfast_receipt_value "$backup/runtime/RESTORE.receipt" volume_count)" == "6" ]] || \
      holdfast_die "runtime restore receipt lacks writer, PostgreSQL, or volume proof"
    runtime_postgres_container_id=$(holdfast_receipt_value \
      "$backup/runtime/RESTORE.receipt" postgres_container_id)
    runtime_postgres_config_hash=$(holdfast_receipt_value \
      "$backup/runtime/RESTORE.receipt" postgres_config_hash)
    runtime_postgres_started_at=$(holdfast_receipt_value \
      "$backup/runtime/RESTORE.receipt" postgres_started_at)
    runtime_postgres_restart_count=$(holdfast_receipt_value \
      "$backup/runtime/RESTORE.receipt" postgres_restart_count)
    [[ "$runtime_postgres_container_id" =~ ^[0-9a-f]{64}$ && \
      "$runtime_postgres_config_hash" =~ ^[0-9a-f]{64}$ && \
      "$runtime_postgres_started_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$ && \
      "$runtime_postgres_restart_count" =~ ^(0|[1-9][0-9]*)$ ]] || \
      holdfast_die "runtime restore receipt has an invalid PostgreSQL epoch proof"
    if [[ "$successor_recovery_v3" == "true" ]]; then
      runtime_restore_receipt_sha=$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")
      runtime_restore_receipt_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
        "$backup/runtime/RESTORE.receipt")
      revalidate_v3_successor_authority "$state_file"
      validate_v3_active_recovery_arm_authority
      validate_v3_recovery_mutation_authority
      require_root_file "$backup/runtime/RESTORE.receipt"
      [[ "$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")" == \
          "$runtime_restore_receipt_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$backup/runtime/RESTORE.receipt")" == \
          "$runtime_restore_receipt_identity" ]] || \
        holdfast_die "schema-v3 runtime restore evidence changed before snapshot"
    fi
    runtime_restore_copy="$state_dir/RUNTIME-RESTORE-${attempt_id}-$(date -u +%Y%m%dT%H%M%S%N).receipt"
    [[ ! -e "$runtime_restore_copy" && ! -L "$runtime_restore_copy" ]] || holdfast_die "runtime restore snapshot already exists"
    install -o 0 -g 0 -m 0600 -- "$backup/runtime/RESTORE.receipt" "$runtime_restore_copy"
    sync -f "$runtime_restore_copy"
    runtime_restore_snapshot=$(holdfast_sha256 "$runtime_restore_copy")

    failure_stage="mixed_estate_restore"
    recovery_estate="$state_dir/APPLY-RECOVERY-ESTATE-${attempt_id}-$(date -u +%Y%m%dT%H%M%S%N)"
    [[ ! -e "$recovery_estate" && ! -L "$recovery_estate" ]] || holdfast_die "recovery estate attempt path already exists"
    mkdir -m 0700 -- "$recovery_estate"
    cp -a -- "$backup/estate/." "$recovery_estate/"
    revalidate_v3_successor_authority "$state_file"
    if [[ "$successor_recovery_v3" == "true" ]]; then
      validate_v3_active_recovery_arm_authority
      validate_v3_recovery_mutation_authority
      verify_live_disposition applied
      cmp -s -- "$backup/estate/APPLIED-TARGETS.sha256" \
        "$recovery_estate/APPLIED-TARGETS.sha256" || \
        holdfast_die "recovery estate applied-target authority changed before restore"
      cmp -s -- "$backup/estate/PREIMAGES.sha256" \
        "$recovery_estate/PREIMAGES.sha256" || \
        holdfast_die "recovery estate preimage authority changed before restore"
      cmp -s -- "$backup/estate/ABSENT.before" "$recovery_estate/ABSENT.before" || \
        holdfast_die "recovery estate absent authority changed before restore"
      cmp -s -- "$backup/estate/TRANSACTION.json" "$recovery_estate/TRANSACTION.json" || \
        holdfast_die "recovery estate transaction authority changed before restore"
      (cd "$recovery_estate/tree" && sha256sum --check "$recovery_estate/PREIMAGES.sha256")
    fi
    python3 "$script_dir/estate_transaction.py" restore \
      --estate-root "$estate_root" --backup-dir "$recovery_estate"
    require_root_file "$recovery_estate/TRANSACTION.json"
    [[ "$(jq -er '.state' "$recovery_estate/TRANSACTION.json")" == "restored" ]] || \
      holdfast_die "mixed estate restore did not record restored state"
    if [[ "$successor_recovery_v3" == "true" ]]; then
      recovery_transaction_sha=$(holdfast_sha256 "$recovery_estate/TRANSACTION.json")
      recovery_transaction_identity=$(stat -c '%d:%i:%u:%h:%f' -- \
        "$recovery_estate/TRANSACTION.json")
      revalidate_v3_successor_authority "$state_file"
      validate_v3_active_recovery_arm_authority
      validate_v3_recovery_mutation_authority
      require_root_file "$recovery_estate/TRANSACTION.json"
      [[ "$(holdfast_sha256 "$recovery_estate/TRANSACTION.json")" == \
          "$recovery_transaction_sha" && \
        "$(stat -c '%d:%i:%u:%h:%f' -- "$recovery_estate/TRANSACTION.json")" == \
          "$recovery_transaction_identity" ]] || \
        holdfast_die "schema-v3 estate restore evidence changed before snapshot"
    fi
    estate_restore_copy="$state_dir/ESTATE-RESTORE-${attempt_id}-$(date -u +%Y%m%dT%H%M%S%N).json"
    [[ ! -e "$estate_restore_copy" && ! -L "$estate_restore_copy" ]] || holdfast_die "estate restore snapshot already exists"
    install -o 0 -g 0 -m 0600 -- "$recovery_estate/TRANSACTION.json" "$estate_restore_copy"
    sync -f "$estate_restore_copy"
    estate_restore_state=$(holdfast_sha256 "$estate_restore_copy")
  fi
  verify_live_disposition preimage
  "${compose[@]}" config --quiet

  failure_stage="restore_prior_running_writers"
  if ((${#restore_running_writers[@]})); then
    revalidate_v3_successor_authority "$state_file"
    if [[ "$successor_recovery_v3" == "true" ]]; then
      validate_v3_active_recovery_arm_authority
      validate_v3_recovery_mutation_authority
      verify_live_disposition preimage
      "${compose[@]}" config --quiet
    fi
    "${compose[@]}" up -d --no-build --wait --wait-timeout 300 --no-deps "${restore_running_writers[@]}"
    for service in "${restore_running_writers[@]}"; do
      restored_ids=()
      restored_output=$("${compose[@]}" ps -aq "$service") || \
        holdfast_die "could not inspect restored writer container: $service"
      if [[ -n "$restored_output" ]]; then mapfile -t restored_ids <<<"$restored_output"; fi
      ((${#restored_ids[@]} == 1)) || holdfast_die "restored writer container identity differs: $service"
      [[ "$("$docker_bin" inspect -f '{{.State.Status}}' "${restored_ids[0]}")" == "running" ]] || \
        holdfast_die "restored writer is not running: $service"
      restored_health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${restored_ids[0]}")
      [[ "$restored_health" == "none" || "$restored_health" == "healthy" ]] || \
        holdfast_die "restored writer is not healthy: $service"
    done
  fi
  writers_reactivated="passed"
  for service in "${application_writers[@]}"; do
    if restore_writer_was_running "$service"; then continue; fi
    uncaptured_ids=()
    uncaptured_output=$(
      "$docker_bin" ps -aq \
        --filter "label=com.docker.compose.project=$compose_project" \
        --filter "label=com.docker.compose.service=$service"
    ) || holdfast_die "could not inspect writer excluded from restore set: $service"
    if [[ -n "$uncaptured_output" ]]; then mapfile -t uncaptured_ids <<<"$uncaptured_output"; fi
    for container_id in "${uncaptured_ids[@]}"; do
      uncaptured_state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$uncaptured_state" != "running" && "$uncaptured_state" != "restarting" && "$uncaptured_state" != "paused" ]] || \
        holdfast_die "writer excluded from the restore set became active: $service"
      "$docker_bin" rm -f "$container_id" >/dev/null
    done
  done
  uncaptured_writers_inactive="passed"
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    verify_live_quarantine_absence
    quarantined_writers_inactive="passed"
  fi
else
  failure_stage="resume_exact_runtime"
  verify_live_disposition applied
  "${compose[@]}" config --quiet
  revalidate_v3_successor_authority "$state_file"
  if [[ "$successor_recovery_v3" == "true" ]]; then
    validate_v3_active_recovery_arm_authority
    validate_v3_recovery_mutation_authority
    verify_live_disposition applied
    "${compose[@]}" config --quiet
  fi
  "${compose[@]}" up -d --no-build --wait --wait-timeout 300 \
    access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
  run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json"
  verify_live_disposition applied
fi

failure_stage="post_recovery_closed_bracket"
verify_closed_bracket

revalidate_v3_successor_authority "$state_file"
if [[ "$successor_recovery_v3" == "true" ]]; then
  validate_v3_active_recovery_arm_authority
  validate_v3_recovery_mutation_authority
  if [[ "$mode" == "restore" ]]; then
    verify_live_disposition preimage
    verify_restore_writer_runtime_disposition
  else
    verify_live_disposition applied
    "${compose[@]}" config --quiet
    run_runtime_verify --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
  fi
  revalidate_v3_successor_authority "$state_file"
  validate_v3_active_recovery_arm_authority
  validate_v3_recovery_mutation_authority
  if [[ "$mode" == "restore" ]]; then
    verify_live_disposition preimage
  else
    verify_live_disposition applied
  fi
fi
recovery_receipt="$state_dir/APPLY-RECOVERY-COMPLETE-${attempt_id}.receipt"
recovery_receipt_tmp="$state_dir/.APPLY-RECOVERY-COMPLETE.$$"
if [[ -f "$recovery_receipt" && ! -L "$recovery_receipt" ]]; then
  require_root_file "$recovery_receipt"
  validate_recovery_route_contract \
    "$recovery_receipt" "existing recovery completion receipt"
  [[ "$(holdfast_receipt_value "$recovery_receipt" attempt_id)" == "$attempt_id" ]] || \
    holdfast_die "existing completion receipt attempt differs"
  [[ "$(holdfast_receipt_value "$recovery_receipt" mode)" == "$mode" ]] || \
    holdfast_die "existing completion receipt mode differs"
  [[ "$(holdfast_receipt_value "$recovery_receipt" backup_dir)" == "$backup" ]] || \
    holdfast_die "existing completion receipt backup differs"
  [[ "$(holdfast_receipt_value "$recovery_receipt" control_sha256)" == "$control_sha" ]] || \
    holdfast_die "existing completion receipt CONTROL differs"
  [[ "$(holdfast_receipt_value "$recovery_receipt" original_estate_transaction_sha256)" == \
    "$transaction_sha" && \
    "$(holdfast_receipt_value "$recovery_receipt" applied_targets_sha256)" == \
      "$applied_targets_sha" ]] || holdfast_die "existing completion receipt rollback authority differs"
  [[ "$(holdfast_receipt_value "$recovery_receipt" pre_restored_retry)" == \
    "$pre_restored_retry" && \
    "$(holdfast_receipt_value "$recovery_receipt" pre_restored_source_attempt)" == \
      "$pre_restored_source_attempt" && \
    "$(holdfast_receipt_value "$recovery_receipt" runtime_restore_receipt_sha256)" == \
      "$runtime_restore_snapshot" && \
    "$(holdfast_receipt_value "$recovery_receipt" estate_restore_state_sha256)" == \
      "$estate_restore_state" && \
    "$(holdfast_receipt_value "$recovery_receipt" pre_restored_superseded_attempt)" == \
      "$pre_restored_superseded_attempt" && \
    "$(holdfast_receipt_value "$recovery_receipt" pre_restored_superseded_failure_receipt_sha256)" == \
      "$pre_restored_superseded_failure_sha" && \
    "$(holdfast_receipt_value "$recovery_receipt" pre_restored_superseded_state_sha256)" == \
      "$pre_restored_superseded_state_sha" && \
    "$(holdfast_receipt_value "$recovery_receipt" pre_restored_runtime_disposition)" == \
      "$pre_restored_runtime_disposition" ]] || holdfast_die "existing completion receipt pre-restored authority differs"
  completion_writer_reconciled=$(holdfast_receipt_value "$recovery_receipt" writer_set_reconciled 2>/dev/null || printf legacy-absent)
  completion_writer_source_attempt=$(holdfast_receipt_value "$recovery_receipt" writer_set_source_attempt 2>/dev/null || printf legacy-absent)
  completion_writer_source_failure=$(holdfast_receipt_value "$recovery_receipt" writer_set_source_failure_receipt_sha256 2>/dev/null || printf legacy-absent)
  completion_writer_source_state=$(holdfast_receipt_value "$recovery_receipt" writer_set_source_state_sha256 2>/dev/null || printf legacy-absent)
  completion_writer_source_manifest=$(holdfast_receipt_value "$recovery_receipt" writer_set_source_manifest_sha256 2>/dev/null || printf legacy-absent)
  completion_writer_preimage=$(holdfast_receipt_value "$recovery_receipt" writer_set_preimage_compose_sha256 2>/dev/null || printf legacy-absent)
  completion_writer_quarantined=$(holdfast_receipt_value "$recovery_receipt" writer_set_quarantined 2>/dev/null || printf none)
  [[ "$completion_writer_quarantined" == "$writer_set_quarantined" ]] || \
    holdfast_die "existing completion receipt writer quarantine authority differs"
  if [[ "$writer_set_quarantined" == "access-governance,newapi" ]]; then
    [[ "$(holdfast_receipt_value "$recovery_receipt" quarantined_writers_inactive)" == \
      "$quarantined_writers_inactive" && "$quarantined_writers_inactive" == "passed" ]] || \
      holdfast_die "existing completion receipt quarantined-writer proof differs"
  fi
  if [[ "$completion_writer_reconciled" == "legacy-absent" && \
    "$completion_writer_source_attempt" == "legacy-absent" && \
    "$completion_writer_source_failure" == "legacy-absent" && \
    "$completion_writer_source_state" == "legacy-absent" && \
    "$completion_writer_source_manifest" == "legacy-absent" && \
    "$completion_writer_preimage" == "legacy-absent" ]]; then
    [[ "$writer_set_reconciled" == "false" && \
      "$writer_set_source_attempt" == "none" && \
      "$writer_set_source_failure_sha" == "none" && \
      "$writer_set_source_state_sha" == "none" && \
      "$writer_set_source_manifest_sha" == "none" && \
      "$writer_set_preimage_compose_sha" == "none" ]] || \
      holdfast_die "legacy completion receipt cannot claim writer reconciliation"
  else
    [[ "$completion_writer_reconciled" == "$writer_set_reconciled" && \
      "$completion_writer_source_attempt" == "$writer_set_source_attempt" && \
      "$completion_writer_source_failure" == "$writer_set_source_failure_sha" && \
      "$completion_writer_source_state" == "$writer_set_source_state_sha" && \
      "$completion_writer_source_manifest" == "$writer_set_source_manifest_sha" && \
      "$completion_writer_preimage" == "$writer_set_preimage_compose_sha" ]] || \
      holdfast_die "existing completion receipt writer reconciliation authority differs"
  fi
else
  [[ ! -e "$recovery_receipt" && ! -L "$recovery_receipt" && ! -e "$recovery_receipt_tmp" && ! -L "$recovery_receipt_tmp" ]] || \
    holdfast_die "unsafe recovery completion receipt path"
  {
    printf 'schema_version=%s\n' "$(recovery_receipt_schema_version)"
    printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'attempt_id=%s\n' "$attempt_id"
    printf 'mode=%s\n' "$mode"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'original_estate_transaction_state=%s\n' "$transaction_state"
    printf 'original_estate_transaction_sha256=%s\n' "$transaction_sha"
    printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
    printf 'legacy_empty_strad=%s\n' "$legacy_empty_strad"
    printf 'recovery_armed_receipt_sha256=%s\n' "$recovery_armed_sha"
    printf 'release_evidence_sha256=%s\n' "$release_evidence_sha"
    printf 'dry_run_receipt_sha256=%s\n' "$dry_receipt_sha"
    printf 'runtime_restore_receipt_sha256=%s\n' "$runtime_restore_snapshot"
    printf 'estate_restore_state_sha256=%s\n' "$estate_restore_state"
    printf 'pre_restored_retry=%s\n' "$pre_restored_retry"
    printf 'pre_restored_source_attempt=%s\n' "$pre_restored_source_attempt"
    printf 'pre_restored_superseded_attempt=%s\n' "$pre_restored_superseded_attempt"
    printf 'pre_restored_superseded_failure_receipt_sha256=%s\n' "$pre_restored_superseded_failure_sha"
    printf 'pre_restored_superseded_state_sha256=%s\n' "$pre_restored_superseded_state_sha"
    printf 'pre_restored_runtime_disposition=%s\n' "$pre_restored_runtime_disposition"
    printf 'restore_running_writers_manifest=%s\n' "$([[ "$mode" == "restore" ]] && basename -- "$restore_writers_manifest" || printf not-applicable)"
    printf 'restore_running_writers_sha256=%s\n' "$restore_writers_sha"
    printf 'writer_set_reconciled=%s\n' "$writer_set_reconciled"
    printf 'writer_set_source_attempt=%s\n' "$writer_set_source_attempt"
    printf 'writer_set_source_failure_receipt_sha256=%s\n' "$writer_set_source_failure_sha"
    printf 'writer_set_source_state_sha256=%s\n' "$writer_set_source_state_sha"
    printf 'writer_set_source_manifest_sha256=%s\n' "$writer_set_source_manifest_sha"
    printf 'writer_set_preimage_compose_sha256=%s\n' "$writer_set_preimage_compose_sha"
    printf 'writer_set_quarantined=%s\n' "$writer_set_quarantined"
    printf 'writers_reactivated=%s\n' "$writers_reactivated"
    printf 'uncaptured_writers_inactive=%s\n' "$uncaptured_writers_inactive"
    printf 'quarantined_writers_inactive=%s\n' "$quarantined_writers_inactive"
    printf 'runtime_verified=%s\n' "$([[ "$mode" == "resume" ]] && printf passed || printf not-applicable)"
    printf 'live_estate_disposition=%s\n' "$([[ "$mode" == "resume" ]] && printf applied || printf preimage)"
    append_recovery_route_contract_fields
    printf 'apply_receipt_created=false\n'
    append_successor_lineage_receipt_fields
  } >"$recovery_receipt_tmp"
  chmod 0600 "$recovery_receipt_tmp"
  mv -fT -- "$recovery_receipt_tmp" "$recovery_receipt"
  sync -f "$recovery_receipt"
  validate_recovery_route_contract \
    "$recovery_receipt" "new recovery completion receipt"
fi
validate_successor_lineage_receipt "$recovery_receipt"
recovery_receipt_sha=$(holdfast_sha256 "$recovery_receipt")

completed_state="$state_dir/APPLY-RECOVERY-COMPLETE-${attempt_id}.json"
completed_state_tmp="$state_dir/.APPLY-RECOVERY-COMPLETE-STATE.$$"
[[ ! -e "$completed_state" && ! -L "$completed_state" && ! -e "$completed_state_tmp" && ! -L "$completed_state_tmp" ]] || \
  holdfast_die "recovery completion state path already exists"
jq \
  --arg state "$([[ "$mode" == "resume" ]] && printf apply_recovered_resumed || printf apply_recovered_restored)" \
  --arg receipt "$(basename -- "$recovery_receipt")" --arg receipt_sha "$recovery_receipt_sha" \
  '.state=$state | .recovery_receipt=$receipt | .recovery_receipt_sha256=$receipt_sha' \
  "$state_file" >"$completed_state_tmp"
chmod 0600 "$completed_state_tmp"
mv -fT -- "$completed_state_tmp" "$completed_state"
sync -f "$completed_state"
completion_current_sha=$(holdfast_sha256 "$state_file")
completion_state_sha=$(holdfast_sha256 "$completed_state")

if [[ "$mode" == "resume" ]]; then
  jq \
    --arg receipt "$(basename -- "$recovery_receipt")" --arg receipt_sha "$recovery_receipt_sha" \
    --arg transaction "$transaction_sha" --arg applied_targets "$applied_targets_sha" \
    '.state="applied_ingress_closed" | .recovery_receipt=$receipt | .recovery_receipt_sha256=$receipt_sha | .services_activated=true | .runtime_verified=true | .transaction_sha256=$transaction | .applied_targets_sha256=$applied_targets' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  state_tmp_sha=$(holdfast_sha256 "$state_tmp")
  revalidate_v3_successor_authority "$state_file"
  validate_v3_recovery_completion_fence "$recovery_receipt" "$completed_state" \
    "$completion_current_sha" "$recovery_receipt_sha" "$completion_state_sha"
  if [[ "$successor_recovery_v3" == "true" ]]; then
    [[ "$(holdfast_sha256 "$state_tmp")" == "$state_tmp_sha" ]] || \
      holdfast_die "schema-v3 resumed CURRENT candidate changed before commit"
  fi
  mv -fT -- "$state_tmp" "$state_file"
  sync -f "$state_file"
else
  # The immutable completion state replaces the active pointer: the release is
  # no longer applied and no later open ceremony may treat it as active.
  armed_state_archive="$state_dir/APPLY-RECOVERY-ARMED-STATE-${attempt_id}.json"
  [[ ! -e "$armed_state_archive" && ! -L "$armed_state_archive" ]] || holdfast_die "recovery armed state archive already exists"
  verify_live_quarantine_absence
  if [[ "$successor_recovery" == "true" ]]; then
    revalidate_v3_successor_authority "$state_file"
    validate_v3_recovery_completion_fence "$recovery_receipt" "$completed_state" \
      "$completion_current_sha" "$recovery_receipt_sha" "$completion_state_sha"
    if [[ "$successor_recovery_v3" == "true" ]]; then
      [[ ! -e "$armed_state_archive" && ! -L "$armed_state_archive" ]] || \
        holdfast_die "schema-v3 recovery arm archive appeared before finalization"
    fi
    restore_immediate_predecessor_current "$armed_state_archive"
  else
    mv -- "$state_file" "$armed_state_archive"
    sync -f "$state_dir"
  fi
fi

recovery_complete="true"
trap - EXIT INT TERM
echo "apply recovery completed in $mode mode; ingress remains closed"
echo "recovery receipt: $recovery_receipt"
