#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --mode restore|resume --backup-dir PATH [--estate-root PATH] [--state-dir PATH] [--legacy-empty-strad] [--quarantine-access-chain]" >&2
  exit 2
}

execute="false"
mode=""
backup=""
estate_root=""
state_dir="/var/lib/holdfast-rikune"
legacy_empty_strad="false"
quarantine_access_chain="false"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --mode) [[ $# -ge 2 ]] || usage; mode=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    --legacy-empty-strad) legacy_empty_strad="true"; shift ;;
    --quarantine-access-chain) quarantine_access_chain="true"; shift ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && ( "$mode" == "restore" || "$mode" == "resume" ) && -n "$backup" ]] || usage
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

psql_bin=$(test_override HOLDFAST_PSQL_BIN psql)
public_verify=$(test_override HOLDFAST_PUBLIC_VERIFY_BIN "$script_dir/public-origin-verify.sh")
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

if [[ -e "$state_dir" || -L "$state_dir" ]]; then
  [[ -d "$state_dir" && ! -L "$state_dir" && "$(readlink -f -- "$state_dir")" == "$state_dir" ]] || \
    holdfast_die "state directory must be canonical and non-symlink"
  [[ "$(stat -c '%u' -- "$state_dir")" == "0" ]] || holdfast_die "state directory must be root-owned"
else
  mkdir -p -- "$state_dir"
fi
chmod 0700 -- "$state_dir"
require_canonical_root_dir "$state_dir"
require_canonical_root_dir "$backup"
[[ -z "$(find "$backup" -maxdepth 0 -perm /077 -print -quit)" ]] || \
  holdfast_die "backup directory must not be group/world accessible"
[[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || holdfast_die "backup contains a symlink"
[[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || holdfast_die "backup contains a non-root-owned entry"
[[ -z "$(find "$backup" -xdev ! -type d ! -type f -print -quit)" ]] || holdfast_die "backup contains a special file"

state_file="$state_dir/CURRENT.json"
runtime_caller_receipt="$backup/RUNTIME-BACKUP-CALLER-ARMED.receipt"
runtime_caller_sha=""
runtime_recovery_id=""
runtime_recovery_receipt=""
runtime_recovery_archive=""
runtime_dry_run_dir=""
runtime_prior_services=()

validate_runtime_caller_authority() {
  local pointer=$1 expected key value caller_estate caller_backup caller_runtime
  local release_sha evidence_sha dry_sha targets_sha preimages_sha absent_sha render_sha
  require_root_file "$pointer"
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
  for service in strad rikune-analyzer; do
    if ! runtime_service_was_running "$service"; then
      excluded+=("$service")
      stop_services+=("$service")
    fi
  done
  "${compose[@]}" stop -t 120 "${stop_services[@]}" >/dev/null
  if ((${#runtime_prior_services[@]})); then
    "${compose[@]}" start "${runtime_prior_services[@]}" >/dev/null
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
  local original_state_sha cleanup_sha arm_state expected key value
  require_root_file "$runtime_recovery_receipt"
  require_root_file "$runtime_recovery_archive"
  require_root_file "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt"
  original_state_sha=$(holdfast_sha256 "$runtime_recovery_archive")
  cleanup_sha=$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")
  arm_state=$(holdfast_receipt_value "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt" runtime_stop_authority)
  [[ "$arm_state" == "present" || "$arm_state" == "not-created" ]] || \
    holdfast_die "runtime backup recovery cleanup has an invalid stop authority"
  for expected in \
    "schema_version=2" "recovery_id=$runtime_recovery_id" \
    "estate_root=$estate_root" "backup_dir=$backup" \
    "runtime_stop_authority=$arm_state" \
    "runtime_backup_caller_armed_sha256=$runtime_caller_sha" \
    "original_state_sha256=$original_state_sha" \
    "runtime_backup_caller_cleanup_sha256=$cleanup_sha" \
    "active_state_archive=$(basename -- "$runtime_recovery_archive")" \
    "route_state=absent" "db_public_db_bracket=absent-404-absent" \
    "old_apply_resumed=false" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup recovery completion differs: $key"
  done
}

complete_runtime_caller_recovery() {
  local arm_state=$1 original_state_sha cleanup_sha temporary expected key value
  original_state_sha=$(holdfast_sha256 "$state_file")
  cleanup_sha=$(holdfast_sha256 "$backup/RUNTIME-BACKUP-CALLER-CLEANUP.receipt")
  if [[ -e "$runtime_recovery_receipt" || -L "$runtime_recovery_receipt" ]]; then
    require_root_file "$runtime_recovery_receipt"
    for expected in \
      "schema_version=2" "recovery_id=$runtime_recovery_id" \
      "estate_root=$estate_root" "backup_dir=$backup" \
      "runtime_stop_authority=$arm_state" \
      "runtime_backup_caller_armed_sha256=$runtime_caller_sha" \
      "original_state_sha256=$original_state_sha" \
      "runtime_backup_caller_cleanup_sha256=$cleanup_sha" \
      "active_state_archive=$(basename -- "$runtime_recovery_archive")" \
      "route_state=absent" "db_public_db_bracket=absent-404-absent" \
      "old_apply_resumed=false" "ingress_opened=false"; do
      key=${expected%%=*}
      value=${expected#*=}
      [[ "$(holdfast_receipt_value "$runtime_recovery_receipt" "$key")" == "$value" ]] || \
        holdfast_die "runtime backup pending recovery completion differs: $key"
    done
  else
    temporary="$state_dir/.RUNTIME-BACKUP-RECOVERY-COMPLETE.$$"
    {
      printf 'schema_version=2\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'recovery_id=%s\n' "$runtime_recovery_id"
      printf 'estate_root=%s\n' "$estate_root"
      printf 'backup_dir=%s\n' "$backup"
      printf 'runtime_stop_authority=%s\n' "$arm_state"
      printf 'runtime_backup_caller_armed_sha256=%s\n' "$runtime_caller_sha"
      printf 'original_state_sha256=%s\n' "$original_state_sha"
      printf 'runtime_backup_caller_cleanup_sha256=%s\n' "$cleanup_sha"
      printf 'active_state_archive=%s\n' "$(basename -- "$runtime_recovery_archive")"
      printf 'route_state=absent\n'
      printf 'db_public_db_bracket=absent-404-absent\n'
      printf 'old_apply_resumed=false\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_recovery_file "$temporary" "$runtime_recovery_receipt"
  fi
  if [[ -e "$runtime_recovery_archive" || -L "$runtime_recovery_archive" ]]; then
    holdfast_die "runtime backup recovery archive exists while CURRENT is still active"
  fi
  mv -T -- "$state_file" "$runtime_recovery_archive"
  sync -f "$runtime_recovery_archive"
  sync -f "$state_dir"
  validate_runtime_recovery_completion
}

# runtime-backup may be killed after its caller has durably armed CURRENT but
# before apply can persist a full CONTROL-bound backup.  Recover that boundary
# before requiring the normal apply artifacts below.  This branch restores only
# the exact pre-backup product subset; it never restores DB, volumes, or estate.
if [[ -f "$runtime_caller_receipt" && ! -L "$runtime_caller_receipt" ]]; then
  runtime_caller_sha=$(holdfast_sha256 "$runtime_caller_receipt")
  runtime_recovery_id=${runtime_caller_sha:0:24}
  runtime_recovery_receipt="$state_dir/RUNTIME-BACKUP-RECOVERY-COMPLETE-${runtime_recovery_id}.receipt"
  runtime_recovery_archive="$state_dir/RUNTIME-BACKUP-ABORTED-${runtime_recovery_id}.json"
  if [[ ! -e "$state_file" && ! -L "$state_file" && \
    ( -e "$runtime_recovery_receipt" || -L "$runtime_recovery_receipt" ) ]]; then
    [[ "$mode" == "restore" && "$legacy_empty_strad" == "false" ]] || \
      holdfast_die "runtime backup recovery completion requires non-legacy restore mode"
    validate_runtime_caller_authority "$runtime_recovery_archive"
    validate_runtime_recovery_completion
    verify_closed_bracket
    echo "previously completed runtime backup recovery verified; rerun apply with a fresh ceremony"
    exit 0
  fi
fi
if [[ -e "$state_file" || -L "$state_file" ]]; then
  require_root_file "$state_file"
  current_state=$(jq -er '.state' "$state_file")
  if [[ "$current_state" == "runtime_backup_armed" ]]; then
    [[ "$mode" == "restore" && "$legacy_empty_strad" == "false" ]] || \
      holdfast_die "runtime backup recovery requires non-legacy restore mode"
    validate_runtime_caller_authority "$state_file"
    verify_closed_bracket
    runtime_arm_state=not-created
    if [[ -e "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" || \
      -L "$backup/runtime/RUNTIME-BACKUP-ARMED.receipt" ]]; then
      runtime_arm_state=present
      validate_runtime_stop_authority
      validate_runtime_backup_success_authority
      validate_runtime_compensation_authority
      restore_runtime_prior_subset
    else
      [[ ! -e "$backup/runtime/BACKUP.receipt" && ! -L "$backup/runtime/BACKUP.receipt" ]] || \
        holdfast_die "runtime backup succeeded without durable stop authority"
    fi
    verify_closed_bracket
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
if [[ "$release_validator" == "$script_dir/validate_release_evidence.py" ]]; then
  python3 "$release_validator" --evidence "$backup/RELEASE-EVIDENCE.json"
else
  "$release_validator" --evidence "$backup/RELEASE-EVIDENCE.json"
fi

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
completed_state_match=""
shopt -s nullglob
for completed_state in "$state_dir"/APPLY-RECOVERY-COMPLETE-*.json; do
  require_root_file "$completed_state"
  if [[ "$(jq -er --arg backup "$backup" '.backup_dir == $backup and (.state == "apply_recovered_restored" or .state == "apply_recovered_resumed")' "$completed_state" 2>/dev/null || true)" == "true" ]]; then
    [[ -z "$completed_state_match" ]] || holdfast_die "multiple completion states exist for this backup"
    completed_state_match=$completed_state
  fi
done
shopt -u nullglob

prior_state="legacy_orphan_applied"
armed_pointer_missing="false"
if [[ -e "$state_file" || -L "$state_file" ]]; then
  require_root_file "$state_file"
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

if [[ "$quarantine_access_chain" == "true" && \
  "$prior_state" != "restore_failed" && "$prior_state" != "apply_recovery_armed" && \
  -z "$completed_state_match" ]]; then
  holdfast_die "access-chain quarantine requires a restore-failed retry"
fi

runtime_restore=$(test_override HOLDFAST_RUNTIME_RESTORE_BIN "$script_dir/runtime-restore.sh")
runtime_verify=$(test_override HOLDFAST_RUNTIME_VERIFY_BIN "$script_dir/runtime-verify.sh")
recovery_compose_root="$estate_root"

validate_recovery_stage_authority() {
  local armed_dry caller_dry recovery_stage resolved_config expected key value
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

  verify_live_disposition applied
  if [[ "$final_services_activated" == "true" ]]; then
    "$runtime_verify" --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
  fi
  verify_closed_bracket
  verify_live_disposition applied

  # If apply crashed before installing its finalization state, establish that
  # durable boundary before promoting the pending receipt.
  if [[ "$prior_state" != "apply_finalizing_ingress_closed" ]]; then
    finalizing_tmp="$state_dir/.CURRENT.json.$$"
    jq -n \
      --arg estate "$estate_root" --arg backup "$backup" \
      --arg pending_sha "$candidate_apply_sha" --arg armed_sha "$armed_receipt_sha" \
      --arg control_sha "$control_sha" --arg release_sha "$release_evidence_sha" \
      --arg transaction_sha "$transaction_sha" \
      --arg targets_sha "$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")" \
      --arg closed_at "$(holdfast_receipt_value "$candidate_apply_receipt" closed_verified_at)" \
      --argjson activated "$final_services_activated" \
      '{schema_version:2,state:"apply_finalizing_ingress_closed",estate_root:$estate,backup_dir:$backup,pending_apply_receipt:"APPLY-PENDING.receipt",pending_apply_receipt_sha256:$pending_sha,apply_armed_receipt_sha256:$armed_sha,control_sha256:$control_sha,release_evidence_sha256:$release_sha,transaction_sha256:$transaction_sha,applied_targets_sha256:$targets_sha,closed_verified_at:$closed_at,route_database_state:"absent",public_ipv4_ipv6_closed_status:404,services_activated:$activated,runtime_verified:$activated,ingress_opened:false}' \
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
  [[ "$(holdfast_receipt_value "$completed_receipt" schema_version)" == "2" ]] || \
    holdfast_die "completed recovery receipt schema differs"
  [[ "$(holdfast_receipt_value "$completed_receipt" estate_root)" == "$estate_root" ]] || \
    holdfast_die "completed recovery receipt points to another estate"
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
  if [[ "$mode" == "restore" ]]; then
    verify_live_disposition preimage
    verify_live_quarantine_absence
    if [[ -f "$state_file" && ! -L "$state_file" ]]; then
      finalized_attempt=$(holdfast_receipt_value "$completed_receipt" attempt_id)
      [[ "$finalized_attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
        holdfast_die "completed recovery attempt identity is unsafe"
      finalized_archive="$state_dir/APPLY-RECOVERY-FINALIZED-STATE-${finalized_attempt}.json"
      [[ ! -e "$finalized_archive" && ! -L "$finalized_archive" ]] || \
        holdfast_die "completed recovery state archive already exists"
      mv -- "$state_file" "$finalized_archive"
      sync -f "$state_dir"
    else
      [[ ! -e "$state_file" && ! -L "$state_file" ]] || holdfast_die "unsafe active state path"
    fi
  else
    verify_live_disposition applied
    "$runtime_verify" --estate-root "$estate_root" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json"
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
  verify_closed_bracket
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
    mv -fT -- "$restore_writers_tmp" "$restore_writers_manifest"
    sync -f "$restore_writers_manifest"
    restore_writers_sha=$(holdfast_sha256 "$restore_writers_manifest")
  fi
  recovery_armed_receipt="$state_dir/APPLY-RECOVERY-ARMED-${attempt_id}.receipt"
  recovery_armed_tmp="$state_dir/.APPLY-RECOVERY-ARMED.$$"
  [[ ! -e "$recovery_armed_receipt" && ! -L "$recovery_armed_receipt" && ! -e "$recovery_armed_tmp" && ! -L "$recovery_armed_tmp" ]] || \
    holdfast_die "recovery arm receipt path already exists"
  {
    printf 'schema_version=2\n'
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
    printf 'route_state=absent\n'
    printf 'public_host=analyze.w33d.xyz\n'
    printf 'db_public_db_bracket=absent-404-absent\n'
  } >"$recovery_armed_tmp"
  chmod 0600 "$recovery_armed_tmp"
  mv -fT -- "$recovery_armed_tmp" "$recovery_armed_receipt"
  sync -f "$recovery_armed_receipt"
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
  mv -fT -- "$state_tmp" "$state_file"
  sync -f "$state_file"
fi

if [[ "$prior_state" == "apply_recovery_armed" && "$mode" == "restore" && \
  "$transaction_is_preimage" != "true" && "$legacy_orphan" == "false" ]]; then
  validate_recovery_stage_authority
fi

recovery_complete="false"
failure_stage="recovery_armed"
record_recovery_failure() {
  local status=$1
  local failed_at failed_receipt failed_tmp failed_state failed_state_tmp route_database_state
  trap - EXIT INT TERM
  set +e
  route_database_state="unverified"
  if verify_database_absent; then route_database_state="absent"; fi
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
    python3 "$script_dir/estate_transaction.py" restore \
      --estate-root "$estate_root" --backup-dir "$recovery_estate"
    require_root_file "$recovery_estate/TRANSACTION.json"
    [[ "$(jq -er '.state' "$recovery_estate/TRANSACTION.json")" == "restored" ]] || \
      holdfast_die "mixed estate restore did not record restored state"
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
  "${compose[@]}" up -d --no-build --wait --wait-timeout 300 \
    access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
  "$runtime_verify" --estate-root "$estate_root" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json"
  verify_live_disposition applied
fi

failure_stage="post_recovery_closed_bracket"
verify_closed_bracket

recovery_receipt="$state_dir/APPLY-RECOVERY-COMPLETE-${attempt_id}.receipt"
recovery_receipt_tmp="$state_dir/.APPLY-RECOVERY-COMPLETE.$$"
if [[ -f "$recovery_receipt" && ! -L "$recovery_receipt" ]]; then
  require_root_file "$recovery_receipt"
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
    printf 'schema_version=2\n'
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
    printf 'route_state=absent\n'
    printf 'public_host=analyze.w33d.xyz\n'
    printf 'db_public_db_bracket=absent-404-absent\n'
    printf 'apply_receipt_created=false\n'
  } >"$recovery_receipt_tmp"
  chmod 0600 "$recovery_receipt_tmp"
  mv -fT -- "$recovery_receipt_tmp" "$recovery_receipt"
  sync -f "$recovery_receipt"
fi
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

if [[ "$mode" == "resume" ]]; then
  jq \
    --arg receipt "$(basename -- "$recovery_receipt")" --arg receipt_sha "$recovery_receipt_sha" \
    --arg transaction "$transaction_sha" --arg applied_targets "$applied_targets_sha" \
    '.state="applied_ingress_closed" | .recovery_receipt=$receipt | .recovery_receipt_sha256=$receipt_sha | .services_activated=true | .runtime_verified=true | .transaction_sha256=$transaction | .applied_targets_sha256=$applied_targets' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  sync -f "$state_file"
else
  # The immutable completion state replaces the active pointer: the release is
  # no longer applied and no later open ceremony may treat it as active.
  armed_state_archive="$state_dir/APPLY-RECOVERY-ARMED-STATE-${attempt_id}.json"
  [[ ! -e "$armed_state_archive" && ! -L "$armed_state_archive" ]] || holdfast_die "recovery armed state archive already exists"
  verify_live_quarantine_absence
  mv -- "$state_file" "$armed_state_archive"
  sync -f "$state_dir"
fi

recovery_complete="true"
trap - EXIT INT TERM
echo "apply recovery completed in $mode mode; ingress remains closed"
echo "recovery receipt: $recovery_receipt"
