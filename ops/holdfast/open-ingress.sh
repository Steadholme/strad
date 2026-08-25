#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --phase prepare|finalize --estate-root PATH --dry-run-dir PATH --release-env FILE --authority-evidence FILE --authority-signature FILE --authority-public-key FILE [--edge-evidence FILE --edge-signature FILE] [--state-dir PATH]" >&2
  exit 2
}

execute="false"
phase=""
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
    --phase) [[ $# -ge 2 ]] || usage; phase=$2; shift 2 ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --dry-run-dir) [[ $# -ge 2 ]] || usage; dry_run_dir=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --authority-evidence) [[ $# -ge 2 ]] || usage; authority_evidence=$2; shift 2 ;;
    --authority-signature) [[ $# -ge 2 ]] || usage; authority_signature=$2; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; shift 2 ;;
    --edge-evidence) [[ $# -ge 2 ]] || usage; edge_evidence=$2; shift 2 ;;
    --edge-signature) [[ $# -ge 2 ]] || usage; edge_signature=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && ( "$phase" == "prepare" || "$phase" == "finalize" ) ]] || usage
[[ -n "$estate_root" && -n "$dry_run_dir" && -n "$release_env" && -n "$authority_evidence" && -n "$authority_signature" && -n "$authority_public_key" ]] || usage
[[ $EUID -eq 0 ]] || { echo "opening ingress requires root" >&2; exit 1; }
[[ -n "${ROUTES_DATABASE_URL:-}" ]] || { echo "ROUTES_DATABASE_URL must be supplied by the secret authority" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
for path in "$estate_root" "$dry_run_dir" "$release_env" "$authority_evidence" "$authority_signature" "$authority_public_key" "$state_dir"; do
  holdfast_require_absolute "$path"
done
holdfast_acquire_lock

stage="$dry_run_dir/stage"
release_evidence="$stage/RELEASE-EVIDENCE.json"
dry_receipt="$dry_run_dir/DRY-RUN.receipt"
state_file="$state_dir/CURRENT.json"
prepare_receipt="$state_dir/OPEN-PREPARE.receipt"
open_receipt="$state_dir/OPEN.receipt"
[[ -f "$state_file" && ! -L "$state_file" ]] || holdfast_die "active apply state is absent"

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
    echo "holdfast: route database does not prove rikune-root/analyze root absence" >&2
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

verify_closed_bracket() {
  verify_database_absent
  "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/
  verify_database_absent
}

verify_open_bracket() {
  verify_database_open
  "$script_dir/public-origin-verify.sh" --mode open --url https://analyze.w33d.xyz/
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
    printf 'public_host=analyze.w33d.xyz\n'
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
    printf 'public_host=analyze.w33d.xyz\n'
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

recover_armed_open() {
  local armed_prepare_sha armed_edge_sha armed_route_down
  echo "armed open state detected; closing the route before reading armed metadata" >&2
  force_route_absent
  verify_closed_bracket
  armed_prepare_sha=$(jq -er '.open_armed_prepare_receipt_sha256' "$state_file")
  armed_edge_sha=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  armed_route_down=$(jq -er '.open_armed_route_down_sha256' "$state_file")
  [[ "$armed_prepare_sha" =~ ^[0-9a-f]{64}$ && "$armed_edge_sha" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "armed open state contains invalid evidence hashes"
  [[ -f "$prepare_receipt" && ! -L "$prepare_receipt" ]] || \
    holdfast_die "armed open recovery cannot find the prepare receipt"
  [[ "$armed_prepare_sha" == "$(holdfast_sha256 "$prepare_receipt")" ]] || \
    holdfast_die "armed open prepare receipt was replaced"
  [[ "$(jq -er '.open_prepare_receipt_sha256' "$state_file")" == "$armed_prepare_sha" ]] || \
    holdfast_die "armed open state points to another prepare receipt"
  [[ "$(jq -er '.open_armed_public_host' "$state_file")" == "analyze.w33d.xyz" ]] || \
    holdfast_die "armed open state targets another host"
  [[ "$(jq -er '.open_armed_edge_owner' "$state_file")" == "existing-w33d-sluice" ]] || \
    holdfast_die "armed open state targets another edge"
  [[ "$armed_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
    holdfast_die "armed route-down SQL differs from the current recovery asset"

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

python3 "$script_dir/validate_release_evidence.py" --evidence "$release_evidence"
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
  chmod 0600 "$receipt_tmp"
  mv -fT -- "$receipt_tmp" "$prepare_receipt"
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg prepare_sha "$(holdfast_sha256 "$prepare_receipt")" \
    '.state="edge_prepared_route_closed" | .open_prepare_receipt_sha256=$prepare_sha' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  echo "runtime/authority prepared while analyze.w33d.xyz remains dual-stack 404; collect and sign v2 pre-open edge evidence"
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
  if "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/; then
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
    | .open_armed_public_host="analyze.w33d.xyz"
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
  printf 'public_host=analyze.w33d.xyz\n'
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
      .open_armed_edge_owner
    )
' "$state_file" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_file"
route_mutation_started="false"
trap - EXIT INT TERM
echo "rikune-root public ingress finalized on analyze.w33d.xyz without Pages, Cloudflare, or DNS mutation"
