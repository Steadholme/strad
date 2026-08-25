#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --phase close-route|execute --estate-root PATH --backup-dir PATH --open-evidence FILE --open-signature FILE --authority-public-key FILE [--revocation-evidence FILE --revocation-signature FILE --edge-rollback-evidence FILE --edge-rollback-signature FILE --open-edge-evidence FILE] [--state-dir PATH] [--activate-services]" >&2
  exit 2
}

execute="false"
phase=""
activate="false"
estate_root=""
backup=""
open_evidence=""
open_signature=""
authority_public_key=""
revocation_evidence=""
revocation_signature=""
edge_rollback_evidence=""
edge_rollback_signature=""
open_edge_evidence=""
state_dir="/var/lib/holdfast-rikune"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --phase) [[ $# -ge 2 ]] || usage; phase=$2; shift 2 ;;
    --activate-services) activate="true"; shift ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    --open-evidence) [[ $# -ge 2 ]] || usage; open_evidence=$2; shift 2 ;;
    --open-signature) [[ $# -ge 2 ]] || usage; open_signature=$2; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; shift 2 ;;
    --revocation-evidence) [[ $# -ge 2 ]] || usage; revocation_evidence=$2; shift 2 ;;
    --revocation-signature) [[ $# -ge 2 ]] || usage; revocation_signature=$2; shift 2 ;;
    --edge-rollback-evidence) [[ $# -ge 2 ]] || usage; edge_rollback_evidence=$2; shift 2 ;;
    --edge-rollback-signature) [[ $# -ge 2 ]] || usage; edge_rollback_signature=$2; shift 2 ;;
    --open-edge-evidence) [[ $# -ge 2 ]] || usage; open_edge_evidence=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && ( "$phase" == "close-route" || "$phase" == "execute" ) ]] || usage
[[ -n "$estate_root" && -n "$backup" && -n "$open_evidence" && -n "$open_signature" && -n "$authority_public_key" ]] || usage
if [[ "$phase" == "execute" ]]; then
  [[ -n "$revocation_evidence" && -n "$revocation_signature" ]] || usage
fi
[[ $EUID -eq 0 ]] || { echo "rollback requires root" >&2; exit 1; }
[[ -n "${ROUTES_DATABASE_URL:-}" ]] || { echo "ROUTES_DATABASE_URL is required" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
# shellcheck disable=SC1091
source "$script_dir/common.sh"
for path in "$estate_root" "$backup" "$open_evidence" "$open_signature" "$authority_public_key" "$state_dir"; do
  holdfast_require_absolute "$path"
done
holdfast_acquire_lock

test_override() {
  local variable=$1 fallback=$2
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
  if [[ "$tool" == "$default" ]]; then
    python3 "$tool" "$@"
  else
    "$tool" "$@"
  fi
}

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

commit_atomic_file() {
  local temporary=$1 target=$2 parent
  parent=$(dirname -- "$target")
  [[ -f "$temporary" && ! -L "$temporary" ]] || holdfast_die "atomic source is unsafe: $temporary"
  chmod 0600 -- "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -f "$target"
  sync -f "$parent"
}

atomic_copy_authority() {
  local source=$1 target=$2 temporary
  require_root_file "$source"
  [[ ! -e "$target" && ! -L "$target" ]] || holdfast_die "frozen rollback authority already exists: $target"
  temporary="$state_dir/.frozen-$(basename -- "$target").$$"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || holdfast_die "frozen rollback temporary path exists"
  install -o 0 -g 0 -m 0600 -- "$source" "$temporary"
  commit_atomic_file "$temporary" "$target"
  [[ "$(holdfast_sha256 "$source")" == "$(holdfast_sha256 "$target")" ]] || \
    holdfast_die "frozen rollback authority differs from its source"
}

load_frozen_rollback_authorities() {
  local attempt armed_name armed_receipt armed_sha expected key value file_name
  attempt=$(jq -er '.rollback_attempt_id' "$state_file")
  [[ "$attempt" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || \
    holdfast_die "rollback frozen-authority attempt identity is unsafe"
  armed_name=$(jq -er '.rollback_armed_receipt' "$state_file")
  [[ "$armed_name" == "ROLLBACK-EXECUTE-ARMED-${attempt}.receipt" ]] || \
    holdfast_die "rollback state points to another frozen authority"
  armed_receipt="$state_dir/$armed_name"
  require_root_file "$armed_receipt"
  armed_sha=$(holdfast_sha256 "$armed_receipt")
  [[ "$(jq -er '.rollback_armed_receipt_sha256' "$state_file")" == "$armed_sha" ]] || \
    holdfast_die "rollback frozen authority receipt was replaced"

  frozen_open_evidence_name="ROLLBACK-OPEN-EVIDENCE-${attempt}.json"
  frozen_open_signature_name="ROLLBACK-OPEN-SIGNATURE-${attempt}.sig"
  frozen_public_key_name="ROLLBACK-AUTHORITY-PUBLIC-KEY-${attempt}.pub"
  frozen_revocation_evidence_name="ROLLBACK-REVOCATION-EVIDENCE-${attempt}.json"
  frozen_revocation_signature_name="ROLLBACK-REVOCATION-SIGNATURE-${attempt}.sig"
  frozen_edge_evidence_name="none"
  frozen_edge_signature_name="none"
  frozen_open_edge_name="none"
  if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
    frozen_edge_evidence_name="ROLLBACK-EDGE-EVIDENCE-${attempt}.json"
    frozen_edge_signature_name="ROLLBACK-EDGE-SIGNATURE-${attempt}.sig"
    frozen_open_edge_name="ROLLBACK-OPEN-EDGE-EVIDENCE-${attempt}.json"
  fi
  for expected in \
    "open_evidence_file=$frozen_open_evidence_name" \
    "open_signature_file=$frozen_open_signature_name" \
    "authority_public_key_file=$frozen_public_key_name" \
    "revocation_evidence_file=$frozen_revocation_evidence_name" \
    "revocation_signature_file=$frozen_revocation_signature_name" \
    "edge_rollback_evidence_file=$frozen_edge_evidence_name" \
    "edge_rollback_signature_file=$frozen_edge_signature_name" \
    "open_edge_evidence_file=$frozen_open_edge_name"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback frozen authority identity differs: $key"
  done
  for file_name in "$frozen_open_evidence_name" "$frozen_open_signature_name" \
    "$frozen_public_key_name" "$frozen_revocation_evidence_name" \
    "$frozen_revocation_signature_name" "$frozen_edge_evidence_name" \
    "$frozen_edge_signature_name" "$frozen_open_edge_name"; do
    [[ "$file_name" == "none" ]] && continue
    require_root_file "$state_dir/$file_name"
  done
  open_evidence="$state_dir/$frozen_open_evidence_name"
  open_signature="$state_dir/$frozen_open_signature_name"
  authority_public_key="$state_dir/$frozen_public_key_name"
  revocation_evidence="$state_dir/$frozen_revocation_evidence_name"
  revocation_signature="$state_dir/$frozen_revocation_signature_name"
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    edge_rollback_evidence="$state_dir/$frozen_edge_evidence_name"
    edge_rollback_signature="$state_dir/$frozen_edge_signature_name"
    open_edge_evidence="$state_dir/$frozen_open_edge_name"
  fi
  for expected in \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "open_signature_sha256=$(holdfast_sha256 "$open_signature")" \
    "authority_public_key_sha256=$(holdfast_sha256 "$authority_public_key")" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "revocation_signature_sha256=$(holdfast_sha256 "$revocation_signature")"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback frozen authority digest differs: $key"
  done
}

psql_bin=$(test_override HOLDFAST_PSQL_BIN psql)
public_verify=$(test_override HOLDFAST_PUBLIC_VERIFY_BIN "$script_dir/public-origin-verify.sh")
release_validator=$(test_override HOLDFAST_RELEASE_VALIDATOR_BIN "$script_dir/validate_release_evidence.py")
authority_tool=$(test_override HOLDFAST_AUTHORITY_EVIDENCE_BIN "$script_dir/authority_evidence.py")
edge_tool=$(test_override HOLDFAST_EDGE_EVIDENCE_BIN "$script_dir/edge_evidence.py")
docker_bin=$(test_override HOLDFAST_DOCKER_BIN docker)
runtime_restore=$(test_override HOLDFAST_RUNTIME_RESTORE_BIN "$script_dir/runtime-restore.sh")
estate_transaction=$(test_override HOLDFAST_ESTATE_TRANSACTION_BIN "$script_dir/estate_transaction.py")

state_file="$state_dir/CURRENT.json"
route_receipt="$state_dir/ROUTE-CLOSE.receipt"
route_preimage="$state_dir/ROUTE-CLOSE-PREIMAGE.jsonl"
require_canonical_root_dir "$state_dir"
require_canonical_root_dir "$backup"
require_canonical_root_dir "$estate_root"
require_root_file "$state_file"

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-rollback-db-absent "$psql_bin" "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: rollback does not prove rikune-root/analyze root absence" >&2
    return 1
  }
}

verify_closed_bracket() {
  verify_database_absent
  "$public_verify" --mode closed --url https://analyze.w33d.xyz/
  verify_database_absent
}

execute_frozen_route_down() {
  local temporary target status
  temporary="$state_dir/.ROUTE-CLOSE-DOWN.$$"
  if [[ -e "$route_preimage" || -L "$route_preimage" ]]; then
    [[ -f "$route_preimage" && ! -L "$route_preimage" ]] || holdfast_die "unsafe route-close preimage evidence"
    target="$state_dir/ROUTE-CLOSE-RETRY-$(date -u +%Y%m%dT%H%M%SZ)-$$.jsonl"
  else
    target="$route_preimage"
  fi
  if PGAPPNAME=holdfast-rikune-close "$psql_bin" "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/20260823_rikune_root_down.sql" >"$temporary" 2>&1; then
    status=0
  else
    status=$?
  fi
  chmod 0600 "$temporary"
  if [[ $status -eq 0 ]]; then
    mv -- "$temporary" "$target"
  else
    target="$state_dir/ROUTE-CLOSE-DOWN-FAILED-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
    mv -- "$temporary" "$target"
    echo "frozen route-down failed; exact output preserved at $target" >&2
    return "$status"
  fi
  route_down_execution_evidence_sha=$(holdfast_sha256 "$target")
}

validate_route_close_receipt_for_adoption() {
  local source_state=$1 expected_public="false" expected_preopen="none" open_receipt expected
  local key value
  require_root_file "$route_receipt"
  require_root_file "$backup/CONTROL.sha256"
  require_root_file "$backup/RELEASE-EVIDENCE.json"
  require_root_file "$route_preimage"
  (cd "$backup" && sha256sum --check CONTROL.sha256)
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || \
    holdfast_die "route-close source state points to another backup"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  if [[ "$source_state" == "ingress_open" ]]; then
    expected_public="true"
    open_receipt="$state_dir/OPEN.receipt"
    require_root_file "$open_receipt"
    [[ "$(jq -er '.open_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$open_receipt")" ]] || \
      holdfast_die "route-close source open receipt was replaced"
    expected_preopen=$(holdfast_receipt_value "$open_receipt" edge_evidence_sha256)
  elif [[ "$source_state" == "finalizing_route_armed" || \
    "$source_state" == "ingress_compensation_unverified" ]]; then
    expected_public="true"
    expected_preopen=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  fi
  for expected in \
    "schema_version=2" "source_state=$source_state" "estate_root=$estate_root" \
    "backup_dir=$backup" "control_sha256=$(holdfast_sha256 "$backup/CONTROL.sha256")" \
    "state_before_sha256=$(holdfast_sha256 "$state_file")" \
    "route_down_sha256=$expected_route_down" \
    "route_preimage_sha256=$(holdfast_sha256 "$route_preimage")" \
    "was_public_open=$expected_public" "preopen_edge_evidence_sha256=$expected_preopen" \
    "route_state=absent" "public_ipv4_ipv6_closed_status=404" \
    "db_public_db_bracket=absent-404-absent" "external_edge_mutation=none"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$route_receipt" "$key")" == "$value" ]] || \
      holdfast_die "route-close adoption receipt differs: $key"
  done
  [[ "$(holdfast_receipt_value "$route_receipt" route_down_execution_evidence_sha256)" \
    =~ ^[0-9a-f]{64}$ ]] || holdfast_die "route-close execution evidence identity is invalid"
}

commit_route_closed_state() {
  local state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg close_sha "$(holdfast_sha256 "$route_receipt")" \
    '.state="route_closed_awaiting_revocation" | .route_close_receipt_sha256=$close_sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
}

validate_backup_and_open_authority() {
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || holdfast_die "state points to another backup"
  require_canonical_root_dir "$backup/estate"
  require_canonical_root_dir "$backup/estate/tree"
  require_canonical_root_dir "$backup/runtime"
  for file in "$backup/CONTROL.sha256" "$backup/RELEASE-EVIDENCE.json" "$backup/release.env" \
    "$backup/DRY-RUN.receipt" "$backup/rollback.override.yml" \
    "$backup/TARGETS.sha256" "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" \
    "$backup/estate/APPLIED-TARGETS.sha256" "$backup/estate/PREIMAGES.sha256" \
    "$backup/estate/ABSENT.before" "$backup/estate/TRANSACTION.json" \
    "$backup/runtime/BACKUP.receipt" "$backup/runtime/SHA256SUMS" \
    "$backup/runtime/compose-config.json" "$backup/runtime/RUNNING-SERVICES.before"; do
    require_root_file "$file"
  done
  [[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || holdfast_die "backup contains a symlink"
  [[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || holdfast_die "backup contains a non-root-owned entry"
  (cd "$backup" && sha256sum --check CONTROL.sha256)
  run_python_tool "$release_validator" "$script_dir/validate_release_evidence.py" \
    --evidence "$backup/RELEASE-EVIDENCE.json"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode open \
    --evidence "$open_evidence" --signature "$open_signature" --public-key "$authority_public_key" \
    --release-env "$backup/release.env" --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$backup/DRY-RUN.receipt"
}

release_services=(
  access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
)
runtime_prior_services=()
rollback_running_services=()
restart_services=()

service_release_index() {
  case "$1" in
    access-governance) printf '0\n' ;;
    verdict) printf '1\n' ;;
    newapi) printf '2\n' ;;
    rikune-analyzer) printf '3\n' ;;
    strad) printf '4\n' ;;
    sluice) printf '5\n' ;;
    sluice-internal) printf '6\n' ;;
    *) return 1 ;;
  esac
}

validate_runtime_prior_services() {
  local manifest="$backup/runtime/RUNNING-SERVICES.before"
  local checksum_line checksum_file service index previous=-1
  runtime_prior_services=()
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" schema_version)" == "2" ]] || \
    holdfast_die "rollback requires a schema-v2 runtime backup"
  for expected in \
    "postgres_database=strad" "database_identity=postgres:5432/strad" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "runtime_writers_stopped=passed" \
    "prior_running_services_manifest=RUNNING-SERVICES.before"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup contract differs: $key"
  done
  [[ "$(holdfast_receipt_value "$backup/runtime/BACKUP.receipt" prior_running_services_sha256)" == \
    "$(holdfast_sha256 "$manifest")" ]] || holdfast_die "runtime prior-running manifest was replaced"
  while IFS= read -r checksum_line; do
    [[ "$checksum_line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
      holdfast_die "runtime SHA256SUMS contains an invalid line"
    checksum_file=${BASH_REMATCH[1]}
    [[ "$checksum_file" != "RUNNING-SERVICES.before" || \
      "$checksum_line" == "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" ]] || \
      holdfast_die "runtime SHA256SUMS does not bind the prior-running manifest"
  done <"$backup/runtime/SHA256SUMS"
  grep -Fqx "$(holdfast_sha256 "$manifest")  RUNNING-SERVICES.before" \
    "$backup/runtime/SHA256SUMS" || holdfast_die "runtime SHA256SUMS omits the prior-running manifest"
  (cd "$backup/runtime" && sha256sum --check SHA256SUMS)
  while IFS= read -r service || [[ -n "$service" ]]; do
    [[ -n "$service" ]] || holdfast_die "runtime prior-running manifest contains a blank service"
    index=-1
    case "$service" in
      strad) index=0 ;;
      rikune-analyzer) index=1 ;;
      *) holdfast_die "runtime prior-running manifest contains an unknown service: $service" ;;
    esac
    ((index > previous)) || holdfast_die "runtime prior-running manifest is duplicated or out of order"
    previous=$index
    runtime_prior_services+=("$service")
  done <"$manifest"
}

service_container_ids() {
  local service=$1
  "$docker_bin" ps -aq \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter "label=com.docker.compose.service=$service"
}

validate_rollback_running_manifest() {
  local manifest=$1 service index previous=-1
  rollback_running_services=()
  require_root_file "$manifest"
  while IFS= read -r service || [[ -n "$service" ]]; do
    [[ -n "$service" ]] || holdfast_die "rollback running-service manifest contains a blank service"
    index=$(service_release_index "$service") || \
      holdfast_die "rollback running-service manifest contains an unknown service: $service"
    ((index > previous)) || holdfast_die "rollback running-service manifest is duplicated or out of order"
    previous=$index
    rollback_running_services+=("$service")
  done <"$manifest"
}

capture_rollback_running_manifest() {
  local target=$1 temporary=$2 service output state
  local ids=()
  [[ ! -e "$target" && ! -L "$target" && ! -e "$temporary" && ! -L "$temporary" ]] || \
    holdfast_die "rollback running-service manifest path already exists"
  : >"$temporary"
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || \
      holdfast_die "could not inspect release service before rollback: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist for release service: $service"
    if ((${#ids[@]} == 0)); then continue; fi
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    case "$state" in
      running) printf '%s\n' "$service" >>"$temporary" ;;
      created|exited|dead) ;;
      *) holdfast_die "release service has an unstable pre-rollback state: $service=$state" ;;
    esac
  done
  commit_atomic_file "$temporary" "$target"
  validate_rollback_running_manifest "$target"
}

rollback_service_was_running() {
  local wanted=$1 service
  for service in "${rollback_running_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

runtime_service_was_running() {
  local wanted=$1 service
  for service in "${runtime_prior_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

quiesce_release_services() {
  local service output state
  local ids=()
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect release service before stop: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist before release-service stop: $service"
    if ((${#ids[@]})); then "$docker_bin" stop -t 120 "${ids[0]}" >/dev/null; fi
  done
  for service in "${release_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect release service after stop: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers exist after release-service stop: $service"
    for container_id in "${ids[@]}"; do
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "release service remains active after rollback quiesce: $service"
    done
  done
}

validate_runtime_restore_receipt() {
  local receipt="$backup/runtime/RESTORE.receipt"
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "restore_mode=schema-v2" \
    "database_identity=postgres:5432/strad" "database_restore=restored" \
    "runtime_writers_removed=passed" "volume_mount_release=passed" "volume_count=6"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime restore receipt differs: $key"
  done
}

validate_estate_restore_manifests() {
  cmp -s -- "$backup/TARGETS.sha256" "$backup/estate/APPLIED-TARGETS.sha256" || \
    holdfast_die "estate applied-target authority differs from CONTROL targets"
  cmp -s -- "$backup/APPLY-PREIMAGES.sha256" "$backup/estate/PREIMAGES.sha256" || \
    holdfast_die "estate preimage authority differs from CONTROL preimages"
  cmp -s -- "$backup/APPLY-ABSENT.paths" "$backup/estate/ABSENT.before" || \
    holdfast_die "estate absent authority differs from CONTROL absent dispositions"
}

verify_estate_disposition() {
  local mode=$1
  python3 - "$mode" "$estate_root" "$backup/TARGETS.sha256" \
    "$backup/APPLY-PREIMAGES.sha256" "$backup/APPLY-ABSENT.paths" \
    "$backup/estate/tree" <<'PY'
import hashlib
import re
import stat
import sys
from pathlib import Path

mode, estate_arg, targets_arg, preimages_arg, absent_arg, tree_arg = sys.argv[1:]
estate = Path(estate_arg)
tree = Path(tree_arg)
manifest_re = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")
path_re = re.compile(r"^[A-Za-z0-9._/-]+$")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_relative(value: str) -> bool:
    parts = Path(value).parts
    return bool(value) and not value.startswith("/") and ".." not in parts


def parse_manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = manifest_re.fullmatch(line)
        if match is None or not safe_relative(match.group(2)):
            raise RuntimeError(f"unsafe rollback manifest line: {path}")
        relative = match.group(2)
        if relative in result:
            raise RuntimeError(f"duplicate rollback manifest path: {relative}")
        result[relative] = match.group(1)
    return result


def parse_absent(path: Path) -> set[str]:
    result: set[str] = set()
    for relative in path.read_text(encoding="utf-8").splitlines():
        if not path_re.fullmatch(relative) or not safe_relative(relative) or relative in result:
            raise RuntimeError(f"unsafe rollback absent path: {relative}")
        result.add(relative)
    return result


def regular_digest(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1 or info.st_uid != 0:
        raise RuntimeError(f"unsafe rollback file: {path}")
    return digest(path)


def validate_parent_chain(relative: str) -> None:
    current = estate
    for component in Path(relative).parts[:-1]:
        current /= component
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or current.is_symlink() or info.st_uid != 0:
            raise RuntimeError(f"unsafe rollback target parent: {relative}")


targets = parse_manifest(Path(targets_arg))
preimages = parse_manifest(Path(preimages_arg))
absent = parse_absent(Path(absent_arg))
if set(targets) != set(preimages) | absent or set(preimages) & absent:
    raise RuntimeError("rollback dispositions do not exactly cover CONTROL targets")
for relative, expected in preimages.items():
    if regular_digest(tree / relative) != expected:
        raise RuntimeError(f"rollback tree checksum mismatch: {relative}")
for relative, applied_digest in targets.items():
    validate_parent_chain(relative)
    observed = regular_digest(estate / relative)
    if mode == "applied":
        allowed = {applied_digest}
    elif mode == "mixed":
        allowed = {applied_digest, preimages.get(relative)} if relative in preimages else {applied_digest, None}
    elif mode == "preimage":
        allowed = {preimages[relative]} if relative in preimages else {None}
    else:
        raise RuntimeError(f"unknown rollback disposition mode: {mode}")
    if observed not in allowed:
        raise RuntimeError(f"live rollback disposition drift: {relative}")
PY
}

load_restored_compose_services() {
  local config_temp=$1 service
  restored_compose_services=()
  declare -gA restored_compose_has=()
  rollback_compose=(
    "$docker_bin" compose --env-file "$estate_root/deploy/.env"
    -f "$estate_root/deploy/docker-compose.yml" -f "$backup/rollback.override.yml"
  )
  "${rollback_compose[@]}" config --format json >"$config_temp"
  [[ "$(jq -er '.name' "$config_temp")" == "$compose_project" ]] || \
    holdfast_die "restored Compose project identity differs"
  mapfile -t restored_compose_services < <(jq -er '.services | keys[]' "$config_temp")
  for service in "${restored_compose_services[@]}"; do
    [[ "$service" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "restored Compose contains an unsafe service name"
    [[ -z "${restored_compose_has[$service]:-}" ]] || holdfast_die "restored Compose repeats a service"
    restored_compose_has[$service]=1
  done
}

compute_restart_services() {
  local service
  restart_services=()
  for service in "${release_services[@]}"; do
    case "$service" in
      strad|rikune-analyzer)
        runtime_service_was_running "$service" || continue
        ;;
      *)
        rollback_service_was_running "$service" || continue
        ;;
    esac
    [[ "${restored_compose_has[$service]:-0}" == "1" ]] || continue
    restart_services+=("$service")
  done
}

service_is_restart_target() {
  local wanted=$1 service
  for service in "${restart_services[@]}"; do
    [[ "$service" == "$wanted" ]] && return 0
  done
  return 1
}

verify_restarted_and_excluded_services() {
  local service output state health
  local ids=()
  for service in "${restart_services[@]}"; do
    output=$(service_container_ids "$service") || holdfast_die "could not inspect reactivated service: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} == 1)) || holdfast_die "reactivated service container identity differs: $service"
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    [[ "$state" == "running" ]] || holdfast_die "reactivated service is not running: $service=$state"
    health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}")
    [[ "$health" == "none" || "$health" == "healthy" ]] || \
      holdfast_die "reactivated service is not healthy: $service=$health"
  done
  for service in "${release_services[@]}"; do
    service_is_restart_target "$service" && continue
    output=$(service_container_ids "$service") || holdfast_die "could not inspect service excluded from rollback activation: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple excluded service containers exist: $service"
    for container_id in "${ids[@]}"; do
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "service excluded from rollback activation became active: $service"
    done
  done
}

join_services() {
  local IFS=,
  printf '%s' "$*"
}

validate_rollback_arm() {
  local expected key value
  [[ "$(jq -er '.estate_root' "$state_file")" == "$estate_root" ]] || \
    holdfast_die "rollback state points to another estate"
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || \
    holdfast_die "rollback state points to another backup"
  original_transaction_sha=$(jq -er '.transaction_sha256' "$state_file")
  [[ "$original_transaction_sha" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "rollback state transaction identity is invalid"
  applied_targets_sha=$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")
  [[ "$(jq -er '.applied_targets_sha256' "$state_file")" == "$applied_targets_sha" ]] || \
    holdfast_die "rollback state applied-target authority was replaced"
  attempt_id=$(jq -er '.rollback_attempt_id' "$state_file")
  [[ "$attempt_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || holdfast_die "rollback attempt identity is unsafe"
  rollback_manifest_name=$(jq -er '.rollback_running_services_manifest' "$state_file")
  [[ "$rollback_manifest_name" == "ROLLBACK-RUNNING-SERVICES-${attempt_id}.before" ]] || \
    holdfast_die "rollback running-service manifest name differs"
  rollback_manifest="$state_dir/$rollback_manifest_name"
  require_root_file "$rollback_manifest"
  rollback_manifest_sha=$(holdfast_sha256 "$rollback_manifest")
  [[ "$(jq -er '.rollback_running_services_sha256' "$state_file")" == "$rollback_manifest_sha" ]] || \
    holdfast_die "rollback running-service manifest was replaced"
  validate_rollback_running_manifest "$rollback_manifest"

  rollback_armed_name=$(jq -er '.rollback_armed_receipt' "$state_file")
  [[ "$rollback_armed_name" == "ROLLBACK-EXECUTE-ARMED-${attempt_id}.receipt" ]] || \
    holdfast_die "rollback armed receipt name differs"
  rollback_armed_receipt="$state_dir/$rollback_armed_name"
  require_root_file "$rollback_armed_receipt"
  rollback_armed_sha=$(holdfast_sha256 "$rollback_armed_receipt")
  [[ "$(jq -er '.rollback_armed_receipt_sha256' "$state_file")" == "$rollback_armed_sha" ]] || \
    holdfast_die "rollback armed receipt was replaced"
  for expected in \
    "schema_version=2" "attempt_id=$attempt_id" "estate_root=$estate_root" \
    "backup_dir=$backup" "control_sha256=$control_sha" \
    "transaction_sha256=$original_transaction_sha" \
    "applied_targets_sha256=$applied_targets_sha" \
    "targets_sha256=$(holdfast_sha256 "$backup/TARGETS.sha256")" \
    "apply_preimages_sha256=$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")" \
    "apply_absent_sha256=$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")" \
    "route_close_receipt_sha256=$(holdfast_sha256 "$route_receipt")" \
    "open_evidence_file=$frozen_open_evidence_name" \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "open_signature_file=$frozen_open_signature_name" \
    "open_signature_sha256=$(holdfast_sha256 "$open_signature")" \
    "authority_public_key_file=$frozen_public_key_name" \
    "authority_public_key_sha256=$(holdfast_sha256 "$authority_public_key")" \
    "revocation_evidence_file=$frozen_revocation_evidence_name" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "revocation_signature_file=$frozen_revocation_signature_name" \
    "revocation_signature_sha256=$(holdfast_sha256 "$revocation_signature")" \
    "edge_rollback_evidence_file=$frozen_edge_evidence_name" \
    "edge_rollback_evidence_sha256=$edge_rollback_sha" \
    "edge_rollback_signature_file=$frozen_edge_signature_name" \
    "edge_rollback_signature_sha256=$edge_rollback_signature_sha" \
    "open_edge_evidence_file=$frozen_open_edge_name" \
    "open_edge_evidence_sha256=$open_edge_sha" \
    "compose_project=$compose_project" \
    "release_services=access-governance,verdict,newapi,rikune-analyzer,strad,sluice,sluice-internal" \
    "running_services_manifest=$rollback_manifest_name" \
    "running_services_sha256=$rollback_manifest_sha" \
    "runtime_prior_services_sha256=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" \
    "activation_policy=restore-exact-prior-running" \
    "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$rollback_armed_receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback armed authority differs: $key"
  done
}

validate_runtime_restore_phase_receipt() {
  local receipt="$state_dir/$runtime_phase_name" expected key value
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "phase=runtime_restore_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "runtime_restore_receipt_sha256=$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")" \
    "runtime_backup_receipt_sha256=$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")" \
    "runtime_backup_manifest_sha256=$(holdfast_sha256 "$backup/runtime/SHA256SUMS")" \
    "transaction_before_sha256=$original_transaction_sha" \
    "applied_targets_sha256=$applied_targets_sha" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime-restore phase receipt differs: $key"
  done
  runtime_phase_sha=$(holdfast_sha256 "$receipt")
}

validate_phase_state_binding() {
  local name_field=$1 sha_field=$2 expected_name=$3 expected_sha=$4
  [[ "$(jq -er --arg field "$name_field" '.[$field]' "$state_file")" == "$expected_name" ]] || \
    holdfast_die "rollback phase state points to another receipt: $name_field"
  [[ "$(jq -er --arg field "$sha_field" '.[$field]' "$state_file")" == "$expected_sha" ]] || \
    holdfast_die "rollback phase state receipt was replaced: $sha_field"
}

persist_runtime_restore_phase() {
  local receipt="$state_dir/$runtime_phase_name" temporary state_tmp
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_runtime_restore_phase_receipt
  else
    temporary="$state_dir/.${runtime_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=runtime_restore_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'runtime_restore_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")"
      printf 'runtime_backup_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/BACKUP.receipt")"
      printf 'runtime_backup_manifest_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/SHA256SUMS")"
      printf 'transaction_before_sha256=%s\n' "$original_transaction_sha"
      printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_runtime_restore_phase_receipt
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$runtime_phase_name" --arg sha "$runtime_phase_sha" \
    '.state="rollback_runtime_restore_done" | .rollback_runtime_restore_phase_receipt=$name | .rollback_runtime_restore_phase_receipt_sha256=$sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_runtime_restore_done"
}

validate_estate_restore_phase_receipt() {
  local receipt="$state_dir/$estate_phase_name" expected key value
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "phase=estate_restore_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "runtime_restore_phase_receipt_sha256=$runtime_phase_sha" \
    "estate_transaction_sha256=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" \
    "applied_targets_sha256=$applied_targets_sha" \
    "preimages_sha256=$(holdfast_sha256 "$backup/estate/PREIMAGES.sha256")" \
    "absent_sha256=$(holdfast_sha256 "$backup/estate/ABSENT.before")" \
    "live_estate_disposition=preimage" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "estate-restore phase receipt differs: $key"
  done
  estate_phase_sha=$(holdfast_sha256 "$receipt")
}

persist_estate_restore_phase() {
  local receipt="$state_dir/$estate_phase_name" temporary state_tmp restored_transaction_sha
  restored_transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_estate_restore_phase_receipt
  else
    temporary="$state_dir/.${estate_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=estate_restore_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'runtime_restore_phase_receipt_sha256=%s\n' "$runtime_phase_sha"
      printf 'estate_transaction_sha256=%s\n' "$restored_transaction_sha"
      printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
      printf 'preimages_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/PREIMAGES.sha256")"
      printf 'absent_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/ABSENT.before")"
      printf 'live_estate_disposition=preimage\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_estate_restore_phase_receipt
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$estate_phase_name" --arg sha "$estate_phase_sha" \
    --arg transaction_sha "$restored_transaction_sha" \
    '.state="rollback_estate_restore_done" | .rollback_estate_restore_phase_receipt=$name | .rollback_estate_restore_phase_receipt_sha256=$sha | .rollback_estate_transaction_sha256=$transaction_sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_estate_restore_done"
}

load_exact_restart_authority() {
  local config_temp
  config_temp=$(mktemp "${TMPDIR:-/var/tmp}/holdfast-rollback-compose.XXXXXX")
  load_restored_compose_services "$config_temp"
  rm -f -- "$config_temp"
  compute_restart_services
  expected_reactivated_services="none"
  if ((${#restart_services[@]})); then
    expected_reactivated_services=$(join_services "${restart_services[@]}")
  fi
}

validate_services_reactivated_phase_receipt() {
  local receipt="$state_dir/$services_phase_name" expected key value
  require_root_file "$receipt"
  load_exact_restart_authority
  for expected in \
    "schema_version=2" "phase=services_reactivated_done" "attempt_id=$attempt_id" \
    "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "estate_restore_phase_receipt_sha256=$estate_phase_sha" \
    "reactivated_services=$expected_reactivated_services" \
    "excluded_services_inactive=passed" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "service-reactivation phase receipt differs: $key"
  done
  verify_restarted_and_excluded_services
  services_phase_sha=$(holdfast_sha256 "$receipt")
}

persist_services_reactivated_phase() {
  local receipt="$state_dir/$services_phase_name" temporary state_tmp
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    validate_services_reactivated_phase_receipt
  else
    temporary="$state_dir/.${services_phase_name}.$$"
    {
      printf 'schema_version=2\n'
      printf 'phase=services_reactivated_done\n'
      printf 'completed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'attempt_id=%s\n' "$attempt_id"
      printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
      printf 'estate_restore_phase_receipt_sha256=%s\n' "$estate_phase_sha"
      printf 'reactivated_services=%s\n' "$expected_reactivated_services"
      printf 'excluded_services_inactive=passed\n'
      printf 'ingress_opened=false\n'
    } >"$temporary"
    commit_atomic_file "$temporary" "$receipt"
    validate_services_reactivated_phase_receipt
  fi
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg name "$services_phase_name" --arg sha "$services_phase_sha" \
    '.state="rollback_services_reactivated_done" | .rollback_services_reactivated_phase_receipt=$name | .rollback_services_reactivated_phase_receipt_sha256=$sha | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_services_reactivated_done"
}

verify_fresh_running_snapshot() {
  local service output state expected="false"
  local ids=()
  for service in "${release_services[@]}"; do
    rollback_service_was_running "$service" && expected="true" || expected="false"
    output=$(service_container_ids "$service") || holdfast_die "could not revalidate release service before rollback: $service"
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || holdfast_die "multiple containers appeared before rollback: $service"
    if ((${#ids[@]} == 0)); then
      [[ "$expected" == "false" ]] || holdfast_die "captured running service disappeared before rollback: $service"
      continue
    fi
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}")
    if [[ "$expected" == "true" ]]; then
      [[ "$state" == "running" ]] || holdfast_die "captured service state changed before rollback: $service=$state"
    else
      [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || \
        holdfast_die "excluded service became active before rollback: $service=$state"
    fi
  done
}

validate_completed_rollback_receipt() {
  local receipt=$1 expected key value reactivated
  validate_runtime_restore_phase_receipt
  validate_estate_restore_phase_receipt
  validate_services_reactivated_phase_receipt
  validate_phase_state_binding rollback_runtime_restore_phase_receipt \
    rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
  validate_phase_state_binding rollback_estate_restore_phase_receipt \
    rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
  validate_phase_state_binding rollback_services_reactivated_phase_receipt \
    rollback_services_reactivated_phase_receipt_sha256 "$services_phase_name" "$services_phase_sha"
  require_root_file "$receipt"
  for expected in \
    "schema_version=2" "rollback_armed_receipt_sha256=$rollback_armed_sha" \
    "running_services_sha256=$rollback_manifest_sha" \
    "runtime_prior_services_sha256=$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")" \
    "runtime_restore_phase_receipt_sha256=$runtime_phase_sha" \
    "estate_restore_phase_receipt_sha256=$estate_phase_sha" \
    "services_reactivated_phase_receipt_sha256=$services_phase_sha" \
    "route_close_receipt_sha256=$(holdfast_sha256 "$route_receipt")" \
    "revocation_evidence_sha256=$(holdfast_sha256 "$revocation_evidence")" \
    "open_evidence_sha256=$(holdfast_sha256 "$open_evidence")" \
    "runtime_restore_receipt_sha256=$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")" \
    "estate_transaction_sha256=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" \
    "runtime_restore=passed" "mixed_estate_restore=passed" \
    "orphan_cleanup=passed" \
    "service_reactivation=passed" "excluded_services_inactive=passed" \
    "activation_policy=restore-exact-prior-running" \
    "public_route_state=dual-stack-404" "ingress_opened=false"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$receipt" "$key")" == "$value" ]] || \
      holdfast_die "rollback completion receipt differs: $key"
  done
  reactivated=$(holdfast_receipt_value "$receipt" reactivated_services)
  [[ "$reactivated" == "$expected_reactivated_services" ]] || \
    holdfast_die "rollback receipt reactivated-services set differs from frozen recovery authority"
}

finalize_rollback_state() {
  local receipt=$1 completed state_tmp current
  completed="$state_dir/ROLLBACK-COMPLETE-${attempt_id}.json"
  [[ ! -e "$completed" && ! -L "$completed" ]] || holdfast_die "rollback completion state already exists"
  current=$(jq -er '.state' "$state_file")
  if [[ "$current" != "rolled_back" ]]; then
    state_tmp="$state_dir/.ROLLBACK-COMPLETE.$$"
    jq --arg receipt_sha "$(holdfast_sha256 "$receipt")" \
      '.state="rolled_back" | .rollback_receipt_sha256=$receipt_sha | .ingress_opened=false' \
      "$state_file" >"$state_tmp"
    commit_atomic_file "$state_tmp" "$state_file"
  else
    [[ "$(jq -er '.rollback_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$receipt")" ]] || \
      holdfast_die "rolled-back state receipt was replaced"
  fi
  mv -- "$state_file" "$completed"
  sync -f "$completed"
  sync -f "$state_dir"
}

if [[ "$phase" == "close-route" ]]; then
  # Safety ordering is intentional: the frozen, transactionally self-snapshotting down asset and
  # the public bracket run before parsing mutable armed/open metadata or validating backup evidence.
  execute_frozen_route_down
  verify_closed_bracket

  current_state=$(jq -er '.state' "$state_file")
  [[ "$current_state" == "ingress_open" || "$current_state" == "finalizing_route_armed" || "$current_state" == "ingress_compensation_unverified" || "$current_state" == "edge_prepared_route_closed" || "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "route close refuses state $current_state"
  if [[ -e "$route_receipt" || -L "$route_receipt" ]]; then
    validate_route_close_receipt_for_adoption "$current_state"
    commit_route_closed_state
    echo "previously completed route close was adopted; now finish revocation evidence"
    exit 0
  fi
  validate_backup_and_open_authority

  preopen_edge_sha="none"
  was_public_open="false"
  if [[ "$current_state" == "ingress_open" ]]; then
    was_public_open="true"
    open_receipt="$state_dir/OPEN.receipt"
    [[ -f "$open_receipt" && ! -L "$open_receipt" ]] || holdfast_die "open receipt is absent"
    [[ "$(jq -er '.open_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$open_receipt")" ]] || \
      holdfast_die "open receipt was replaced"
    preopen_edge_sha=$(holdfast_receipt_value "$open_receipt" edge_evidence_sha256)
  elif [[ "$current_state" == "finalizing_route_armed" || "$current_state" == "ingress_compensation_unverified" ]]; then
    was_public_open="true"
    preopen_edge_sha=$(jq -er '.open_armed_edge_evidence_sha256' "$state_file")
  fi
  if [[ "$was_public_open" == "true" ]]; then
    [[ "$preopen_edge_sha" =~ ^[0-9a-f]{64}$ ]] || holdfast_die "public open edge evidence hash is invalid"
  fi

  receipt_tmp="$state_dir/.ROUTE-CLOSE.receipt.$$"
  {
    printf 'schema_version=2\n'
    printf 'route_closed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'source_state=%s\n' "$current_state"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$(holdfast_sha256 "$backup/CONTROL.sha256")"
    printf 'state_before_sha256=%s\n' "$(holdfast_sha256 "$state_file")"
    printf 'route_down_sha256=%s\n' "$expected_route_down"
    printf 'route_down_execution_evidence_sha256=%s\n' "$route_down_execution_evidence_sha"
    printf 'route_preimage_sha256=%s\n' "$(holdfast_sha256 "$route_preimage")"
    printf 'route_conflict_cleanup=same-name-or-analyze-root\n'
    printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
    printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$open_evidence")"
    printf 'was_public_open=%s\n' "$was_public_open"
    printf 'preopen_edge_evidence_sha256=%s\n' "$preopen_edge_sha"
    printf 'route_state=absent\n'
    printf 'public_host=analyze.w33d.xyz\n'
    printf 'edge_owner=existing-w33d-sluice\n'
    printf 'public_ipv4_ipv6_closed_status=404\n'
    printf 'db_public_db_bracket=absent-404-absent\n'
    printf 'external_edge_mutation=none\n'
  } >"$receipt_tmp"
  commit_atomic_file "$receipt_tmp" "$route_receipt"
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_ROUTE_CLOSE_RECEIPT:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  commit_route_closed_state
  echo "route is dual-stack 404 closed; now revoke the exact source grant, await all seven tombstones, then sign v2 rollback evidence"
  exit 0
fi

current_state=$(jq -er '.state' "$state_file")
[[ "$current_state" == "route_closed_awaiting_revocation" || \
  "$current_state" == "rollback_execute_armed" || \
  "$current_state" == "rollback_runtime_restore_done" || \
  "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]] || \
  holdfast_die "rollback execute refuses state $current_state"
require_root_file "$route_receipt"
[[ "$(jq -er '.route_close_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$route_receipt")" ]] || \
  holdfast_die "route-close receipt was replaced"
if [[ "$current_state" != "route_closed_awaiting_revocation" ]]; then
  load_frozen_rollback_authorities
fi
validate_backup_and_open_authority
for path in "$revocation_evidence" "$revocation_signature"; do holdfast_require_absolute "$path"; done
run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode rollback \
  --evidence "$revocation_evidence" --signature "$revocation_signature" \
  --public-key "$authority_public_key" --release-env "$backup/release.env" \
  --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
  --route-close-receipt "$route_receipt"
verify_closed_bracket

edge_rollback_sha="none"
edge_rollback_signature_sha="none"
open_edge_sha="none"
if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
  [[ -n "$edge_rollback_evidence" && -n "$edge_rollback_signature" && -n "$open_edge_evidence" ]] || \
    holdfast_die "public rollback requires signed v2 dual-stack 404 evidence"
  for path in "$edge_rollback_evidence" "$edge_rollback_signature" "$open_edge_evidence"; do holdfast_require_absolute "$path"; done
  run_python_tool "$edge_tool" "$script_dir/edge_evidence.py" --mode rollback \
    --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-edge-evidence "$open_edge_evidence" \
    --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
  edge_rollback_sha=$(holdfast_sha256 "$edge_rollback_evidence")
  edge_rollback_signature_sha=$(holdfast_sha256 "$edge_rollback_signature")
  open_edge_sha=$(holdfast_sha256 "$open_edge_evidence")
fi
verify_closed_bracket

rollback_receipt="$backup/ROLLBACK.receipt"
validate_runtime_prior_services
validate_estate_restore_manifests
control_sha=$(holdfast_sha256 "$backup/CONTROL.sha256")
state_control_sha=$(jq -er '.control_sha256' "$state_file")
[[ "$state_control_sha" == "$control_sha" ]] || \
  holdfast_die "rollback current state CONTROL differs"
compose_project=$(jq -er '.name' "$backup/runtime/compose-config.json")
[[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
  holdfast_die "runtime backup has an unsafe Compose project name"

fresh_arm="false"
if [[ "$current_state" == "route_closed_awaiting_revocation" ]]; then
  [[ ! -e "$rollback_receipt" && ! -L "$rollback_receipt" ]] || \
    holdfast_die "rollback receipt exists before execute is armed"
  [[ ! -e "$backup/runtime/RESTORE.receipt" && ! -L "$backup/runtime/RESTORE.receipt" ]] || \
    holdfast_die "runtime restore receipt exists before rollback execute is armed"
  original_transaction_sha=$(holdfast_sha256 "$backup/estate/TRANSACTION.json")
  applied_targets_sha=$(holdfast_sha256 "$backup/estate/APPLIED-TARGETS.sha256")
  [[ "$(jq -er '.transaction_sha256' "$state_file")" == "$original_transaction_sha" ]] || \
    holdfast_die "rollback current state transaction authority differs"
  [[ "$(jq -er '.applied_targets_sha256' "$state_file")" == "$applied_targets_sha" ]] || \
    holdfast_die "rollback current state applied-target authority differs"
  [[ "$(jq -er '.schema_version == 1 and .state == "applied"' \
    "$backup/estate/TRANSACTION.json")" == "true" ]] || \
    holdfast_die "rollback requires the exact applied estate transaction"
  verify_estate_disposition applied
  attempt_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  frozen_open_evidence_name="ROLLBACK-OPEN-EVIDENCE-${attempt_id}.json"
  frozen_open_signature_name="ROLLBACK-OPEN-SIGNATURE-${attempt_id}.sig"
  frozen_public_key_name="ROLLBACK-AUTHORITY-PUBLIC-KEY-${attempt_id}.pub"
  frozen_revocation_evidence_name="ROLLBACK-REVOCATION-EVIDENCE-${attempt_id}.json"
  frozen_revocation_signature_name="ROLLBACK-REVOCATION-SIGNATURE-${attempt_id}.sig"
  frozen_edge_evidence_name="none"
  frozen_edge_signature_name="none"
  frozen_open_edge_name="none"
  atomic_copy_authority "$open_evidence" "$state_dir/$frozen_open_evidence_name"
  atomic_copy_authority "$open_signature" "$state_dir/$frozen_open_signature_name"
  atomic_copy_authority "$authority_public_key" "$state_dir/$frozen_public_key_name"
  atomic_copy_authority "$revocation_evidence" "$state_dir/$frozen_revocation_evidence_name"
  atomic_copy_authority "$revocation_signature" "$state_dir/$frozen_revocation_signature_name"
  if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
    frozen_edge_evidence_name="ROLLBACK-EDGE-EVIDENCE-${attempt_id}.json"
    frozen_edge_signature_name="ROLLBACK-EDGE-SIGNATURE-${attempt_id}.sig"
    frozen_open_edge_name="ROLLBACK-OPEN-EDGE-EVIDENCE-${attempt_id}.json"
    atomic_copy_authority "$edge_rollback_evidence" "$state_dir/$frozen_edge_evidence_name"
    atomic_copy_authority "$edge_rollback_signature" "$state_dir/$frozen_edge_signature_name"
    atomic_copy_authority "$open_edge_evidence" "$state_dir/$frozen_open_edge_name"
  fi
  open_evidence="$state_dir/$frozen_open_evidence_name"
  open_signature="$state_dir/$frozen_open_signature_name"
  authority_public_key="$state_dir/$frozen_public_key_name"
  revocation_evidence="$state_dir/$frozen_revocation_evidence_name"
  revocation_signature="$state_dir/$frozen_revocation_signature_name"
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    edge_rollback_evidence="$state_dir/$frozen_edge_evidence_name"
    edge_rollback_signature="$state_dir/$frozen_edge_signature_name"
    open_edge_evidence="$state_dir/$frozen_open_edge_name"
  fi
  # Re-verify the immutable copies themselves.  Validation of the source paths
  # before copying is not sufficient across a validate-to-copy TOCTOU window.
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode open \
    --evidence "$open_evidence" --signature "$open_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$backup/DRY-RUN.receipt"
  run_python_tool "$authority_tool" "$script_dir/authority_evidence.py" --mode rollback \
    --evidence "$revocation_evidence" --signature "$revocation_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
    --route-close-receipt "$route_receipt"
  if [[ "$frozen_edge_evidence_name" != "none" ]]; then
    run_python_tool "$edge_tool" "$script_dir/edge_evidence.py" --mode rollback \
      --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
      --public-key "$authority_public_key" --release-env "$backup/release.env" \
      --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-edge-evidence "$open_edge_evidence" \
      --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
    edge_rollback_sha=$(holdfast_sha256 "$edge_rollback_evidence")
    edge_rollback_signature_sha=$(holdfast_sha256 "$edge_rollback_signature")
    open_edge_sha=$(holdfast_sha256 "$open_edge_evidence")
  fi
  rollback_manifest_name="ROLLBACK-RUNNING-SERVICES-${attempt_id}.before"
  rollback_manifest="$state_dir/$rollback_manifest_name"
  rollback_manifest_tmp="$state_dir/.ROLLBACK-RUNNING-SERVICES.$$"
  capture_rollback_running_manifest "$rollback_manifest" "$rollback_manifest_tmp"
  rollback_manifest_sha=$(holdfast_sha256 "$rollback_manifest")

  rollback_armed_name="ROLLBACK-EXECUTE-ARMED-${attempt_id}.receipt"
  rollback_armed_receipt="$state_dir/$rollback_armed_name"
  rollback_armed_tmp="$state_dir/.ROLLBACK-EXECUTE-ARMED.$$"
  [[ ! -e "$rollback_armed_receipt" && ! -L "$rollback_armed_receipt" && \
    ! -e "$rollback_armed_tmp" && ! -L "$rollback_armed_tmp" ]] || \
    holdfast_die "rollback armed receipt path already exists"
  {
    printf 'schema_version=2\n'
    printf 'armed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'attempt_id=%s\n' "$attempt_id"
    printf 'estate_root=%s\n' "$estate_root"
    printf 'backup_dir=%s\n' "$backup"
    printf 'control_sha256=%s\n' "$control_sha"
    printf 'transaction_sha256=%s\n' "$original_transaction_sha"
    printf 'applied_targets_sha256=%s\n' "$applied_targets_sha"
    printf 'targets_sha256=%s\n' "$(holdfast_sha256 "$backup/TARGETS.sha256")"
    printf 'apply_preimages_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-PREIMAGES.sha256")"
    printf 'apply_absent_sha256=%s\n' "$(holdfast_sha256 "$backup/APPLY-ABSENT.paths")"
    printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
    printf 'open_evidence_file=%s\n' "$frozen_open_evidence_name"
    printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
    printf 'open_signature_file=%s\n' "$frozen_open_signature_name"
    printf 'open_signature_sha256=%s\n' "$(holdfast_sha256 "$open_signature")"
    printf 'authority_public_key_file=%s\n' "$frozen_public_key_name"
    printf 'authority_public_key_sha256=%s\n' "$(holdfast_sha256 "$authority_public_key")"
    printf 'revocation_evidence_file=%s\n' "$frozen_revocation_evidence_name"
    printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
    printf 'revocation_signature_file=%s\n' "$frozen_revocation_signature_name"
    printf 'revocation_signature_sha256=%s\n' "$(holdfast_sha256 "$revocation_signature")"
    printf 'edge_rollback_evidence_file=%s\n' "$frozen_edge_evidence_name"
    printf 'edge_rollback_evidence_sha256=%s\n' "$edge_rollback_sha"
    printf 'edge_rollback_signature_file=%s\n' "$frozen_edge_signature_name"
    printf 'edge_rollback_signature_sha256=%s\n' "$edge_rollback_signature_sha"
    printf 'open_edge_evidence_file=%s\n' "$frozen_open_edge_name"
    printf 'open_edge_evidence_sha256=%s\n' "$open_edge_sha"
    printf 'compose_project=%s\n' "$compose_project"
    printf 'release_service_count=7\n'
    printf 'release_services=access-governance,verdict,newapi,rikune-analyzer,strad,sluice,sluice-internal\n'
    printf 'running_services_manifest=%s\n' "$rollback_manifest_name"
    printf 'running_services_sha256=%s\n' "$rollback_manifest_sha"
    printf 'runtime_prior_services_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")"
    printf 'activate_services_requested=%s\n' "$activate"
    printf 'activation_policy=restore-exact-prior-running\n'
    printf 'ingress_opened=false\n'
  } >"$rollback_armed_tmp"
  commit_atomic_file "$rollback_armed_tmp" "$rollback_armed_receipt"
  rollback_armed_sha=$(holdfast_sha256 "$rollback_armed_receipt")

  state_tmp="$state_dir/.CURRENT.json.$$"
  jq \
    --arg attempt "$attempt_id" --arg manifest "$rollback_manifest_name" \
    --arg manifest_sha "$rollback_manifest_sha" --arg armed "$rollback_armed_name" \
    --arg armed_sha "$rollback_armed_sha" --arg control "$control_sha" \
    '.state="rollback_execute_armed" | .rollback_attempt_id=$attempt | .rollback_running_services_manifest=$manifest | .rollback_running_services_sha256=$manifest_sha | .rollback_armed_receipt=$armed | .rollback_armed_receipt_sha256=$armed_sha | .control_sha256=$control | .ingress_opened=false' \
    "$state_file" >"$state_tmp"
  commit_atomic_file "$state_tmp" "$state_file"
  current_state="rollback_execute_armed"
  fresh_arm="true"
fi
validate_rollback_arm
runtime_phase_name="ROLLBACK-RUNTIME-RESTORE-DONE-${attempt_id}.receipt"
estate_phase_name="ROLLBACK-ESTATE-RESTORE-DONE-${attempt_id}.receipt"
services_phase_name="ROLLBACK-SERVICES-REACTIVATED-DONE-${attempt_id}.receipt"
activation_requested=$(holdfast_receipt_value "$rollback_armed_receipt" activate_services_requested)
[[ "$activation_requested" == "true" || "$activation_requested" == "false" ]] || \
  holdfast_die "rollback armed activation compatibility value differs"

if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && "${HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_ARM:-0}" == "1" ]]; then
  kill -KILL "$$"
fi

# A receipt is written only after all restore and lifecycle proofs pass.  If a
# SIGKILL lands between that receipt and CURRENT finalization, reuse it without
# repeating or resampling the runtime mutation.
if [[ -e "$rollback_receipt" || -L "$rollback_receipt" ]]; then
  validate_completed_rollback_receipt "$rollback_receipt"
  finalize_rollback_state "$rollback_receipt"
  echo "previously completed checksum-bound rollback was finalized; ingress remains closed"
  exit 0
fi

if [[ "$current_state" == "rollback_execute_armed" ]]; then
  [[ "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" == "$original_transaction_sha" && \
    "$(jq -er '.schema_version == 1 and .state == "applied"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
    holdfast_die "pre-restore estate transaction differs from the armed authority"
  verify_estate_disposition applied
  if [[ "$fresh_arm" == "true" ]]; then verify_fresh_running_snapshot; fi
  quiesce_release_services
  if [[ -e "$state_dir/$runtime_phase_name" || -L "$state_dir/$runtime_phase_name" ]]; then
    validate_runtime_restore_receipt
  elif [[ -e "$backup/runtime/RESTORE.receipt" || -L "$backup/runtime/RESTORE.receipt" ]]; then
    # runtime-restore commits RESTORE.receipt only after its full mutation.  A
    # crash in the following receipt/state gap is adopted instead of replayed.
    validate_runtime_restore_receipt
  else
    "$runtime_restore" --execute --compose-root "$estate_root" --backup-dir "$backup/runtime"
    validate_runtime_restore_receipt
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  fi
  persist_runtime_restore_phase
fi

if [[ "$current_state" == "rollback_runtime_restore_done" || \
  "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_runtime_restore_phase_receipt
  validate_phase_state_binding rollback_runtime_restore_phase_receipt \
    rollback_runtime_restore_phase_receipt_sha256 "$runtime_phase_name" "$runtime_phase_sha"
fi

if [[ "$current_state" == "rollback_runtime_restore_done" ]]; then
  quiesce_release_services
  transaction_state=$(jq -er '.state' "$backup/estate/TRANSACTION.json")
  if [[ "$transaction_state" == "restored" ]]; then
    verify_estate_disposition preimage
  else
    [[ "$transaction_state" == "applied" ]] || \
      holdfast_die "estate transaction has an unknown rollback phase: $transaction_state"
    verify_estate_disposition mixed
    run_python_tool "$estate_transaction" "$script_dir/estate_transaction.py" restore \
      --estate-root "$estate_root" --backup-dir "$backup/estate"
    require_root_file "$backup/estate/TRANSACTION.json"
    [[ "$(jq -er '.schema_version == 1 and .state == "restored"' \
      "$backup/estate/TRANSACTION.json")" == "true" ]] || \
      holdfast_die "estate rollback did not record restored state"
    verify_estate_disposition preimage
    if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
      "${HOLDFAST_TEST_SIGKILL_AFTER_ESTATE_RESTORE:-0}" == "1" ]]; then
      kill -KILL "$$"
    fi
  fi
  persist_estate_restore_phase
fi

if [[ "$current_state" == "rollback_estate_restore_done" || \
  "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_estate_restore_phase_receipt
  validate_phase_state_binding rollback_estate_restore_phase_receipt \
    rollback_estate_restore_phase_receipt_sha256 "$estate_phase_name" "$estate_phase_sha"
  [[ "$(jq -er '.rollback_estate_transaction_sha256' "$state_file")" == \
    "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")" ]] || \
    holdfast_die "rollback state restored-transaction identity differs"
  verify_estate_disposition preimage
fi

if [[ "$current_state" == "rollback_estate_restore_done" ]]; then
  load_exact_restart_authority
  if ((${#restart_services[@]})); then
    "${rollback_compose[@]}" up -d --no-build --wait --wait-timeout 300 --no-deps \
      "${restart_services[@]}"
  fi
  verify_restarted_and_excluded_services
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
    "${HOLDFAST_TEST_SIGKILL_AFTER_SERVICE_REACTIVATION:-0}" == "1" ]]; then
    kill -KILL "$$"
  fi
  persist_services_reactivated_phase
fi

if [[ "$current_state" == "rollback_services_reactivated_done" || \
  "$current_state" == "rolled_back" ]]; then
  validate_services_reactivated_phase_receipt
  validate_phase_state_binding rollback_services_reactivated_phase_receipt \
    rollback_services_reactivated_phase_receipt_sha256 "$services_phase_name" "$services_phase_sha"
fi
verify_closed_bracket

reactivated_services="$expected_reactivated_services"
rollback_receipt_tmp="$backup/.ROLLBACK.receipt.$$"
{
  printf 'schema_version=2\n'
  printf 'rolled_back_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'rollback_armed_receipt_sha256=%s\n' "$rollback_armed_sha"
  printf 'running_services_sha256=%s\n' "$rollback_manifest_sha"
  printf 'runtime_prior_services_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RUNNING-SERVICES.before")"
  printf 'runtime_restore_phase_receipt_sha256=%s\n' "$runtime_phase_sha"
  printf 'estate_restore_phase_receipt_sha256=%s\n' "$estate_phase_sha"
  printf 'services_reactivated_phase_receipt_sha256=%s\n' "$services_phase_sha"
  printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
  printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
  printf 'runtime_restore_receipt_sha256=%s\n' "$(holdfast_sha256 "$backup/runtime/RESTORE.receipt")"
  printf 'estate_transaction_sha256=%s\n' "$(holdfast_sha256 "$backup/estate/TRANSACTION.json")"
  printf 'runtime_restore=passed\n'
  printf 'mixed_estate_restore=passed\n'
  printf 'orphan_cleanup=passed\n'
  printf 'service_reactivation=passed\n'
  printf 'reactivated_services=%s\n' "$reactivated_services"
  printf 'excluded_services_inactive=passed\n'
  printf 'activation_policy=restore-exact-prior-running\n'
  printf 'activate_services_requested=%s\n' "$activation_requested"
  printf 'public_route_state=dual-stack-404\n'
  printf 'ingress_opened=false\n'
} >"$rollback_receipt_tmp"
commit_atomic_file "$rollback_receipt_tmp" "$rollback_receipt"
if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && \
  "${HOLDFAST_TEST_SIGKILL_AFTER_ROLLBACK_RECEIPT:-0}" == "1" ]]; then
  kill -KILL "$$"
fi
validate_completed_rollback_receipt "$rollback_receipt"
finalize_rollback_state "$rollback_receipt"
echo "checksum-bound estate and runtime were restored; ingress remains closed"
