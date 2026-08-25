#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --compose-root PATH --backup-dir NEW_PATH" >&2
  exit 2
}

compose_root=""
backup=""
while (($#)); do
  case "$1" in
    --compose-root) [[ $# -ge 2 ]] || usage; compose_root=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$compose_root" && -n "$backup" ]] || usage
[[ $EUID -eq 0 ]] || { echo "runtime backup requires root" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
# shellcheck disable=SC1091
source "$script_dir/common.sh"
holdfast_require_absolute "$compose_root"
holdfast_require_absolute "$backup"
[[ ! -e "$backup" && ! -L "$backup" ]] || holdfast_die "runtime backup already exists"

holdfast_lock_path() {
  local path=/run/lock/holdfast-rikune.lock
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && -n "${HOLDFAST_LOCK_PATH:-}" ]]; then
    path=$HOLDFAST_LOCK_PATH
  fi
  printf '%s\n' "$path"
}

acquire_or_adopt_holdfast_lock() {
  local expected observed=""
  expected=$(holdfast_lock_path)
  holdfast_require_absolute "$expected"
  if [[ -e "/proc/$$/fd/9" ]]; then
    observed=$(readlink -f -- "/proc/$$/fd/9" 2>/dev/null || true)
  fi
  if [[ "$observed" == "$expected" ]]; then
    flock -n 9 || holdfast_die "another Holdfast estate mutation is active"
    return
  fi
  holdfast_acquire_lock
}

validate_strad_database_contract() {
  local config_path=$1
  python3 - "$config_path" <<'PY'
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


def fail(message: str) -> None:
    raise SystemExit(f"runtime database contract: {message}")


def load(path: str) -> object:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def target(value: object) -> tuple[str, int, str] | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port if parsed.port is not None else 5432
    except ValueError:
        return None
    if parsed.scheme not in {"postgres", "postgresql"}:
        return None
    if parsed.query or parsed.fragment or parsed.hostname != "postgres" or port != 5432:
        return None
    if parsed.path != "/strad":
        return None
    return ("postgres", 5432, "strad")


document = load(sys.argv[1])
if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
    fail("resolved Compose document is malformed")
services = document["services"]
strad = services.get("strad")
if not isinstance(strad, dict) or not isinstance(strad.get("environment"), dict):
    fail("resolved Compose lacks the Strad environment")
if target(strad["environment"].get("STRAD_DATABASE_URL")) != ("postgres", 5432, "strad"):
    fail("STRAD_DATABASE_URL must resolve exactly to postgres:5432/strad")

owners: list[tuple[str, str]] = []
for service_name, service in services.items():
    if not isinstance(service, dict) or not isinstance(service.get("environment"), dict):
        continue
    for key, value in service["environment"].items():
        if target(value) == ("postgres", 5432, "strad"):
            owners.append((service_name, key))
if owners != [("strad", "STRAD_DATABASE_URL")]:
    fail(f"Strad database authority is not unique: {owners!r}")
print("postgres:5432/strad")
PY
}

acquire_or_adopt_holdfast_lock

docker_bin=docker
if [[ -n "${HOLDFAST_DOCKER_BIN:-}" ]]; then
  [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "Docker command override is test-only"
  docker_bin=$HOLDFAST_DOCKER_BIN
fi
compose_source=("$docker_bin" compose --env-file "$compose_root/deploy/.env" -f "$compose_root/deploy/docker-compose.yml")
umask 077
config_temp=$(mktemp "${TMPDIR:-/var/tmp}/holdfast-runtime-compose.XXXXXX")
cleanup_config_temp() { rm -f -- "$config_temp"; }
trap cleanup_config_temp EXIT
"${compose_source[@]}" config --format json >"$config_temp"
[[ "$(validate_strad_database_contract "$config_temp")" == "postgres:5432/strad" ]] || \
  holdfast_die "resolved Strad database identity differs"

mkdir -m 0700 -- "$backup"
config_json="$backup/compose-config.json"
install -o 0 -g 0 -m 0600 -- "$config_temp" "$config_json"
cleanup_config_temp
trap - EXIT
# Every subsequent Compose action uses this protected, resolved snapshot.  That
# keeps service, database and volume identities stable across the backup.
compose=("$docker_bin" compose -f "$config_json")
volume_image=$(jq -er '.services["rikune-volume-init"].image' "$config_json")
[[ "$volume_image" =~ @sha256:[0-9a-f]{64}$ ]] || holdfast_die "volume backup image is not immutable"

runtime_backup_complete="false"
runtime_stop_armed="false"
probe_volumes=()
pg_probe=""
pg_volume=""

commit_runtime_file() {
  local temporary=$1 target=$2
  [[ -f "$temporary" && ! -L "$temporary" ]] || holdfast_die "runtime atomic source is unsafe"
  chmod 0600 -- "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$target"
  sync -f "$target"
  sync -f "$backup"
}

cleanup_probe_volumes() {
  local item
  for item in "${probe_volumes[@]}"; do
    "$docker_bin" volume rm -f "$item" >/dev/null 2>&1 || true
  done
}

cleanup_pg_probe() {
  if [[ -n "$pg_probe" ]]; then "$docker_bin" rm -f "$pg_probe" >/dev/null 2>&1 || true; fi
  if [[ -n "$pg_volume" ]]; then "$docker_bin" volume rm -f "$pg_volume" >/dev/null 2>&1 || true; fi
}

runtime_service_in_prior_manifest() {
  local wanted=$1 service
  while IFS= read -r service; do
    [[ "$service" == "$wanted" ]] && return 0
  done <"$running_manifest"
  return 1
}

resume_prior_running_runtime() {
  local service output state health all_ready poll_seconds="5"
  local ids=() prior=()
  if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && -n "${HOLDFAST_TEST_HEALTH_POLL_SECONDS:-}" ]]; then
    poll_seconds=$HOLDFAST_TEST_HEALTH_POLL_SECONDS
    [[ "$poll_seconds" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  fi
  mapfile -t prior <"$running_manifest"
  # The one-shot initializer was never an allowed running preimage and must not
  # be activated by compensation.
  "${compose[@]}" stop -t 120 rikune-volume-init >/dev/null || return 1
  if ((${#prior[@]})); then "${compose[@]}" start "${prior[@]}" >/dev/null || return 1; fi
  all_ready="false"
  for _ in $(seq 1 60); do
    all_ready="true"
    for service in "${prior[@]}"; do
      output=$("${compose[@]}" ps -aq "$service") || return 1
      ids=()
      if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
      if ((${#ids[@]} != 1)); then
        all_ready="false"
        continue
      fi
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}") || return 1
      health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}") || return 1
      if [[ "$state" != "running" || ("$health" != "none" && "$health" != "healthy") ]]; then
        all_ready="false"
      fi
    done
    [[ "$all_ready" == "true" ]] && break
    sleep "$poll_seconds"
  done
  [[ "$all_ready" == "true" ]] || return 1
  for service in strad rikune-analyzer; do
    output=$("${compose[@]}" ps -aq "$service") || return 1
    ids=()
    if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
    ((${#ids[@]} <= 1)) || return 1
    if runtime_service_in_prior_manifest "$service"; then
      ((${#ids[@]} == 1)) || return 1
      state=$("$docker_bin" inspect -f '{{.State.Status}}' "${ids[0]}") || return 1
      [[ "$state" == "running" ]] || return 1
      health=$("$docker_bin" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${ids[0]}") || return 1
      [[ "$health" == "none" || "$health" == "healthy" ]] || return 1
    else
      for container_id in "${ids[@]}"; do
        state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id") || return 1
        [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || return 1
      done
    fi
  done
  output=$("${compose[@]}" ps -aq rikune-volume-init) || return 1
  ids=()
  if [[ -n "$output" ]]; then mapfile -t ids <<<"$output"; fi
  ((${#ids[@]} <= 1)) || return 1
  for container_id in "${ids[@]}"; do
    state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id") || return 1
    [[ "$state" != "running" && "$state" != "restarting" && "$state" != "paused" ]] || return 1
  done
}

record_runtime_compensation() {
  local original_status=$1 result=$2 receipt temporary
  receipt="$backup/RUNTIME-BACKUP-COMPENSATED.receipt"
  if [[ "$result" != "passed" ]]; then receipt="$backup/RUNTIME-BACKUP-COMPENSATION-FAILED.receipt"; fi
  temporary="$backup/.$(basename -- "$receipt").$$"
  [[ ! -e "$receipt" && ! -L "$receipt" && ! -e "$temporary" && ! -L "$temporary" ]] || return 1
  {
    printf 'schema_version=2\n'
    printf 'compensated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'original_status=%s\n' "$original_status"
    printf 'runtime_backup_armed_sha256=%s\n' "$(holdfast_sha256 "$runtime_armed_receipt")"
    printf 'prior_running_services_sha256=%s\n' "$(holdfast_sha256 "$running_manifest")"
    printf 'prior_running_services_restored=%s\n' "$result"
    printf 'excluded_runtime_services_inactive=%s\n' "$result"
    printf 'volume_init_inactive=%s\n' "$result"
  } >"$temporary"
  commit_runtime_file "$temporary" "$receipt"
}

runtime_backup_exit() {
  local status=$? compensation="failed"
  trap - EXIT HUP INT TERM
  set +e
  cleanup_pg_probe
  cleanup_probe_volumes
  if [[ "$runtime_stop_armed" == "true" && "$runtime_backup_complete" != "true" ]]; then
    if resume_prior_running_runtime; then compensation="passed"; fi
    record_runtime_compensation "$status" "$compensation" || true
    if [[ "$compensation" != "passed" ]]; then
      echo "holdfast: runtime backup compensation failed; stop authority remains at $runtime_armed_receipt" >&2
    fi
    [[ $status -ne 0 ]] || status=1
  fi
  exit "$status"
}

# The caller owns the wider seven-service lifecycle.  This layer freezes only
# the two long-running writers of Strad state; the one-shot volume initializer
# must already be inactive and is still stopped below as a defensive fence.
capturable_writers=(strad rikune-analyzer)
running_manifest="$backup/RUNNING-SERVICES.before"
: >"$running_manifest"
for service in "${capturable_writers[@]}"; do
  writer_output=$("${compose[@]}" ps -aq "$service") || \
    holdfast_die "could not inspect runtime writer before backup: $service"
  writer_ids=()
  if [[ -n "$writer_output" ]]; then mapfile -t writer_ids <<<"$writer_output"; fi
  ((${#writer_ids[@]} <= 1)) || holdfast_die "multiple containers exist for runtime writer: $service"
  if ((${#writer_ids[@]} == 1)); then
    writer_state=$("$docker_bin" inspect -f '{{.State.Status}}' "${writer_ids[0]}")
    case "$writer_state" in
      running) printf '%s\n' "$service" >>"$running_manifest" ;;
      created|exited|dead) ;;
      *) holdfast_die "runtime writer has an unstable pre-backup state: $service=$writer_state" ;;
    esac
  fi
done

init_output=$("${compose[@]}" ps -aq rikune-volume-init) || \
  holdfast_die "could not inspect runtime writer before backup: rikune-volume-init"
init_ids=()
if [[ -n "$init_output" ]]; then mapfile -t init_ids <<<"$init_output"; fi
((${#init_ids[@]} <= 1)) || holdfast_die "multiple containers exist for runtime writer: rikune-volume-init"
init_state="absent"
if ((${#init_ids[@]} == 1)); then
  init_state=$("$docker_bin" inspect -f '{{.State.Status}}' "${init_ids[0]}")
  [[ "$init_state" == "created" || "$init_state" == "exited" || "$init_state" == "dead" ]] || \
    holdfast_die "rikune-volume-init must finish before runtime backup: $init_state"
fi

# The stop receipt may outlive an abrupt caller death, so every authority it
# references must reach durable storage before the receipt authorizes stop.
chmod 0600 -- "$config_json" "$running_manifest"
sync -f "$config_json"
sync -f "$running_manifest"
sync -f "$backup"

compose_project=$(jq -er '.name' "$config_json")
[[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
  holdfast_die "runtime backup has an unsafe Compose project name"
runtime_armed_receipt="$backup/RUNTIME-BACKUP-ARMED.receipt"
runtime_armed_tmp="$backup/.RUNTIME-BACKUP-ARMED.receipt.$$"
{
  printf 'schema_version=2\n'
  printf 'armed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'backup_dir=%s\n' "$backup"
  printf 'compose_project=%s\n' "$compose_project"
  printf 'compose_config_sha256=%s\n' "$(holdfast_sha256 "$config_json")"
  printf 'database_identity=postgres:5432/strad\n'
  printf 'prior_running_services_manifest=RUNNING-SERVICES.before\n'
  printf 'prior_running_services_sha256=%s\n' "$(holdfast_sha256 "$running_manifest")"
  printf 'runtime_writer_count=3\n'
  printf 'runtime_writers=strad,rikune-analyzer,rikune-volume-init\n'
  printf 'stop_authority=armed-before-writer-stop\n'
  printf 'volume_init_prior_state=%s\n' "$init_state"
} >"$runtime_armed_tmp"
commit_runtime_file "$runtime_armed_tmp" "$runtime_armed_receipt"
runtime_stop_armed="true"
trap runtime_backup_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

runtime_writers=(strad rikune-analyzer rikune-volume-init)
"${compose[@]}" stop -t 120 "${runtime_writers[@]}"
for service in "${runtime_writers[@]}"; do
  writer_output=$("${compose[@]}" ps -aq "$service") || \
    holdfast_die "could not confirm runtime writer stop: $service"
  writer_ids=()
  if [[ -n "$writer_output" ]]; then mapfile -t writer_ids <<<"$writer_output"; fi
  for container_id in "${writer_ids[@]}"; do
    writer_state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
    [[ "$writer_state" != "running" && "$writer_state" != "restarting" && "$writer_state" != "paused" ]] || \
      holdfast_die "runtime writer remains active after stop: $service"
  done
done

if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && "${HOLDFAST_TEST_FAIL_AFTER_RUNTIME_STOP:-0}" == "1" ]]; then
  holdfast_die "injected failure after runtime writer stop"
fi
if [[ "${HOLDFAST_TEST_MODE:-0}" == "1" && "${HOLDFAST_TEST_SIGKILL_AFTER_RUNTIME_STOP:-0}" == "1" ]]; then
  kill -KILL "$$"
fi

strad_connection_count() {
  local observed
  # The variable is expanded by the shell inside the PostgreSQL container.
  # shellcheck disable=SC2016
  observed=$("${compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d postgres -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_stat_activity WHERE datname = 'strad';
SQL
  ) || holdfast_die "could not inspect Strad database connections"
  [[ "$observed" =~ ^[0-9]+$ ]] || holdfast_die "invalid Strad database connection count"
  printf '%s\n' "$observed"
}

connections_before=$(strad_connection_count)
[[ "$connections_before" == "0" ]] || \
  holdfast_die "another client remains connected to the Strad database"

# The quoted program is intentionally expanded inside the PostgreSQL container.
# shellcheck disable=SC2016
"${compose[@]}" exec -T postgres sh -ceu \
  'exec pg_dump -U "$POSTGRES_USER" -d strad -Fc' >"$backup/strad.dump"
[[ -s "$backup/strad.dump" ]] || holdfast_die "Strad PostgreSQL dump is empty"
connections_after=$(strad_connection_count)
[[ "$connections_after" == "0" ]] || \
  holdfast_die "a client connected to the Strad database during backup"

: >"$backup/VOLUMES.tsv"
volumes=(strad_uploads rikune_workspaces rikune_storage rikune_state rikune_cache rikune_audit)
declare -A physical_volumes=()
for logical in "${volumes[@]}"; do
  actual=$(jq -er --arg logical "$logical" \
    '.volumes[$logical].name // (.name + "_" + $logical)' "$config_json")
  [[ "$actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "unsafe volume identity: $logical"
  [[ -z "${physical_volumes[$actual]:-}" ]] || \
    holdfast_die "runtime volumes share one physical identity: $actual"
  physical_volumes[$actual]=$logical
  if ! "$docker_bin" volume inspect "$actual" >/dev/null 2>&1; then
    printf '%s\tabsent\t%s\n' "$logical" "$actual" >>"$backup/VOLUMES.tsv"
    continue
  fi
  archive="$logical.tar"
  "$docker_bin" run --rm --network none \
    -v "$actual:/source:ro" -v "$backup:/backup" "$volume_image" \
    /bin/sh -ceu "tar -C /source -cf /backup/$archive ."
  [[ -f "$backup/$archive" && ! -L "$backup/$archive" ]] || holdfast_die "volume archive failed: $logical"
  printf '%s\tpresent\t%s\n' "$logical" "$actual" >>"$backup/VOLUMES.tsv"
done

# Isolated volume restore probes use disposable, explicitly named Docker volumes.
while IFS=$'\t' read -r logical state actual; do
  [[ "$state" == "present" ]] || continue
  probe="holdfast_${logical}_restore_probe_$$"
  probe_volumes+=("$probe")
  "$docker_bin" volume create "$probe" >/dev/null
  "$docker_bin" run --rm --network none \
    -v "$probe:/restore" -v "$backup:/backup:ro" "$volume_image" \
    /bin/sh -ceu "tar -C /restore -xf /backup/$logical.tar"
done <"$backup/VOLUMES.tsv"

# Restore the Strad archive into an isolated disposable server, never a shared live database.
postgres_image=$(jq -er '.services.postgres.image' "$config_json")
[[ "$postgres_image" =~ @sha256:[0-9a-f]{64}$ ]] || holdfast_die "PostgreSQL image is not immutable"
pg_probe="holdfast-pg-restore-probe-$$"
pg_volume="holdfast_pg_restore_probe_$$"
"$docker_bin" volume create "$pg_volume" >/dev/null
"$docker_bin" run -d --name "$pg_probe" --network none \
  -e POSTGRES_HOST_AUTH_METHOD=trust -v "$pg_volume:/var/lib/postgresql" "$postgres_image" >/dev/null
ready="false"
for _ in $(seq 1 60); do
  if "$docker_bin" exec "$pg_probe" pg_isready -U postgres >/dev/null 2>&1; then
    ready="true"
    break
  fi
  sleep 1
done
[[ "$ready" == "true" ]] || holdfast_die "isolated PostgreSQL restore probe did not become ready"
"$docker_bin" cp "$backup/strad.dump" "$pg_probe:/tmp/strad.dump"
"$docker_bin" exec "$pg_probe" createdb -U postgres strad
"$docker_bin" exec "$pg_probe" pg_restore -U postgres -d strad \
  --exit-on-error --no-owner --no-acl /tmp/strad.dump
cleanup_pg_probe
cleanup_probe_volumes

checksum_files=(
  strad.dump VOLUMES.tsv compose-config.json RUNNING-SERVICES.before
  RUNTIME-BACKUP-ARMED.receipt
)
while IFS= read -r archive; do
  checksum_files+=("${archive#./}")
done < <(cd "$backup" && find . -maxdepth 1 -type f -name '*.tar' -print | sort)
checksum_temp="$backup/.SHA256SUMS.$$"
(cd "$backup" && sha256sum "${checksum_files[@]}") >"$checksum_temp"
commit_runtime_file "$checksum_temp" "$backup/SHA256SUMS"
receipt_temp="$backup/.BACKUP.receipt.$$"
{
  printf 'schema_version=2\n'
  printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'postgres_dump=pg_dump_custom\n'
  printf 'database_count=1\n'
  printf 'postgres_database=strad\n'
  printf 'database_host=postgres\n'
  printf 'database_port=5432\n'
  printf 'database_identity=postgres:5432/strad\n'
  printf 'database_connections_before_dump=0\n'
  printf 'database_connections_after_dump=0\n'
  printf 'runtime_writer_count=3\n'
  printf 'runtime_writers=strad,rikune-analyzer,rikune-volume-init\n'
  printf 'runtime_writers_stopped=passed\n'
  printf 'writers_left_quiesced=passed\n'
  printf 'prior_running_services_manifest=RUNNING-SERVICES.before\n'
  printf 'prior_running_services_sha256=%s\n' "$(holdfast_sha256 "$running_manifest")"
  printf 'runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt\n'
  printf 'runtime_backup_armed_sha256=%s\n' "$(holdfast_sha256 "$runtime_armed_receipt")"
  printf 'volume_count=6\n'
  printf 'isolated_restore_probe=passed\n'
} >"$receipt_temp"
commit_runtime_file "$receipt_temp" "$backup/BACKUP.receipt"
chmod 0600 "$backup"/*
for durable_file in "$backup"/*; do
  sync -f "$durable_file"
done
sync -f "$backup"
echo "Strad PostgreSQL and six-volume backup passed; Strad writers remain stopped: $backup"
runtime_backup_complete="true"
