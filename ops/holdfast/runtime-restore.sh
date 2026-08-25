#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --compose-root PATH --backup-dir PATH [--legacy-empty-strad]" >&2
  exit 2
}

execute="false"
legacy_empty_strad="false"
compose_root=""
backup=""
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --legacy-empty-strad) legacy_empty_strad="true"; shift ;;
    --compose-root) [[ $# -ge 2 ]] || usage; compose_root=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && -n "$compose_root" && -n "$backup" ]] || usage
[[ $EUID -eq 0 ]] || { echo "runtime restore requires root" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
# shellcheck disable=SC1091
source "$script_dir/common.sh"
holdfast_require_absolute "$compose_root"
holdfast_require_absolute "$backup"

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

validate_running_manifest() {
  local manifest=$1 previous=-1 service index found
  local allowed=(strad rikune-analyzer)
  while IFS= read -r service; do
    [[ -n "$service" ]] || holdfast_die "running-service manifest contains an empty entry"
    found=-1
    for index in "${!allowed[@]}"; do
      if [[ "${allowed[$index]}" == "$service" ]]; then found=$index; break; fi
    done
    ((found >= 0)) || holdfast_die "running-service manifest contains an unknown service: $service"
    ((found > previous)) || holdfast_die "running-service manifest is duplicated or out of order"
    previous=$found
  done <"$manifest"
}

acquire_or_adopt_holdfast_lock
require_canonical_root_dir "$backup"
[[ -z "$(find "$backup" -xdev -type l -print -quit)" ]] || holdfast_die "runtime backup contains a symlink"
[[ -z "$(find "$backup" -xdev ! -user root -print -quit)" ]] || holdfast_die "runtime backup contains a non-root-owned entry"
[[ -z "$(find "$backup" -xdev ! -type d ! -type f -print -quit)" ]] || holdfast_die "runtime backup contains a special file"
for file in "$backup/BACKUP.receipt" "$backup/SHA256SUMS" "$backup/VOLUMES.tsv" \
  "$backup/compose-config.json"; do
  require_root_file "$file"
done

backup_schema=$(holdfast_receipt_value "$backup/BACKUP.receipt" schema_version)
if [[ "$legacy_empty_strad" == "true" ]]; then
  [[ "$backup_schema" == "1" ]] || holdfast_die "--legacy-empty-strad accepts only a schema-v1 backup"
  require_root_file "$backup/postgres.dump"
  for expected in "postgres_dump=pg_dump_custom" "volume_count=6"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v1 runtime backup contract differs: $key"
  done
else
  [[ "$backup_schema" == "2" ]] || \
    holdfast_die "schema-v1 runtime backup requires the explicit --legacy-empty-strad gate"
  require_root_file "$backup/strad.dump"
  require_root_file "$backup/RUNTIME-BACKUP-ARMED.receipt"
  for expected in \
    "postgres_dump=pg_dump_custom" "database_count=1" \
    "postgres_database=strad" "database_host=postgres" \
    "database_port=5432" "database_identity=postgres:5432/strad" \
    "database_connections_before_dump=0" "database_connections_after_dump=0" \
    "runtime_writer_count=3" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "runtime_writers_stopped=passed" "writers_left_quiesced=passed" \
    "runtime_backup_armed_receipt=RUNTIME-BACKUP-ARMED.receipt" "volume_count=6"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" "$key")" == "$value" ]] || \
      holdfast_die "schema-v2 runtime backup contract differs: $key"
  done
  [[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" prior_running_services_manifest)" == \
    "RUNNING-SERVICES.before" ]] || holdfast_die "runtime backup prior-running manifest name differs"
  require_root_file "$backup/RUNNING-SERVICES.before"
  validate_running_manifest "$backup/RUNNING-SERVICES.before"
  [[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" prior_running_services_sha256)" == \
    "$(holdfast_sha256 "$backup/RUNNING-SERVICES.before")" ]] || \
    holdfast_die "runtime backup prior-running manifest hash differs"
  [[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" runtime_backup_armed_sha256)" == \
    "$(holdfast_sha256 "$backup/RUNTIME-BACKUP-ARMED.receipt")" ]] || \
    holdfast_die "runtime backup stop authority hash differs"
  for expected in \
    "schema_version=2" "backup_dir=$backup" \
    "compose_project=$(jq -er '.name' "$backup/compose-config.json")" \
    "compose_config_sha256=$(holdfast_sha256 "$backup/compose-config.json")" \
    "database_identity=postgres:5432/strad" \
    "prior_running_services_manifest=RUNNING-SERVICES.before" \
    "prior_running_services_sha256=$(holdfast_sha256 "$backup/RUNNING-SERVICES.before")" \
    "runtime_writer_count=3" \
    "runtime_writers=strad,rikune-analyzer,rikune-volume-init" \
    "stop_authority=armed-before-writer-stop"; do
    key=${expected%%=*}
    value=${expected#*=}
    [[ "$(holdfast_receipt_value "$backup/RUNTIME-BACKUP-ARMED.receipt" "$key")" == "$value" ]] || \
      holdfast_die "runtime backup stop authority differs: $key"
  done
  init_prior_state=$(holdfast_receipt_value "$backup/RUNTIME-BACKUP-ARMED.receipt" volume_init_prior_state)
  [[ "$init_prior_state" == "absent" || "$init_prior_state" == "created" || \
    "$init_prior_state" == "exited" || "$init_prior_state" == "dead" ]] || \
    holdfast_die "runtime backup stop authority has an active volume initializer"
fi
[[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
  holdfast_die "runtime backup lacks a passed isolated restore probe"

expected_volumes=(strad_uploads rikune_workspaces rikune_storage rikune_state rikune_cache rikune_audit)
mapfile -t observed_volumes < <(cut -f1 "$backup/VOLUMES.tsv")
[[ "${observed_volumes[*]}" == "${expected_volumes[*]}" ]] || \
  holdfast_die "runtime backup volume set or order differs from the frozen six-volume contract"
declare -A observed_actuals=()
expected_checksum_files=(VOLUMES.tsv compose-config.json)
if [[ "$legacy_empty_strad" == "true" ]]; then
  expected_checksum_files+=(postgres.dump)
else
  expected_checksum_files+=(RUNNING-SERVICES.before RUNTIME-BACKUP-ARMED.receipt strad.dump)
fi
while IFS=$'\t' read -r logical state actual extra; do
  [[ -z "${extra:-}" && "$actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
    holdfast_die "unsafe runtime volume disposition"
  [[ "$state" == "absent" || "$state" == "present" ]] || holdfast_die "invalid volume disposition"
  [[ -z "${observed_actuals[$actual]:-}" ]] || holdfast_die "runtime backup repeats a physical volume"
  observed_actuals[$actual]=$logical
  if [[ "$legacy_empty_strad" == "true" && "$state" != "absent" ]]; then
    holdfast_die "legacy empty-Strad recovery requires six expected-absent volumes"
  fi
  if [[ "$state" == "present" ]]; then
    require_root_file "$backup/$logical.tar"
    expected_checksum_files+=("$logical.tar")
  elif [[ -e "$backup/$logical.tar" || -L "$backup/$logical.tar" ]]; then
    holdfast_die "absent runtime volume has an unexpected archive: $logical"
  fi
done <"$backup/VOLUMES.tsv"

declared_checksum_files=()
declare -A declared_checksum_seen=()
while IFS= read -r checksum_line; do
  [[ "$checksum_line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]] || \
    holdfast_die "runtime SHA256SUMS contains an invalid line"
  checksum_file=${BASH_REMATCH[1]}
  [[ -z "${declared_checksum_seen[$checksum_file]:-}" ]] || \
    holdfast_die "runtime SHA256SUMS repeats a file: $checksum_file"
  declared_checksum_seen[$checksum_file]=1
  declared_checksum_files+=("$checksum_file")
done <"$backup/SHA256SUMS"
mapfile -t expected_checksum_files_sorted < <(printf '%s\n' "${expected_checksum_files[@]}" | sort)
mapfile -t declared_checksum_files_sorted < <(printf '%s\n' "${declared_checksum_files[@]}" | sort)
[[ "${declared_checksum_files_sorted[*]}" == "${expected_checksum_files_sorted[*]}" ]] || \
  holdfast_die "runtime SHA256SUMS file set differs from the backup contract"
(cd "$backup" && sha256sum --check SHA256SUMS)
[[ "$(validate_strad_database_contract "$backup/compose-config.json")" == "postgres:5432/strad" ]] || \
  holdfast_die "frozen Strad database identity differs"

docker_bin=docker
if [[ -n "${HOLDFAST_DOCKER_BIN:-}" ]]; then
  [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "Docker command override is test-only"
  docker_bin=$HOLDFAST_DOCKER_BIN
fi
compose_source=("$docker_bin" compose --env-file "$compose_root/deploy/.env" -f "$compose_root/deploy/docker-compose.yml")
umask 077
current_config_temp=$(mktemp "${TMPDIR:-/var/tmp}/holdfast-runtime-restore-compose.XXXXXX")
cleanup_current_config() { rm -f -- "$current_config_temp"; }
trap cleanup_current_config EXIT
"${compose_source[@]}" config --format json >"$current_config_temp"
[[ "$(validate_strad_database_contract "$current_config_temp")" == "postgres:5432/strad" ]] || \
  holdfast_die "live Strad database identity differs"
# Bind every mutation to the protected resolved document that passed validation.
compose=("$docker_bin" compose -f "$current_config_temp")
volume_image=$(jq -er '.services["rikune-volume-init"].image' "$backup/compose-config.json")
[[ "$volume_image" =~ @sha256:[0-9a-f]{64}$ ]] || holdfast_die "volume restore image is not immutable"

for logical in "${expected_volumes[@]}"; do
  frozen_actual=$(jq -er --arg logical "$logical" \
    '.volumes[$logical].name // (.name + "_" + $logical)' "$backup/compose-config.json")
  live_actual=$(jq -er --arg logical "$logical" \
    '.volumes[$logical].name // (.name + "_" + $logical)' "$current_config_temp")
  [[ "$frozen_actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ && "$live_actual" == "$frozen_actual" ]] || \
    holdfast_die "frozen/live runtime volume identity differs: $logical"
  [[ "${observed_actuals[$frozen_actual]:-}" == "$logical" ]] || \
    holdfast_die "runtime backup physical volume identity differs: $logical"
done

# Stop and remove every container that can own Strad or Rikune persistent state.
runtime_writers=(strad rikune-analyzer rikune-volume-init)
"${compose[@]}" stop -t 120 "${runtime_writers[@]}"
for service in "${runtime_writers[@]}"; do
  writer_output=$("${compose[@]}" ps -aq "$service") || \
    holdfast_die "could not inspect runtime writer after stop: $service"
  writer_ids=()
  if [[ -n "$writer_output" ]]; then mapfile -t writer_ids <<<"$writer_output"; fi
  for container_id in "${writer_ids[@]}"; do
    writer_state=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")
    [[ "$writer_state" != "running" && "$writer_state" != "restarting" && "$writer_state" != "paused" ]] || \
      holdfast_die "runtime writer remains active after stop: $service"
  done
done
"${compose[@]}" rm -f -s "${runtime_writers[@]}"
for service in "${runtime_writers[@]}"; do
  orphan_output=$("${compose[@]}" ps -aq "$service") || \
    holdfast_die "could not prove runtime writer removal: $service"
  [[ -z "$orphan_output" ]] || holdfast_die "runtime writer container remains after cleanup: $service"
done

while IFS=$'\t' read -r logical state actual; do
  holder_output=$("$docker_bin" ps -aq --filter "volume=$actual") || \
    holdfast_die "could not inspect volume holders: $actual"
  [[ -z "$holder_output" ]] || holdfast_die "a container still holds runtime volume: $actual"
done <"$backup/VOLUMES.tsv"

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
[[ "$connections_before" == "0" ]] || holdfast_die "another client remains connected to the Strad database"

legacy_public_tables="not-applicable"
legacy_user_relations="not-applicable"
database_restore="restored"
if [[ "$legacy_empty_strad" == "true" ]]; then
  # The variable is expanded by the shell inside the PostgreSQL container.
  # shellcheck disable=SC2016
  database_exists=$("${compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d postgres -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_database WHERE datname = 'strad';
SQL
  ) || holdfast_die "could not prove the legacy Strad database identity"
  [[ "$database_exists" == "1" ]] || holdfast_die "legacy recovery requires one existing Strad database"
  # shellcheck disable=SC2016
  legacy_public_tables=$("${compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d strad -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_tables WHERE schemaname = 'public';
SQL
  ) || holdfast_die "could not prove the legacy Strad public schema is empty"
  [[ "$legacy_public_tables" == "0" ]] || holdfast_die "legacy Strad database contains public tables"
  # shellcheck disable=SC2016
  legacy_user_relations=$("${compose[@]}" exec -T postgres sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d strad -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*)
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname !~ '^pg_toast'
   AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f');
SQL
  ) || holdfast_die "could not prove the legacy Strad database is empty"
  [[ "$legacy_user_relations" == "0" ]] || holdfast_die "legacy Strad database contains user relations"
  [[ "$(strad_connection_count)" == "0" ]] || \
    holdfast_die "a client connected during the legacy empty-Strad proof"
  database_restore="skipped_proven_empty"
fi

while IFS=$'\t' read -r logical state actual; do
  "$docker_bin" volume rm -f "$actual" >/dev/null 2>&1 || true
  if "$docker_bin" volume inspect "$actual" >/dev/null 2>&1; then
    holdfast_die "volume could not be removed before exact restore: $actual"
  fi
  if [[ "$state" == "absent" ]]; then continue; fi
  "$docker_bin" volume create "$actual" >/dev/null
  "$docker_bin" run --rm --network none \
    -v "$actual:/restore" -v "$backup:/backup:ro" "$volume_image" \
    /bin/sh -ceu "tar -C /restore -xf /backup/$logical.tar"
done <"$backup/VOLUMES.tsv"

if [[ "$legacy_empty_strad" != "true" ]]; then
  # These literal identities are the schema-v2 safety boundary.  Never use the
  # shared POSTGRES_DB or any Access/Verdict/NewAPI database here.
  # shellcheck disable=SC2016
  "${compose[@]}" exec -T postgres sh -ceu \
    'dropdb --if-exists --maintenance-db postgres -U "$POSTGRES_USER" strad; createdb -T template0 -U "$POSTGRES_USER" strad'
  # shellcheck disable=SC2016
  "${compose[@]}" exec -T postgres sh -ceu \
    'exec pg_restore -U "$POSTGRES_USER" -d strad --exit-on-error --no-owner --no-acl' \
    <"$backup/strad.dump"
  [[ "$(strad_connection_count)" == "0" ]] || \
    holdfast_die "a client connected to the Strad database during restore"
fi

restore_receipt="$backup/RESTORE.receipt"
restore_receipt_tmp="$backup/.RESTORE.receipt.$$"
[[ ! -L "$restore_receipt" && ! -e "$restore_receipt_tmp" && ! -L "$restore_receipt_tmp" ]] || \
  holdfast_die "unsafe runtime restore receipt path"
{
  printf 'schema_version=2\n'
  printf 'restored_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'restore_mode=%s\n' "$([[ "$legacy_empty_strad" == "true" ]] && printf legacy-empty-strad || printf schema-v2)"
  printf 'database_identity=postgres:5432/strad\n'
  printf 'database_restore=%s\n' "$database_restore"
  printf 'legacy_public_table_count=%s\n' "$legacy_public_tables"
  printf 'legacy_user_relation_count=%s\n' "$legacy_user_relations"
  printf 'database_connections_before_restore=0\n'
  printf 'runtime_writer_count=3\n'
  printf 'runtime_writers_removed=passed\n'
  printf 'volume_mount_release=passed\n'
  printf 'volume_count=6\n'
} >"$restore_receipt_tmp"
chmod 0600 "$restore_receipt_tmp"
mv -fT -- "$restore_receipt_tmp" "$restore_receipt"
sync -f "$restore_receipt"
echo "Strad database disposition and six volumes restored; runtime writers remain removed"
