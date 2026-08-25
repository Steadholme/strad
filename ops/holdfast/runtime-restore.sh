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
restore_receipt_tmp=""
cleanup_restore_temps() {
  rm -f -- "$current_config_temp"
  if [[ -n "$restore_receipt_tmp" ]]; then rm -f -- "$restore_receipt_tmp"; fi
}
trap cleanup_restore_temps EXIT
"${compose_source[@]}" config --format json >"$current_config_temp"
[[ "$(validate_strad_database_contract "$current_config_temp")" == "postgres:5432/strad" ]] || \
  holdfast_die "live Strad database identity differs"
python3 - "$current_config_temp" "$backup/compose-config.json" <<'PY'
import json
import sys
from pathlib import Path


def load(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


if load(sys.argv[1]) != load(sys.argv[2]):
    raise SystemExit("runtime restore resolved Compose differs from frozen authority")
PY
# Bind every mutation to the checksum-protected frozen document after proving
# that the caller's final resolve is semantically identical to it.
compose=("$docker_bin" compose -f "$backup/compose-config.json")
frozen_postgres_config_hash_output=$("${compose[@]}" config --hash postgres) || \
  holdfast_die "could not resolve the frozen PostgreSQL Compose config hash"
[[ "$frozen_postgres_config_hash_output" != *$'\n'* && \
  "$frozen_postgres_config_hash_output" != *$'\r'* && \
  "$frozen_postgres_config_hash_output" =~ ^postgres[[:space:]]([0-9a-f]{64})$ ]] || \
  holdfast_die "frozen PostgreSQL Compose config hash is invalid"
frozen_postgres_config_hash=${BASH_REMATCH[1]}
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

postgres_container_attestation="not-run"
postgres_pgdata_mount="not-run"
attested_postgres_id=""
attested_postgres_project=""
attested_postgres_config_hash=""
attested_postgres_started_at=""
attested_postgres_restart_count=""
validate_postgres_runtime_authority() {
  local frozen_config="$backup/compose-config.json"
  local compose_project frozen_image_ref frozen_image_id container_output container_id
  local container_status container_image_ref container_image_id container_config_hash
  local container_started_at container_restart_count
  local -a postgres_containers=() pgdata_contract=()

  compose_project=$(jq -er '.name' "$frozen_config")
  [[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || \
    holdfast_die "frozen PostgreSQL Compose project is unsafe"
  frozen_image_ref=$(jq -er '.services.postgres.image' "$frozen_config")
  [[ "$frozen_image_ref" =~ @sha256:[0-9a-f]{64}$ ]] || \
    holdfast_die "frozen PostgreSQL image reference is not immutable"
  frozen_image_id=$("$docker_bin" image inspect --format '{{.Id}}' "$frozen_image_ref") || \
    holdfast_die "could not resolve the frozen PostgreSQL image ID"
  [[ "$frozen_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    holdfast_die "frozen PostgreSQL image ID is invalid"

  container_output=$("$docker_bin" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter 'label=com.docker.compose.service=postgres') || \
    holdfast_die "could not enumerate the PostgreSQL runtime authority"
  if [[ -n "$container_output" ]]; then mapfile -t postgres_containers <<<"$container_output"; fi
  ((${#postgres_containers[@]} == 1)) || \
    holdfast_die "restore requires exactly one PostgreSQL container"
  container_id=${postgres_containers[0]}
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "PostgreSQL container identity is unsafe"

  container_status=$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container state"
  [[ "$container_status" == "running" ]] || \
    holdfast_die "PostgreSQL container is not running"
  container_started_at=$("$docker_bin" inspect -f '{{.State.StartedAt}}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container start epoch"
  [[ "$container_started_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$ ]] || \
    holdfast_die "PostgreSQL container start epoch is invalid"
  container_restart_count=$("$docker_bin" inspect -f '{{.RestartCount}}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container restart count"
  [[ "$container_restart_count" =~ ^(0|[1-9][0-9]*)$ ]] || \
    holdfast_die "PostgreSQL container restart count is invalid"
  container_config_hash=$("$docker_bin" inspect -f \
    '{{ index .Config.Labels "com.docker.compose.config-hash" }}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container Compose config hash"
  [[ "$container_config_hash" =~ ^[0-9a-f]{64}$ ]] || \
    holdfast_die "PostgreSQL container Compose config hash is missing or invalid"
  [[ "$container_config_hash" == "$frozen_postgres_config_hash" ]] || \
    holdfast_die "PostgreSQL container Compose config hash differs from frozen authority"
  container_image_ref=$("$docker_bin" inspect -f '{{.Config.Image}}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container image reference"
  [[ "$container_image_ref" == "$frozen_image_ref" ]] || \
    holdfast_die "PostgreSQL container image reference differs from frozen authority"
  container_image_id=$("$docker_bin" inspect -f '{{.Image}}' "$container_id") || \
    holdfast_die "could not inspect PostgreSQL container image ID"
  [[ "$container_image_id" == "$frozen_image_id" ]] || \
    holdfast_die "PostgreSQL container image ID differs from frozen authority"

  mapfile -t pgdata_contract < <(python3 - "$frozen_config" \
    <("$docker_bin" image inspect --format '{{json .Config.Env}}' "$frozen_image_ref") <<'PY'
import json
import posixpath
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"runtime PostgreSQL contract: {message}")


def canonical_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{label} must be an absolute path")
    normalized = posixpath.normpath(value)
    if normalized != value or any(ord(character) < 32 for character in value):
        fail(f"{label} must be canonical")
    return value


def env_value(values: object, label: str) -> str | None:
    if values is None:
        values = []
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        fail(f"{label} environment is malformed")
    matches = [item.split("=", 1)[1] for item in values if item.startswith("PGDATA=")]
    if len(matches) > 1:
        fail(f"{label} environment repeats PGDATA")
    return matches[0] if matches else None


def overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
image_environment = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
project = document.get("name")
services = document.get("services")
volumes = document.get("volumes")
if not isinstance(project, str) or not isinstance(services, dict) or not isinstance(volumes, dict):
    fail("frozen Compose document is malformed")
postgres = services.get("postgres")
mounts = postgres.get("volumes") if isinstance(postgres, dict) else None
if not isinstance(mounts, list):
    fail("frozen PostgreSQL service lacks a volume contract")
environment = postgres.get("environment") if isinstance(postgres, dict) else None
if not isinstance(environment, dict):
    fail("frozen PostgreSQL environment is malformed")
compose_pgdata = environment.get("PGDATA")
if compose_pgdata is not None:
    expected_pgdata = canonical_path(compose_pgdata, "frozen PostgreSQL PGDATA")
else:
    image_pgdata = env_value(image_environment, "immutable image")
    if image_pgdata is None:
        fail("immutable image environment lacks PGDATA")
    expected_pgdata = canonical_path(image_pgdata, "immutable image PGDATA")

normalized_mounts: list[tuple[dict[str, object], str]] = []
for mount in mounts:
    if not isinstance(mount, dict):
        fail("frozen PostgreSQL mount is malformed")
    target = canonical_path(mount.get("target"), "frozen PostgreSQL mount target")
    normalized_mounts.append((mount, target))
matches = [
    (mount, target)
    for mount, target in normalized_mounts
    if mount.get("source") == "pgdata"
    and mount.get("type") == "volume"
    and mount.get("read_only", False) is False
    and (target == expected_pgdata or expected_pgdata.startswith(target + "/"))
]
if len(matches) != 1:
    fail("expected exactly one writable pgdata volume covering PGDATA")
mount, expected_target = matches[0]
for candidate, target in normalized_mounts:
    if candidate is not mount and overlaps(target, expected_pgdata):
        fail("frozen PostgreSQL mount overlaps PGDATA")
definition = volumes.get("pgdata")
if not isinstance(definition, dict):
    fail("frozen Compose lacks the pgdata named volume")
actual = definition.get("name", f"{project}_pgdata")
if not isinstance(actual, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", actual) is None:
    fail("frozen pgdata physical volume identity is unsafe")
print(actual)
print(expected_target)
print(expected_pgdata)
PY
  )
  ((${#pgdata_contract[@]} == 3)) || \
    holdfast_die "frozen PostgreSQL pgdata contract is incomplete"
  python3 - "${pgdata_contract[0]}" "${pgdata_contract[1]}" \
    "${pgdata_contract[2]}" \
    <("$docker_bin" inspect -f '{{json .Config.Env}}' "$container_id") \
    <("$docker_bin" inspect -f '{{json .Mounts}}' "$container_id") <<'PY'
import json
import posixpath
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"runtime PostgreSQL mount: {message}")


def canonical_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{label} must be an absolute path")
    normalized = posixpath.normpath(value)
    if normalized != value or any(ord(character) < 32 for character in value):
        fail(f"{label} must be canonical")
    return value


def overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


expected_source, expected_target, expected_pgdata = sys.argv[1:4]
container_environment = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
mounts = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
if container_environment is None:
    container_environment = []
if not isinstance(container_environment, list) or not all(
    isinstance(item, str) for item in container_environment
):
    fail("container environment inspection is malformed")
pgdata_values = [
    item.split("=", 1)[1]
    for item in container_environment
    if item.startswith("PGDATA=")
]
if len(pgdata_values) != 1:
    fail("container environment must contain exactly one PGDATA")
actual_pgdata = canonical_path(pgdata_values[0], "container PGDATA")
if actual_pgdata != expected_pgdata:
    fail("container PGDATA differs from frozen authority")
if not isinstance(mounts, list):
    fail("container mount inspection is not a list")
normalized_mounts = []
for mount in mounts:
    if not isinstance(mount, dict):
        fail("container mount inspection contains a malformed entry")
    target = canonical_path(mount.get("Destination"), "container mount target")
    normalized_mounts.append((mount, target))
source_mounts = [
    (mount, target)
    for mount, target in normalized_mounts
    if mount.get("Name") == expected_source
]
if len(source_mounts) != 1:
    fail("expected exactly one pgdata named-volume source")
mount, target = source_mounts[0]
if (
    mount.get("Type") != "volume"
    or target != expected_target
    or mount.get("RW") is not True
):
    fail("pgdata source, target, type, or RW disposition differs")
overlapping = [
    mount
    for mount, target in normalized_mounts
    if mount is not source_mounts[0][0] and overlaps(target, expected_pgdata)
]
if overlapping:
    fail("an additional container mount overlaps PGDATA")
PY
  if [[ -n "$attested_postgres_id" ]] && \
    [[ "$container_id" != "$attested_postgres_id" || \
      "$container_config_hash" != "$attested_postgres_config_hash" || \
      "$container_started_at" != "$attested_postgres_started_at" || \
      "$container_restart_count" != "$attested_postgres_restart_count" ]]; then
    holdfast_die "PostgreSQL container epoch changed between attestations"
  fi
  attested_postgres_id="$container_id"
  attested_postgres_project="$compose_project"
  attested_postgres_config_hash="$container_config_hash"
  attested_postgres_started_at="$container_started_at"
  attested_postgres_restart_count="$container_restart_count"
  postgres_container_attestation="passed"
  postgres_pgdata_mount="passed"
}

require_attested_postgres_identity() {
  local container_output container_status container_config_hash
  local container_started_at container_restart_count
  local -a postgres_containers=()
  [[ -n "$attested_postgres_id" && -n "$attested_postgres_project" ]] || \
    holdfast_die "PostgreSQL container has not been attested"
  container_output=$("$docker_bin" ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$attested_postgres_project" \
    --filter 'label=com.docker.compose.service=postgres') || \
    holdfast_die "could not re-enumerate the attested PostgreSQL container"
  if [[ -n "$container_output" ]]; then mapfile -t postgres_containers <<<"$container_output"; fi
  ((${#postgres_containers[@]} == 1)) || \
    holdfast_die "attested PostgreSQL container set changed"
  [[ "${postgres_containers[0]}" == "$attested_postgres_id" ]] || \
    holdfast_die "attested PostgreSQL container identity changed"
  container_status=$("$docker_bin" inspect -f '{{.State.Status}}' "$attested_postgres_id") || \
    holdfast_die "attested PostgreSQL container disappeared"
  [[ "$container_status" == "running" ]] || \
    holdfast_die "attested PostgreSQL container is not running"
  container_started_at=$("$docker_bin" inspect -f '{{.State.StartedAt}}' \
    "$attested_postgres_id") || holdfast_die "attested PostgreSQL container disappeared"
  container_restart_count=$("$docker_bin" inspect -f '{{.RestartCount}}' \
    "$attested_postgres_id") || holdfast_die "attested PostgreSQL container disappeared"
  container_config_hash=$("$docker_bin" inspect -f \
    '{{ index .Config.Labels "com.docker.compose.config-hash" }}' \
    "$attested_postgres_id") || holdfast_die "attested PostgreSQL container disappeared"
  [[ "$container_started_at" == "$attested_postgres_started_at" && \
    "$container_restart_count" == "$attested_postgres_restart_count" && \
    "$container_config_hash" == "$attested_postgres_config_hash" && \
    "$container_config_hash" == "$frozen_postgres_config_hash" ]] || \
    holdfast_die "attested PostgreSQL container epoch changed"
}

attested_postgres_exec() {
  require_attested_postgres_identity
  "$docker_bin" exec -i "$attested_postgres_id" "$@"
}

# No writer stop, database command, or volume mutation may precede this proof.
validate_postgres_runtime_authority

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

# Re-attest after writer removal and holder proof, immediately before the
# first database command or volume replacement can cross the destructive gate.
validate_postgres_runtime_authority

strad_connection_count() {
  local observed
  # The variable is expanded by the shell inside the PostgreSQL container.
  # shellcheck disable=SC2016
  observed=$(attested_postgres_exec sh -ceu \
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
  database_exists=$(attested_postgres_exec sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d postgres -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_database WHERE datname = 'strad';
SQL
  ) || holdfast_die "could not prove the legacy Strad database identity"
  [[ "$database_exists" == "1" ]] || holdfast_die "legacy recovery requires one existing Strad database"
  # shellcheck disable=SC2016
  legacy_public_tables=$(attested_postgres_exec sh -ceu \
    'exec psql -U "$POSTGRES_USER" -d strad -XAtq -v ON_ERROR_STOP=1' <<'SQL'
SELECT count(*) FROM pg_tables WHERE schemaname = 'public';
SQL
  ) || holdfast_die "could not prove the legacy Strad public schema is empty"
  [[ "$legacy_public_tables" == "0" ]] || holdfast_die "legacy Strad database contains public tables"
  # shellcheck disable=SC2016
  legacy_user_relations=$(attested_postgres_exec sh -ceu \
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
  attested_postgres_exec sh -ceu \
    'dropdb --if-exists --maintenance-db postgres -U "$POSTGRES_USER" strad;
createdb -T template0 -U "$POSTGRES_USER" strad;
exec pg_restore -U "$POSTGRES_USER" -d strad --exit-on-error --no-owner --no-acl' \
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
  printf 'postgres_container_attestation=%s\n' "$postgres_container_attestation"
  printf 'postgres_pgdata_mount=%s\n' "$postgres_pgdata_mount"
  printf 'postgres_runtime_epoch_attestation=passed\n'
  printf 'postgres_container_id=%s\n' "$attested_postgres_id"
  printf 'postgres_config_hash=%s\n' "$attested_postgres_config_hash"
  printf 'postgres_started_at=%s\n' "$attested_postgres_started_at"
  printf 'postgres_restart_count=%s\n' "$attested_postgres_restart_count"
  printf 'volume_mount_release=passed\n'
  printf 'volume_count=6\n'
} >"$restore_receipt_tmp"
chmod 0600 "$restore_receipt_tmp"
# Publish no success evidence if the fixed PostgreSQL runtime epoch changed
# after the final database command or while the receipt was being prepared.
require_attested_postgres_identity
mv -fT -- "$restore_receipt_tmp" "$restore_receipt"
restore_receipt_tmp=""
sync -f "$restore_receipt"
echo "Strad database disposition and six volumes restored; runtime writers remain removed"
