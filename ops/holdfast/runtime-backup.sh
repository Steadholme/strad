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
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
holdfast_require_absolute "$compose_root"
holdfast_require_absolute "$backup"
[[ ! -e "$backup" && ! -L "$backup" ]] || holdfast_die "runtime backup already exists"

docker_bin=docker
if [[ -n "${HOLDFAST_DOCKER_BIN:-}" ]]; then
  [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "Docker command override is test-only"
  docker_bin=$HOLDFAST_DOCKER_BIN
fi
compose=("$docker_bin" compose --env-file "$compose_root/deploy/.env" -f "$compose_root/deploy/docker-compose.yml")
umask 077
mkdir -m 0700 -- "$backup"
config_json="$backup/compose-config.json"
"${compose[@]}" config --format json >"$config_json"
jq -e '.name | type == "string" and length > 0' "$config_json" >/dev/null
volume_image=$(jq -er '.services["rikune-volume-init"].image' "$config_json")
[[ "$volume_image" =~ @sha256:[0-9a-f]{64}$ ]] || holdfast_die "volume backup image is not immutable"

running_services=()
for service in strad rikune-analyzer; do
  container_id=$("${compose[@]}" ps -q "$service")
  if [[ -n "$container_id" && "$("$docker_bin" inspect -f '{{.State.Status}}' "$container_id")" == "running" ]]; then
    running_services+=("$service")
  fi
done
resume_services() {
  if ((${#running_services[@]})); then
    "${compose[@]}" start "${running_services[@]}" >/dev/null || true
  fi
}
trap resume_services EXIT
if ((${#running_services[@]})); then
  "${compose[@]}" stop -t 120 "${running_services[@]}"
fi

# The quoted program is intentionally expanded inside the PostgreSQL container.
# shellcheck disable=SC2016
"${compose[@]}" exec -T postgres sh -ceu \
  'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' >"$backup/postgres.dump"
[[ -s "$backup/postgres.dump" ]] || holdfast_die "PostgreSQL dump is empty"

: >"$backup/VOLUMES.tsv"
volumes=(strad_uploads rikune_workspaces rikune_storage rikune_state rikune_cache rikune_audit)
for logical in "${volumes[@]}"; do
  actual=$(jq -er --arg logical "$logical" \
    '.volumes[$logical].name // (.name + "_" + $logical)' "$config_json")
  [[ "$actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "unsafe volume identity: $logical"
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
probe_volumes=()
cleanup_probe_volumes() {
  local item
  for item in "${probe_volumes[@]}"; do
    "$docker_bin" volume rm -f "$item" >/dev/null 2>&1 || true
  done
}
trap 'cleanup_probe_volumes; resume_services' EXIT
while IFS=$'\t' read -r logical state actual; do
  [[ "$state" == "present" ]] || continue
  probe="holdfast_${logical}_restore_probe_$$"
  probe_volumes+=("$probe")
  "$docker_bin" volume create "$probe" >/dev/null
  "$docker_bin" run --rm --network none \
    -v "$probe:/restore" -v "$backup:/backup:ro" "$volume_image" \
    /bin/sh -ceu "tar -C /restore -xf /backup/$logical.tar"
done <"$backup/VOLUMES.tsv"

# Restore the PostgreSQL archive into an isolated disposable server, never the live database.
postgres_image=$(jq -er '.services.postgres.image' "$config_json")
[[ "$postgres_image" =~ @sha256:[0-9a-f]{64}$ ]] || holdfast_die "PostgreSQL image is not immutable"
pg_probe="holdfast-pg-restore-probe-$$"
pg_volume="holdfast_pg_restore_probe_$$"
cleanup_pg_probe() {
  "$docker_bin" rm -f "$pg_probe" >/dev/null 2>&1 || true
  "$docker_bin" volume rm -f "$pg_volume" >/dev/null 2>&1 || true
}
trap 'cleanup_pg_probe; cleanup_probe_volumes; resume_services' EXIT
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
"$docker_bin" cp "$backup/postgres.dump" "$pg_probe:/tmp/postgres.dump"
"$docker_bin" exec "$pg_probe" createdb -U postgres holdfast_restore_probe
"$docker_bin" exec "$pg_probe" pg_restore -U postgres -d holdfast_restore_probe \
  --exit-on-error --no-owner --no-acl /tmp/postgres.dump
cleanup_pg_probe
cleanup_probe_volumes
trap resume_services EXIT

checksum_files=(postgres.dump VOLUMES.tsv compose-config.json)
while IFS= read -r archive; do
  checksum_files+=("${archive#./}")
done < <(cd "$backup" && find . -maxdepth 1 -type f -name '*.tar' -print | sort)
(cd "$backup" && sha256sum "${checksum_files[@]}") >"$backup/SHA256SUMS"
{
  printf 'schema_version=1\n'
  printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'postgres_dump=pg_dump_custom\n'
  printf 'volume_count=6\n'
  printf 'isolated_restore_probe=passed\n'
} >"$backup/BACKUP.receipt"
chmod 0600 "$backup"/*
sync -f "$backup/postgres.dump"
resume_services
trap - EXIT
echo "runtime backup and isolated restore probes passed: $backup"
