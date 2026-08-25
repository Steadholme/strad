#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --compose-root PATH --backup-dir PATH" >&2
  exit 2
}

execute="false"
compose_root=""
backup=""
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --compose-root) [[ $# -ge 2 ]] || usage; compose_root=$2; shift 2 ;;
    --backup-dir) [[ $# -ge 2 ]] || usage; backup=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && -n "$compose_root" && -n "$backup" ]] || usage
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
holdfast_require_absolute "$compose_root"
holdfast_require_absolute "$backup"
[[ -f "$backup/BACKUP.receipt" && -f "$backup/SHA256SUMS" && -f "$backup/VOLUMES.tsv" ]] || \
  holdfast_die "runtime backup package is incomplete"
[[ "$(holdfast_receipt_value "$backup/BACKUP.receipt" isolated_restore_probe)" == "passed" ]] || \
  holdfast_die "runtime backup lacks a passed isolated restore probe"
(cd "$backup" && sha256sum --check SHA256SUMS)

docker_bin=docker
if [[ -n "${HOLDFAST_DOCKER_BIN:-}" ]]; then
  [[ "${HOLDFAST_TEST_MODE:-0}" == "1" ]] || holdfast_die "Docker command override is test-only"
  docker_bin=$HOLDFAST_DOCKER_BIN
fi
compose=("$docker_bin" compose --env-file "$compose_root/deploy/.env" -f "$compose_root/deploy/docker-compose.yml")
volume_image=$(jq -er '.services["rikune-volume-init"].image' "$backup/compose-config.json")

expected_volumes=(strad_uploads rikune_workspaces rikune_storage rikune_state rikune_cache rikune_audit)
mapfile -t observed_volumes < <(cut -f1 "$backup/VOLUMES.tsv")
[[ "${observed_volumes[*]}" == "${expected_volumes[*]}" ]] || \
  holdfast_die "runtime backup volume set or order differs from the frozen six-volume contract"

# Explicitly stop and remove both containers so no orphan process retains a volume mount.
"${compose[@]}" stop -t 120 strad rikune-analyzer || true
"${compose[@]}" rm -f -s strad rikune-analyzer || true
for service in strad rikune-analyzer; do
  orphan=$("${compose[@]}" ps -aq "$service")
  [[ -z "$orphan" ]] || holdfast_die "orphan container remains after cleanup: $service"
done

while IFS=$'\t' read -r logical state actual; do
  [[ "$actual" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || holdfast_die "unsafe volume identity"
  "$docker_bin" volume rm -f "$actual" >/dev/null 2>&1 || true
  if "$docker_bin" volume inspect "$actual" >/dev/null 2>&1; then
    holdfast_die "volume could not be removed before exact restore: $actual"
  fi
  if [[ "$state" == "absent" ]]; then
    continue
  fi
  [[ "$state" == "present" ]] || holdfast_die "invalid volume disposition"
  "$docker_bin" volume create "$actual" >/dev/null
  "$docker_bin" run --rm --network none \
    -v "$actual:/restore" -v "$backup:/backup:ro" "$volume_image" \
    /bin/sh -ceu "tar -C /restore -xf /backup/$logical.tar"
done <"$backup/VOLUMES.tsv"

# The quoted programs are intentionally expanded inside the PostgreSQL container.
# shellcheck disable=SC2016
"${compose[@]}" exec -T postgres sh -ceu \
  'dropdb --if-exists --maintenance-db postgres -U "$POSTGRES_USER" "$POSTGRES_DB"; createdb -T template0 -U "$POSTGRES_USER" "$POSTGRES_DB"'
# shellcheck disable=SC2016
"${compose[@]}" exec -T postgres sh -ceu \
  'exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --exit-on-error --no-owner --no-acl' \
  <"$backup/postgres.dump"

printf 'restored_at=%s\norphan_cleanup=passed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  >"$backup/RESTORE.receipt"
chmod 0600 "$backup/RESTORE.receipt"
echo "runtime PostgreSQL and six volume dispositions restored; services remain stopped"
