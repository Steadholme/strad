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
source "$script_dir/common.sh"
for path in "$estate_root" "$backup" "$open_evidence" "$open_signature" "$authority_public_key" "$state_dir"; do
  holdfast_require_absolute "$path"
done
holdfast_acquire_lock

state_file="$state_dir/CURRENT.json"
route_receipt="$state_dir/ROUTE-CLOSE.receipt"
route_preimage="$state_dir/ROUTE-CLOSE-PREIMAGE.jsonl"
[[ -f "$state_file" && ! -L "$state_file" ]] || holdfast_die "active release state is absent"

verify_database_absent() {
  local observed
  observed=$(PGAPPNAME=holdfast-rikune-rollback-db-absent psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql") || return 1
  [[ "$observed" == "ok" ]] || {
    echo "holdfast: rollback does not prove rikune-root/analyze root absence" >&2
    return 1
  }
}

verify_closed_bracket() {
  verify_database_absent
  "$script_dir/public-origin-verify.sh" --mode closed --url https://analyze.w33d.xyz/
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
  if PGAPPNAME=holdfast-rikune-close psql "$ROUTES_DATABASE_URL" -XAtq \
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

validate_backup_and_open_authority() {
  [[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || holdfast_die "state points to another backup"
  [[ -d "$backup/estate/tree" && -d "$backup/runtime" && -f "$backup/CONTROL.sha256" ]] || \
    holdfast_die "backup package is incomplete"
  (cd "$backup" && sha256sum --check CONTROL.sha256)
  python3 "$script_dir/validate_release_evidence.py" --evidence "$backup/RELEASE-EVIDENCE.json"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  python3 "$script_dir/authority_evidence.py" --mode open \
    --evidence "$open_evidence" --signature "$open_signature" --public-key "$authority_public_key" \
    --release-env "$backup/release.env" --release-evidence "$backup/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$backup/DRY-RUN.receipt"
}

if [[ "$phase" == "close-route" ]]; then
  # Safety ordering is intentional: the frozen, transactionally self-snapshotting down asset and
  # the public bracket run before parsing mutable armed/open metadata or validating backup evidence.
  execute_frozen_route_down
  verify_closed_bracket

  current_state=$(jq -er '.state' "$state_file")
  [[ "$current_state" == "ingress_open" || "$current_state" == "finalizing_route_armed" || "$current_state" == "ingress_compensation_unverified" || "$current_state" == "edge_prepared_route_closed" || "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "route close refuses state $current_state"
  [[ ! -e "$route_receipt" && ! -L "$route_receipt" ]] || holdfast_die "route-close receipt already exists"
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
    printf 'route_closed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
  chmod 0600 "$receipt_tmp"
  mv -fT -- "$receipt_tmp" "$route_receipt"
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg close_sha "$(holdfast_sha256 "$route_receipt")" \
    '.state="route_closed_awaiting_revocation" | .route_close_receipt_sha256=$close_sha' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  echo "route is dual-stack 404 closed; now revoke the exact source grant, await all seven tombstones, then sign v2 rollback evidence"
  exit 0
fi

validate_backup_and_open_authority
current_state=$(jq -er '.state' "$state_file")
[[ "$current_state" == "route_closed_awaiting_revocation" ]] || \
  holdfast_die "rollback execute refuses state $current_state"
[[ -f "$route_receipt" && ! -L "$route_receipt" ]] || holdfast_die "route-close receipt is absent"
[[ "$(jq -er '.route_close_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$route_receipt")" ]] || \
  holdfast_die "route-close receipt was replaced"
for path in "$revocation_evidence" "$revocation_signature"; do holdfast_require_absolute "$path"; done
python3 "$script_dir/authority_evidence.py" --mode rollback \
  --evidence "$revocation_evidence" --signature "$revocation_signature" \
  --public-key "$authority_public_key" --release-env "$backup/release.env" \
  --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-evidence "$open_evidence" \
  --route-close-receipt "$route_receipt"
verify_closed_bracket

if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
  [[ -n "$edge_rollback_evidence" && -n "$edge_rollback_signature" && -n "$open_edge_evidence" ]] || \
    holdfast_die "public rollback requires signed v2 dual-stack 404 evidence"
  for path in "$edge_rollback_evidence" "$edge_rollback_signature" "$open_edge_evidence"; do holdfast_require_absolute "$path"; done
  python3 "$script_dir/edge_evidence.py" --mode rollback \
    --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-edge-evidence "$open_edge_evidence" \
    --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
fi
verify_closed_bracket

# Runtime restoration explicitly removes orphan Strad/analyzer containers before volume recovery.
"$script_dir/runtime-restore.sh" --execute --compose-root "$estate_root" --backup-dir "$backup/runtime"
python3 "$script_dir/estate_transaction.py" restore \
  --estate-root "$estate_root" --backup-dir "$backup/estate"
(cd "$estate_root" && sha256sum --check "$backup/estate/PREIMAGES.sha256")
docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" config --quiet
if [[ "$activate" == "true" ]]; then
  docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" \
    -f "$backup/rollback.override.yml" up -d --no-build access-governance verdict newapi sluice sluice-internal
fi
verify_closed_bracket

rollback_receipt="$backup/ROLLBACK.receipt"
{
  printf 'rolled_back_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
  printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
  printf 'runtime_restore=passed\n'
  printf 'mixed_estate_restore=passed\n'
  printf 'orphan_cleanup=passed\n'
  printf 'public_route_state=dual-stack-404\n'
} >"$rollback_receipt"
chmod 0600 "$rollback_receipt"
completed="$state_dir/ROLLBACK-COMPLETE-$(date -u +%Y%m%dT%H%M%SZ).json"
state_tmp="$state_dir/.ROLLBACK-COMPLETE.$$"
jq --arg receipt_sha "$(holdfast_sha256 "$rollback_receipt")" \
  '.state="rolled_back" | .rollback_receipt_sha256=$receipt_sha' "$state_file" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_file"
mv -- "$state_file" "$completed"
echo "checksum-bound estate and runtime were restored; ingress remains closed"
