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
[[ -f "$state_file" && ! -L "$state_file" ]] || holdfast_die "active release state is absent"
[[ "$(jq -er '.backup_dir' "$state_file")" == "$backup" ]] || holdfast_die "state points to another backup"
[[ -d "$backup/estate/tree" && -d "$backup/runtime" && -f "$backup/CONTROL.sha256" ]] || \
  holdfast_die "backup package is incomplete"
(cd "$backup" && sha256sum --check CONTROL.sha256)
python3 "$script_dir/validate_release_evidence.py" --evidence "$backup/RELEASE-EVIDENCE.json"
python3 "$script_dir/authority_evidence.py" --mode open \
  --evidence "$open_evidence" --signature "$open_signature" --public-key "$authority_public_key" \
  --release-env "$backup/release.env" --release-evidence "$backup/RELEASE-EVIDENCE.json" \
  --dry-run-receipt "$backup/DRY-RUN.receipt"

current_state=$(jq -er '.state' "$state_file")
if [[ "$phase" == "close-route" ]]; then
  [[ "$current_state" == "ingress_open" || "$current_state" == "route_prepared_edge_closed" || "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "route close refuses state $current_state"
  [[ ! -e "$route_receipt" && ! -L "$route_receipt" ]] || holdfast_die "route-close receipt already exists"
  expected_route_down=$(jq -er '.route_down_sha256' "$backup/RELEASE-EVIDENCE.json")
  [[ "$expected_route_down" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_down.sql")" ]] || \
    holdfast_die "route-down SQL differs from release evidence"
  PGAPPNAME=holdfast-rikune-close psql "$ROUTES_DATABASE_URL" -X \
    -f "$script_dir/assets/20260823_rikune_root_down.sql"
  observed=$(PGAPPNAME=holdfast-rikune-closed psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root_absent.sql")
  [[ "$observed" == "ok" ]] || holdfast_die "route close verification failed"
  receipt_tmp="$state_dir/.ROUTE-CLOSE.receipt.$$"
  {
    printf 'route_closed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'route_down_sha256=%s\n' "$expected_route_down"
    printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
    printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$open_evidence")"
    printf 'was_public_open=%s\n' "$([[ "$current_state" == "ingress_open" ]] && echo true || echo false)"
  } >"$receipt_tmp"
  chmod 0600 "$receipt_tmp"
  mv -fT -- "$receipt_tmp" "$route_receipt"
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg close_sha "$(holdfast_sha256 "$route_receipt")" \
    '.state="route_closed_awaiting_revocation" | .route_close_receipt_sha256=$close_sha' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  echo "route is closed; now revoke the exact source grant, await all seven tombstones, then sign rollback evidence bound to this receipt"
  exit 0
fi

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
observed=$(PGAPPNAME=holdfast-rikune-closed psql "$ROUTES_DATABASE_URL" -XAtq \
  -f "$script_dir/assets/verify_rikune_root_absent.sql")
[[ "$observed" == "ok" ]] || holdfast_die "route was reopened during revocation ceremony"

if [[ "$(holdfast_receipt_value "$route_receipt" was_public_open)" == "true" ]]; then
  [[ -n "$edge_rollback_evidence" && -n "$edge_rollback_signature" && -n "$open_edge_evidence" ]] || \
    holdfast_die "public rollback requires signed Pages/Cloudflare restoration evidence"
  for path in "$edge_rollback_evidence" "$edge_rollback_signature" "$open_edge_evidence"; do holdfast_require_absolute "$path"; done
  python3 "$script_dir/edge_evidence.py" --mode rollback \
    --evidence "$edge_rollback_evidence" --signature "$edge_rollback_signature" \
    --public-key "$authority_public_key" --release-env "$backup/release.env" \
    --release-evidence "$backup/RELEASE-EVIDENCE.json" --open-edge-evidence "$open_edge_evidence" \
    --route-close-receipt "$route_receipt" --revocation-evidence "$revocation_evidence"
fi

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

rollback_receipt="$backup/ROLLBACK.receipt"
{
  printf 'rolled_back_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'route_close_receipt_sha256=%s\n' "$(holdfast_sha256 "$route_receipt")"
  printf 'revocation_evidence_sha256=%s\n' "$(holdfast_sha256 "$revocation_evidence")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$open_evidence")"
  printf 'runtime_restore=passed\n'
  printf 'mixed_estate_restore=passed\n'
  printf 'orphan_cleanup=passed\n'
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
