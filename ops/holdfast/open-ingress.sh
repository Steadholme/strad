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
if [[ "$phase" == "finalize" ]]; then
  [[ -n "$edge_evidence" && -n "$edge_signature" ]] || usage
fi
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
[[ -f "$state_file" && ! -L "$state_file" ]] || holdfast_die "active apply state is absent"
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

prepare_receipt="$state_dir/OPEN-PREPARE.receipt"
open_receipt="$state_dir/OPEN.receipt"
current_state=$(jq -er '.state' "$state_file")
if [[ "$phase" == "prepare" ]]; then
  [[ "$current_state" == "applied_ingress_closed" ]] || \
    holdfast_die "open prepare refuses state $current_state (re-open/race blocked)"
  [[ ! -e "$prepare_receipt" && ! -L "$prepare_receipt" && ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
    holdfast_die "open ceremony receipt already exists"
  expected_route_up=$(jq -er '.route_up_sha256' "$release_evidence")
  [[ "$expected_route_up" == "$(holdfast_sha256 "$script_dir/assets/20260823_rikune_root_up.sql")" ]] || \
    holdfast_die "route-up SQL differs from release evidence"
  PGAPPNAME=holdfast-rikune-open-prepare psql "$ROUTES_DATABASE_URL" -X \
    -f "$script_dir/assets/20260823_rikune_root_up.sql"
  observed=$(PGAPPNAME=holdfast-rikune-verify psql "$ROUTES_DATABASE_URL" -XAtq \
    -f "$script_dir/assets/verify_rikune_root.sql")
  [[ "$observed" == "ok" ]] || holdfast_die "rikune-root preparation verification failed"
  receipt_tmp="$state_dir/.OPEN-PREPARE.receipt.$$"
  {
    printf 'prepared_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$release_evidence")"
    printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$authority_evidence")"
    printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$authority_evidence")"
    printf 'route_up_sha256=%s\n' "$expected_route_up"
    printf 'public_cutover_complete=false\n'
  } >"$receipt_tmp"
  chmod 0600 "$receipt_tmp"
  mv -fT -- "$receipt_tmp" "$prepare_receipt"
  state_tmp="$state_dir/.CURRENT.json.$$"
  jq --arg prepare_sha "$(holdfast_sha256 "$prepare_receipt")" \
    '.state="route_prepared_edge_closed" | .open_prepare_receipt_sha256=$prepare_sha' \
    "$state_file" >"$state_tmp"
  chmod 0600 "$state_tmp"
  mv -fT -- "$state_tmp" "$state_file"
  echo "route/runtime prepared; now detach GitHub Pages cname, PATCH Cloudflare DNS, purge host cache, and collect signed IPv4/IPv6 evidence"
  exit 0
fi

[[ "$current_state" == "route_prepared_edge_closed" ]] || \
  holdfast_die "open finalize refuses state $current_state (re-open/race blocked)"
[[ -f "$prepare_receipt" && ! -L "$prepare_receipt" && ! -e "$open_receipt" && ! -L "$open_receipt" ]] || \
  holdfast_die "open prepare receipt is absent or final receipt already exists"
[[ "$(jq -er '.open_prepare_receipt_sha256' "$state_file")" == "$(holdfast_sha256 "$prepare_receipt")" ]] || \
  holdfast_die "open prepare receipt was replaced"
for path in "$edge_evidence" "$edge_signature"; do holdfast_require_absolute "$path"; done
python3 "$script_dir/edge_evidence.py" --mode cutover \
  --evidence "$edge_evidence" --signature "$edge_signature" --public-key "$authority_public_key" \
  --release-env "$release_env" --release-evidence "$release_evidence" \
  --open-evidence "$authority_evidence" --prepare-receipt "$prepare_receipt"
observed=$(PGAPPNAME=holdfast-rikune-finalize psql "$ROUTES_DATABASE_URL" -XAtq \
  -f "$script_dir/assets/verify_rikune_root.sql")
[[ "$observed" == "ok" ]] || holdfast_die "rikune-root drifted before public finalize"
"$script_dir/runtime-verify.sh" --estate-root "$estate_root" --release-env "$release_env" \
  --release-evidence "$release_evidence"
"$script_dir/public-origin-verify.sh" https://rikune.w33d.xyz/

receipt_tmp="$state_dir/.OPEN.receipt.$$"
{
  printf 'opened_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'open_prepare_receipt_sha256=%s\n' "$(holdfast_sha256 "$prepare_receipt")"
  printf 'open_evidence_sha256=%s\n' "$(holdfast_sha256 "$authority_evidence")"
  printf 'edge_evidence_sha256=%s\n' "$(holdfast_sha256 "$edge_evidence")"
  printf 'source_grant_id=%s\n' "$(jq -er '.source_grant_id' "$authority_evidence")"
  printf 'public_ipv4_ipv6_origin=sluice-strad\n'
  printf 'cache_policy=private,no-store\n'
} >"$receipt_tmp"
chmod 0600 "$receipt_tmp"
mv -fT -- "$receipt_tmp" "$open_receipt"
state_tmp="$state_dir/.CURRENT.json.$$"
jq --arg open_sha "$(holdfast_sha256 "$open_receipt")" \
  '.state="ingress_open" | .open_receipt_sha256=$open_sha' "$state_file" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_file"
echo "rikune-root public ingress finalized after Pages/DNS cutover and dual-stack cache verification"
