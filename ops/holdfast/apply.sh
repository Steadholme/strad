#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --execute --estate-root PATH --dry-run-dir PATH --release-env FILE --backup-root PATH [--state-dir PATH] [--activate-services]" >&2
  exit 2
}

execute="false"
activate="false"
estate_root=""
dry_run_dir=""
release_env=""
backup_root=""
state_dir="/var/lib/holdfast-rikune"
while (($#)); do
  case "$1" in
    --execute) execute="true"; shift ;;
    --activate-services) activate="true"; shift ;;
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --dry-run-dir) [[ $# -ge 2 ]] || usage; dry_run_dir=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --backup-root) [[ $# -ge 2 ]] || usage; backup_root=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || usage; state_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ "$execute" == "true" && -n "$estate_root" && -n "$dry_run_dir" && -n "$release_env" && -n "$backup_root" ]] || usage
[[ $EUID -eq 0 ]] || { echo "apply requires root" >&2; exit 1; }
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=common.sh
source "$script_dir/common.sh"
for path in "$estate_root" "$dry_run_dir" "$release_env" "$backup_root" "$state_dir"; do
  holdfast_require_absolute "$path"
done

# Acquire before receipt, preimage, or expected-absent validation.
holdfast_acquire_lock
stage="$dry_run_dir/stage"
receipt="$dry_run_dir/DRY-RUN.receipt"
[[ -d "$estate_root/access-governance" && -d "$stage" && -f "$receipt" && ! -L "$receipt" ]] || \
  holdfast_die "estate or dry-run package is incomplete"
[[ -z "$(find "$dry_run_dir" -maxdepth 0 -perm /077 -print -quit)" ]] || \
  holdfast_die "dry-run directory must not be group/world accessible"
[[ "$(holdfast_receipt_value "$receipt" cargo_gate)" == "passed" ]] || \
  holdfast_die "production apply refuses a dry-run without the Rust gate"

python3 "$script_dir/validate_release_evidence.py" --evidence "$stage/RELEASE-EVIDENCE.json"
[[ "$(holdfast_receipt_value "$receipt" targets_sha256)" == "$(holdfast_sha256 "$stage/TARGETS.sha256")" ]] || \
  holdfast_die "dry-run target manifest changed"
[[ "$(holdfast_receipt_value "$receipt" release_evidence_sha256)" == "$(holdfast_sha256 "$stage/RELEASE-EVIDENCE.json")" ]] || \
  holdfast_die "dry-run release evidence changed"
release_env_sha=$(holdfast_sha256 "$release_env")
[[ "$(holdfast_receipt_value "$receipt" release_env_sha256)" == "$release_env_sha" ]] || \
  holdfast_die "release env differs from the dry-run identity"
[[ "$(jq -er '.release_env_sha256' "$stage/RELEASE-EVIDENCE.json")" == "$release_env_sha" ]] || \
  holdfast_die "release env differs from RELEASE-EVIDENCE"

python3 "$script_dir/supply_chain_evidence.py" \
  --release-env "$release_env" \
  --evidence "$stage/evidence/SUPPLY-CHAIN.json" \
  --signature "$stage/evidence/SUPPLY-CHAIN.sig" \
  --public-key "$stage/evidence/SUPPLY-CHAIN.pub" \
  --dockerfile "$script_dir/../../Dockerfile.analyzer" \
  --bridge-lock "$script_dir/../../bridge/package-lock.json" \
  --release-evidence "$stage/RELEASE-EVIDENCE.json"
for key in evidence signature public_key; do
  receipt_key="supply_chain_${key}_sha256"
  case "$key" in
    evidence) file="$stage/evidence/SUPPLY-CHAIN.json" ;;
    signature) file="$stage/evidence/SUPPLY-CHAIN.sig" ;;
    public_key) file="$stage/evidence/SUPPLY-CHAIN.pub" ;;
  esac
  [[ "$(holdfast_receipt_value "$receipt" "$receipt_key")" == "$(holdfast_sha256 "$file")" ]] || \
    holdfast_die "supply-chain artifact differs from dry-run receipt: $key"
done
grep -q '"catalog_only": false' "$stage/RELEASE-EVIDENCE.json" || \
  holdfast_die "candidate-only rendering cannot be applied"
if grep -q 'registry.invalid/' "$stage/RELEASE-EVIDENCE.json"; then
  holdfast_die "test-only image digests cannot be applied"
fi
(cd "$stage" && sha256sum --check TARGETS.sha256)
docker compose --env-file "$stage/deploy/.env" -f "$stage/deploy/docker-compose.yml" config --quiet

mkdir -p -- "$backup_root" "$state_dir"
chmod 0700 -- "$backup_root" "$state_dir"
[[ ! -e "$state_dir/CURRENT.json" && ! -L "$state_dir/CURRENT.json" ]] || \
  holdfast_die "an active Holdfast release state already exists"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_root/holdfast-rikune-${timestamp}-$$"
[[ ! -e "$backup" && ! -L "$backup" ]] || holdfast_die "backup collision"
mkdir -m 0700 -- "$backup"

# Runtime backup plus isolated restore probes are mandatory before file mutation.
"$script_dir/runtime-backup.sh" --compose-root "$stage" --backup-dir "$backup/runtime"
python3 "$script_dir/estate_transaction.py" apply \
  --estate-root "$estate_root" \
  --stage-root "$stage" \
  --targets "$stage/TARGETS.sha256" \
  --preimages "$script_dir/preimages.sha256" \
  --absent "$script_dir/absent.paths" \
  --backup-dir "$backup/estate"

install -m 0600 -- "$stage/RELEASE-EVIDENCE.json" "$backup/RELEASE-EVIDENCE.json"
install -m 0600 -- "$release_env" "$backup/release.env"
install -m 0600 -- "$receipt" "$backup/DRY-RUN.receipt"
install -m 0600 -- "$stage/evidence/SUPPLY-CHAIN.json" "$backup/SUPPLY-CHAIN.json"
install -m 0600 -- "$stage/evidence/SUPPLY-CHAIN.sig" "$backup/SUPPLY-CHAIN.sig"
install -m 0600 -- "$stage/evidence/SUPPLY-CHAIN.pub" "$backup/SUPPLY-CHAIN.pub"
rollback_image=$(jq -er '.release.ACCESS_GOVERNANCE_ROLLBACK_IMAGE' "$stage/RELEASE-EVIDENCE.json")
printf 'services:\n  access-governance:\n    image: %s\n' "$rollback_image" >"$backup/rollback.override.yml"
(
  cd "$backup"
  sha256sum RELEASE-EVIDENCE.json release.env DRY-RUN.receipt SUPPLY-CHAIN.json \
    SUPPLY-CHAIN.sig SUPPLY-CHAIN.pub rollback.override.yml \
    estate/APPLIED-TARGETS.sha256 estate/PREIMAGES.sha256 estate/ABSENT.before estate/TRANSACTION.json \
    runtime/SHA256SUMS runtime/BACKUP.receipt
) >"$backup/CONTROL.sha256"

(cd "$estate_root" && sha256sum --check "$stage/TARGETS.sha256")
docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" config --quiet
if [[ "$activate" == "true" ]]; then
  docker compose --env-file "$estate_root/deploy/.env" -f "$estate_root/deploy/docker-compose.yml" \
    up -d --no-build access-governance verdict newapi rikune-analyzer strad sluice sluice-internal
fi

apply_receipt="$backup/APPLY.receipt"
{
  printf 'applied_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'estate_root=%s\n' "$estate_root"
  printf 'backup_dir=%s\n' "$backup"
  printf 'release_env_sha256=%s\n' "$release_env_sha"
  printf 'release_evidence_sha256=%s\n' "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")"
  printf 'cargo_gate=passed\n'
  printf 'runtime_backup=passed\n'
  printf 'ingress_opened=false\n'
  printf 'services_activated=%s\n' "$activate"
} >"$apply_receipt"
chmod 0600 "$apply_receipt"
state_tmp="$state_dir/.CURRENT.json.$$"
jq -n \
  --arg backup "$backup" \
  --arg apply_sha "$(holdfast_sha256 "$apply_receipt")" \
  --arg release_sha "$(holdfast_sha256 "$backup/RELEASE-EVIDENCE.json")" \
  '{schema_version:1,state:"applied_ingress_closed",backup_dir:$backup,apply_receipt_sha256:$apply_sha,release_evidence_sha256:$release_sha}' \
  >"$state_tmp"
chmod 0600 "$state_tmp"
mv -fT -- "$state_tmp" "$state_dir/CURRENT.json"
echo "estate transaction applied with runtime backup; ingress remains closed"
echo "rollback backup: $backup"
