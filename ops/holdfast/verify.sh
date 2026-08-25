#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --dry-run-dir PATH [--phase staged|live] [--release-env FILE --authority-evidence FILE --authority-signature FILE --authority-public-key FILE] [--deep]" >&2
  exit 2
}

estate_root=""
dry_run_dir=""
phase="staged"
release_env=""
authority_evidence=""
authority_signature=""
authority_public_key=""
deep="false"
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --dry-run-dir) [[ $# -ge 2 ]] || usage; dry_run_dir=$2; shift 2 ;;
    --phase) [[ $# -ge 2 ]] || usage; phase=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --authority-evidence) [[ $# -ge 2 ]] || usage; authority_evidence=$2; shift 2 ;;
    --authority-signature) [[ $# -ge 2 ]] || usage; authority_signature=$2; shift 2 ;;
    --authority-public-key) [[ $# -ge 2 ]] || usage; authority_public_key=$2; shift 2 ;;
    --deep) deep="true"; shift ;;
    *) usage ;;
  esac
done
[[ -n "$estate_root" && -n "$dry_run_dir" ]] || usage
[[ "$phase" == "staged" || "$phase" == "live" ]] || usage
for path in "$estate_root" "$dry_run_dir"; do
  [[ "$path" = /* && "$path" != "/" ]] || { echo "unsafe path: $path" >&2; exit 1; }
done
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/validate_release_evidence.py" \
  --evidence "$dry_run_dir/stage/RELEASE-EVIDENCE.json"
if [[ "$phase" == "staged" ]]; then
  target_root="$dry_run_dir/stage"
else
  target_root="$estate_root"
fi
(
  cd "$target_root"
  sha256sum --check "$dry_run_dir/stage/TARGETS.sha256"
)
(
  cd "$target_root/access-governance"
  cargo fmt --check
  scripts/generate_permission_catalog.sh --check
  python3 scripts/validate_authz_manifests.py
  if [[ "$deep" == "true" ]]; then
    cargo test --locked --lib catalog
  fi
)
docker compose --env-file "$target_root/deploy/.env" -f "$target_root/deploy/docker-compose.yml" config --quiet
jq -e '
  .requestable_package_count == 8
  and (.packages | length == 9)
  and .packages[8].package_id == "pkg_rikune_analyst"
  and .packages[8].membership_digest == "16b3b01187d066ce7a2e3b4b8c13185cae93bc9b64ee680ccf7c62b501df4b6c"
  and .packages[8].policy_digest == "6cb61051c0fdfea360a3fedc9b938a63581e4358d992bb418408eaeb024cdffa"
' "$target_root/access-governance/catalog/packages.snapshot.json" >/dev/null
jq -e '
  ([.entries[].key | select(startswith("rikune."))] | length) == 7
  and ([.generated_from[].source | select(. == "rikune-authz")] | length) == 1
  and ([.entries[] | select(.key == "cistern.console.enter" and .risk == "high")] | length) == 1
  and ([.generated_from[].source | select(. == "cistern-authz")] | length) == 1
' "$target_root/access-governance/catalog/permissions.snapshot.json" >/dev/null
jq -e '
  ([.routes[] | select(.name == "cistern-dash")] | length) == 1
  and ([.routes[] | select(
    .name == "cistern-dash"
    and .protected == false
    and .auth == "sso"
    and .internal_only == false
    and .require_group == ""
    and .require_permission == ""
    and .permission_resource == ""
    and .risk == ""
    and .require_scope == ""
  )] | length) == 1
' "$target_root/deploy/routes.seed.json" >/dev/null

if [[ "$phase" == "live" ]]; then
  [[ -n "$release_env" && -n "$authority_evidence" && -n "$authority_signature" && -n "$authority_public_key" && -n "${ROUTES_DATABASE_URL:-}" ]] || {
    echo "live verification needs release/evidence paths and ROUTES_DATABASE_URL" >&2
    exit 1
  }
  python3 "$script_dir/authority_evidence.py" --mode open \
    --evidence "$authority_evidence" --signature "$authority_signature" \
    --public-key "$authority_public_key" --release-env "$release_env" \
    --release-evidence "$dry_run_dir/stage/RELEASE-EVIDENCE.json" \
    --dry-run-receipt "$dry_run_dir/DRY-RUN.receipt"
  observed=$(PGAPPNAME=holdfast-rikune-verify psql "$ROUTES_DATABASE_URL" -XAtq -f "$script_dir/assets/verify_rikune_root.sql")
  [[ "$observed" == "ok" ]] || { echo "rikune-root live authority is not exact" >&2; exit 1; }
  "$script_dir/runtime-verify.sh" --estate-root "$estate_root" --release-env "$release_env" \
    --release-evidence "$dry_run_dir/stage/RELEASE-EVIDENCE.json"
fi
echo "Holdfast Rikune verification passed for phase: $phase"
