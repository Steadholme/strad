#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --estate-root PATH --release-env FILE --secret-env FILE --supply-chain-evidence FILE --supply-chain-signature FILE --supply-chain-public-key FILE --output NEW_PATH" >&2
  exit 2
}

estate_root=""
release_env=""
secret_env=""
output=""
supply_chain_evidence=""
supply_chain_signature=""
supply_chain_public_key=""
while (($#)); do
  case "$1" in
    --estate-root) [[ $# -ge 2 ]] || usage; estate_root=$2; shift 2 ;;
    --release-env) [[ $# -ge 2 ]] || usage; release_env=$2; shift 2 ;;
    --secret-env) [[ $# -ge 2 ]] || usage; secret_env=$2; shift 2 ;;
    --supply-chain-evidence) [[ $# -ge 2 ]] || usage; supply_chain_evidence=$2; shift 2 ;;
    --supply-chain-signature) [[ $# -ge 2 ]] || usage; supply_chain_signature=$2; shift 2 ;;
    --supply-chain-public-key) [[ $# -ge 2 ]] || usage; supply_chain_public_key=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$estate_root" && -n "$release_env" && -n "$secret_env" && -n "$output" && -n "$supply_chain_evidence" && -n "$supply_chain_signature" && -n "$supply_chain_public_key" ]] || usage
[[ "$estate_root" = /* && "$release_env" = /* && "$secret_env" = /* && "$output" = /* && "$supply_chain_evidence" = /* && "$supply_chain_signature" = /* && "$supply_chain_public_key" = /* ]] || {
  echo "all paths must be explicit absolute paths" >&2
  exit 2
}
[[ "$estate_root" != "/" && "$output" != "/" && ! -e "$output" && ! -L "$output" ]] || {
  echo "unsafe estate root or output already exists" >&2
  exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/supply_chain_evidence.py" \
  --release-env "$release_env" \
  --evidence "$supply_chain_evidence" \
  --signature "$supply_chain_signature" \
  --public-key "$supply_chain_public_key" \
  --dockerfile "$script_dir/../../Dockerfile.analyzer" \
  --bridge-lock "$script_dir/../../bridge/package-lock.json"
umask 077
mkdir -m 0700 -- "$output"
python3 "$script_dir/render.py" \
  --estate-root "$estate_root" \
  --stage-root "$output/stage" \
  --release-env "$release_env" \
  --secret-env "$secret_env"
python3 "$script_dir/validate_release_evidence.py" \
  --evidence "$output/stage/RELEASE-EVIDENCE.json"
mkdir -m 0700 -- "$output/stage/evidence"
install -m 0600 -- "$supply_chain_evidence" "$output/stage/evidence/SUPPLY-CHAIN.json"
install -m 0600 -- "$supply_chain_signature" "$output/stage/evidence/SUPPLY-CHAIN.sig"
install -m 0600 -- "$supply_chain_public_key" "$output/stage/evidence/SUPPLY-CHAIN.pub"
python3 "$script_dir/supply_chain_evidence.py" \
  --release-env "$release_env" \
  --evidence "$output/stage/evidence/SUPPLY-CHAIN.json" \
  --signature "$output/stage/evidence/SUPPLY-CHAIN.sig" \
  --public-key "$output/stage/evidence/SUPPLY-CHAIN.pub" \
  --dockerfile "$script_dir/../../Dockerfile.analyzer" \
  --bridge-lock "$script_dir/../../bridge/package-lock.json" \
  --release-evidence "$output/stage/RELEASE-EVIDENCE.json"
python3 -m unittest discover -s "$script_dir/tests" -p 'test_*.py'

mkdir -m 0700 -- "$output/patches"
while IFS= read -r relative; do
  [[ -n "$relative" ]] || continue
  safe_name=${relative//\//__}
  if [[ "$relative" == "deploy/.env" ]]; then
    python3 "$script_dir/redact_env_diff.py" \
      "$estate_root/$relative" "$output/stage/$relative" "$output/patches/${safe_name}.redacted.json"
    continue
  fi
  old_path="$estate_root/$relative"
  [[ -e "$old_path" || -L "$old_path" ]] || old_path=/dev/null
  set +e
  diff -u --label "a/$relative" --label "b/$relative" \
    "$old_path" "$output/stage/$relative" >"$output/patches/${safe_name}.patch"
  diff_status=$?
  set -e
  [[ $diff_status -eq 0 || $diff_status -eq 1 ]] || {
    echo "diff failed for $relative" >&2
    exit 1
  }
done < <(awk '{print $2}' "$output/stage/TARGETS.sha256")

(
  cd "$output/stage"
  sha256sum --check TARGETS.sha256
)
(
  cd "$output/stage/access-governance"
  cargo fmt --check
  scripts/generate_permission_catalog.sh --check
  python3 scripts/validate_authz_manifests.py
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$output/cargo-target}" cargo test --locked --lib catalog
)
docker compose \
  --env-file "$output/stage/deploy/.env" \
  -f "$output/stage/deploy/docker-compose.yml" \
  config --quiet
bash -n \
  "$script_dir/candidate-source.sh" \
  "$script_dir/common.sh" \
  "$script_dir/dry-run.sh" \
  "$script_dir/apply.sh" \
  "$script_dir/open-ingress.sh" \
  "$script_dir/public-origin-verify.sh" \
  "$script_dir/verify.sh" \
  "$script_dir/rollback.sh" \
  "$script_dir/runtime-backup.sh" \
  "$script_dir/runtime-restore.sh" \
  "$script_dir/runtime-verify.sh"
python3 -m py_compile \
  "$script_dir/render.py" \
  "$script_dir/redact_env_diff.py" \
  "$script_dir/authority_evidence.py" \
  "$script_dir/edge_evidence.py" \
  "$script_dir/estate_transaction.py" \
  "$script_dir/supply_chain_evidence.py" \
  "$script_dir/validate_release_evidence.py"

targets_digest=$(sha256sum "$output/stage/TARGETS.sha256" | cut -d' ' -f1)
evidence_digest=$(sha256sum "$output/stage/RELEASE-EVIDENCE.json" | cut -d' ' -f1)
release_env_digest=$(sha256sum "$release_env" | cut -d' ' -f1)
{
  printf 'generator=%s\n' "$(tr -d '\n' <"$script_dir/GENERATOR_VERSION")"
  printf 'targets_sha256=%s\n' "$targets_digest"
  printf 'release_evidence_sha256=%s\n' "$evidence_digest"
  printf 'release_env_sha256=%s\n' "$release_env_digest"
  printf 'supply_chain_evidence_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.json" | cut -d' ' -f1)"
  printf 'supply_chain_signature_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.sig" | cut -d' ' -f1)"
  printf 'supply_chain_public_key_sha256=%s\n' "$(sha256sum "$output/stage/evidence/SUPPLY-CHAIN.pub" | cut -d' ' -f1)"
  printf 'cargo_gate=passed\n'
  printf 'secrets=redacted\n'
} >"$output/DRY-RUN.receipt"
chmod 0600 "$output/DRY-RUN.receipt"
echo "dry-run complete: $output"
